/* aix_replicator.c - Raw disk replication from AIX to Linux target
 * Compile on AIX: xlc -o aix_replicator aix_replicator.c -lpthread
 * Requires root. Target must be running aix_receiver (see below).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>

#define BLOCK_SIZE      (1024 * 1024)   /* 1MB chunks */
#define DEFAULT_PORT    9000
#define MAGIC           0x41495852      /* "AIXR" */
#define MAX_RETRIES     3

typedef struct {
    uint32_t magic;
    uint64_t offset;        /* byte offset on source disk */
    uint32_t length;        /* bytes in this block */
    uint32_t checksum;      /* simple XOR checksum */
    uint8_t  flags;         /* 0x01 = last block */
} __attribute__((packed)) BlockHeader;

typedef struct {
    char    source_dev[256];
    char    target_ip[64];
    int     target_port;
    int     sock_fd;
    int     disk_fd;
    off64_t disk_size;
    int     verbose;
    int     dry_run;
} ReplicationCtx;

static volatile int g_running = 1;

void sig_handler(int sig) {
    g_running = 0;
    fprintf(stderr, "\nCaught signal %d, shutting down...\n", sig);
}

uint32_t xor_checksum(const uint8_t *data, size_t len) {
    uint32_t csum = 0;
    for (size_t i = 0; i < len; i++) csum ^= data[i];
    return csum;
}

/* Get disk size on AIX using lseek64 to end */
off64_t get_disk_size(int fd) {
    off64_t size = lseek64(fd, 0, SEEK_END);
    lseek64(fd, 0, SEEK_SET);
    return size;
}

int connect_to_target(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    /* Set TCP keepalive */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

    /* Larger send buffer for throughput */
    int bufsize = 8 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

int send_block(int sock, off64_t offset, const uint8_t *data,
               uint32_t length, uint8_t flags) {
    BlockHeader hdr = {
        .magic    = htonl(MAGIC),
        .offset   = htobe64(offset),   /* network byte order (big-endian) */
        .length   = htonl(length),
        .checksum = htonl(xor_checksum(data, length)),
        .flags    = flags
    };

    /* Send header */
    ssize_t sent = send(sock, &hdr, sizeof(hdr), 0);
    if (sent != sizeof(hdr)) return -1;

    /* Send data */
    size_t total = 0;
    while (total < length) {
        sent = send(sock, data + total, length - total, 0);
        if (sent <= 0) return -1;
        total += sent;
    }

    /* Wait for ACK */
    uint8_t ack = 0;
    if (recv(sock, &ack, 1, MSG_WAITALL) != 1 || ack != 0xAC) {
        fprintf(stderr, "Bad ACK at offset %lld\n", (long long)offset);
        return -1;
    }

    return 0;
}

int replicate_disk(ReplicationCtx *ctx) {
    uint8_t *buf = malloc(BLOCK_SIZE);
    if (!buf) { perror("malloc"); return -1; }

    off64_t offset   = 0;
    off64_t total    = ctx->disk_size;
    size_t  blocks   = 0;
    int     rc       = 0;

    printf("Starting replication: %s -> %s:%d (%lld bytes)\n",
           ctx->source_dev, ctx->target_ip, ctx->target_port,
           (long long)total);

    lseek64(ctx->disk_fd, 0, SEEK_SET);

    while (g_running && offset < total) {
        off64_t remaining = total - offset;
        uint32_t to_read  = (remaining > BLOCK_SIZE) ? BLOCK_SIZE
                                                      : (uint32_t)remaining;

        ssize_t nread = read(ctx->disk_fd, buf, to_read);
        if (nread <= 0) {
            if (nread < 0) perror("read");
            break;
        }

        uint8_t flags = ((offset + nread) >= total) ? 0x01 : 0x00;

        if (!ctx->dry_run) {
            int retry = 0;
            while (retry < MAX_RETRIES) {
                if (send_block(ctx->sock_fd, offset, buf, nread, flags) == 0)
                    break;
                fprintf(stderr, "Retry %d for offset %lld\n",
                        ++retry, (long long)offset);
            }
            if (retry == MAX_RETRIES) {
                fprintf(stderr, "Failed after %d retries at offset %lld\n",
                        MAX_RETRIES, (long long)offset);
                rc = -1;
                break;
            }
        }

        offset += nread;
        blocks++;

        if (ctx->verbose || (blocks % 100 == 0)) {
            printf("\r  Progress: %.1f%% (%lld / %lld MB)   ",
                   (double)offset / total * 100.0,
                   (long long)(offset >> 20),
                   (long long)(total  >> 20));
            fflush(stdout);
        }
    }

    printf("\nDone. %zu blocks sent, %lld bytes.\n",
           blocks, (long long)offset);
    free(buf);
    return rc;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr,
            "Usage: %s <source_dev> <target_ip> <target_port> [-v] [-n]\n"
            "  -v  verbose\n"
            "  -n  dry run (no network)\n"
            "Example: %s /dev/hdisk1 192.168.1.100 9000\n",
            argv[0], argv[0]);
        return 1;
    }

    ReplicationCtx ctx = {0};
    strncpy(ctx.source_dev, argv[1], sizeof(ctx.source_dev)-1);
    strncpy(ctx.target_ip,  argv[2], sizeof(ctx.target_ip)-1);
    ctx.target_port = atoi(argv[3]);

    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) ctx.verbose  = 1;
        if (strcmp(argv[i], "-n") == 0) ctx.dry_run  = 1;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    ctx.disk_fd = open(ctx.source_dev, O_RDONLY | O_LARGEFILE);
    if (ctx.disk_fd < 0) {
        perror("open source device");
        return 1;
    }

    ctx.disk_size = get_disk_size(ctx.disk_fd);
    if (ctx.disk_size <= 0) {
        fprintf(stderr, "Cannot determine disk size\n");
        close(ctx.disk_fd);
        return 1;
    }

    if (!ctx.dry_run) {
        ctx.sock_fd = connect_to_target(ctx.target_ip, ctx.target_port);
        if (ctx.sock_fd < 0) {
            close(ctx.disk_fd);
            return 1;
        }
    }

    int rc = replicate_disk(&ctx);

    close(ctx.disk_fd);
    if (!ctx.dry_run) close(ctx.sock_fd);

    return rc;
}
