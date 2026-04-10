/* linux_receiver.c - Runs on Linux target, receives disk image
 * Compile: gcc -O2 -o linux_receiver linux_receiver.c -lpthread
 * Run as root: ./linux_receiver /dev/sdb 9000 9001
 *   /dev/sdb = target block device (or a file)
 *   9000     = bulk replication port
 *   9001     = live mirror port
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>

#define BLOCK_SIZE      (1024 * 1024)
#define MAGIC_BULK      0x41495852   /* "AIXR" - bulk replication */
#define MAGIC_MIRROR    0x4D495252   /* "MIRR" - live mirror */

typedef struct {
    uint32_t magic;
    uint64_t offset;
    uint32_t length;
    uint32_t checksum;
    uint8_t  flags;
} __attribute__((packed)) BulkHeader;

typedef struct {
    uint32_t magic;
    uint64_t blkno;
    uint32_t blkcount;
    uint32_t blksize;
    uint8_t  op;
} __attribute__((packed)) MirrorHdr;

typedef struct {
    int      disk_fd;
    int      client_fd;
    int      is_mirror;   /* 0=bulk, 1=mirror */
} HandlerArgs;

static volatile int g_running = 1;

void sig_handler(int s) { g_running = 0; }

uint32_t xor_checksum(const uint8_t *d, size_t n) {
    uint32_t c = 0;
    for (size_t i = 0; i < n; i++) c ^= d[i];
    return c;
}

ssize_t recv_all(int fd, void *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t r = recv(fd, (char*)buf + got, len - got, 0);
        if (r <= 0) return r;
        got += r;
    }
    return got;
}

void *handle_bulk(void *arg) {
    HandlerArgs *a   = arg;
    int          cfd = a->client_fd;
    int          dfd = a->disk_fd;
    uint8_t     *buf = malloc(BLOCK_SIZE);
    uint64_t     written = 0;

    printf("[bulk] Connection accepted\n");

    while (g_running) {
        BulkHeader hdr;
        if (recv_all(cfd, &hdr, sizeof(hdr)) != sizeof(hdr)) break;

        if (ntohl(hdr.magic) != MAGIC_BULK) {
            fprintf(stderr, "[bulk] Bad magic\n");
            break;
        }

        uint64_t offset = be64toh(hdr.offset);
        uint32_t length = ntohl(hdr.length);
        uint32_t csum   = ntohl(hdr.checksum);
        uint8_t  flags  = hdr.flags;

        if (length > BLOCK_SIZE) {
            fprintf(stderr, "[bulk] Block too large: %u\n", length);
            break;
        }

        if (recv_all(cfd, buf, length) != (ssize_t)length) break;

        /* Verify checksum */
        if (xor_checksum(buf, length) != csum) {
            fprintf(stderr, "[bulk] Checksum mismatch at offset %lu\n", offset);
            uint8_t nack = 0xFF;
            send(cfd, &nack, 1, 0);
            continue;
        }

        /* Write to disk at correct offset */
        if (pwrite(dfd, buf, length, (off_t)offset) != (ssize_t)length) {
            perror("[bulk] pwrite");
            break;
        }

        written += length;

        /* ACK */
        uint8_t ack = 0xAC;
        send(cfd, &ack, 1, 0);

        if (flags & 0x01) {
            printf("[bulk] Final block received. Total: %lu MB\n",
                   written >> 20);
            /* Flush to disk */
            fsync(dfd);
            break;
        }
    }

    free(buf);
    close(cfd);
    free(a);
    return NULL;
}

void *handle_mirror(void *arg) {
    HandlerArgs *a   = arg;
    int          cfd = a->client_fd;
    int          dfd = a->disk_fd;
    uint8_t     *buf = malloc(64 * 1024); /* max 64KB per write op */
    uint64_t     ops = 0;

    printf("[mirror] Connection accepted\n");

    while (g_running) {
        MirrorHdr hdr;
        if (recv_all(cfd, &hdr, sizeof(hdr)) != sizeof(hdr)) break;

        if (ntohl(hdr.magic) != MAGIC_MIRROR) {
            fprintf(stderr, "[mirror] Bad magic\n");
            break;
        }

        uint64_t blkno    = be64toh(hdr.blkno);
        uint32_t blkcount = ntohl(hdr.blkcount);
        uint32_t blksize  = ntohl(hdr.blksize);
        size_t   datalen  = (size_t)blkcount * blksize;

        if (datalen > 64 * 1024) {
            fprintf(stderr, "[mirror] Payload too large\n");
            break;
        }

        if (recv_all(cfd, buf, datalen) != (ssize_t)datalen) break;

        off_t byte_offset = (off_t)blkno * blksize;
        if (pwrite(dfd, buf, datalen, byte_offset) != (ssize_t)datalen) {
            perror("[mirror] pwrite");
        }

        ops++;
        if (ops % 1000 == 0)
            printf("[mirror] %lu write ops applied\n", ops);
    }

    free(buf);
    close(cfd);
    free(a);
    return NULL;
}

int make_listener(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    int rbuf = 8 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rbuf, sizeof(rbuf));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    listen(fd, 4);
    return fd;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr,
            "Usage: %s <target_dev_or_file> <bulk_port> <mirror_port>\n"
            "Example: %s /dev/sdb 9000 9001\n",
            argv[0], argv[0]);
        return 1;
    }

    const char *target = argv[1];
    int bulk_port      = atoi(argv[2]);
    int mirror_port    = atoi(argv[3]);

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    int disk_fd = open(target, O_RDWR | O_CREAT | O_LARGEFILE, 0600);
    if (disk_fd < 0) { perror("open target"); return 1; }

    int bulk_fd   = make_listener(bulk_port);
    int mirror_fd = make_listener(mirror_port);
    if (bulk_fd < 0 || mirror_fd < 0) return 1;

    printf("Listening: bulk=%d mirror=%d target=%s\n",
           bulk_port, mirror_port, target);

    fd_set rfds;
    while (g_running) {
        FD_ZERO(&rfds);
        FD_SET(bulk_fd,   &rfds);
        FD_SET(mirror_fd, &rfds);
        int maxfd = (bulk_fd > mirror_fd ? bulk_fd : mirror_fd) + 1;

        struct timeval tv = { .tv_sec = 1 };
        if (select(maxfd, &rfds, NULL, NULL, &tv) <= 0) continue;

        int is_mirror = 0;
        int listener  = -1;
        if (FD_ISSET(bulk_fd,   &rfds)) { listener = bulk_fd;   is_mirror = 0; }
        if (FD_ISSET(mirror_fd, &rfds)) { listener = mirror_fd; is_mirror = 1; }

        if (listener < 0) continue;

        int cfd = accept(listener, NULL, NULL);
        if (cfd < 0) continue;

        HandlerArgs *a = malloc(sizeof(HandlerArgs));
        a->disk_fd     = disk_fd;
        a->client_fd   = cfd;
        a->is_mirror   = is_mirror;

        pthread_t tid;
        pthread_create(&tid, NULL,
                       is_mirror ? handle_mirror : handle_bulk, a);
        pthread_detach(tid);
    }

    close(bulk_fd);
    close(mirror_fd);
    close(disk_fd);
    return 0;
}
