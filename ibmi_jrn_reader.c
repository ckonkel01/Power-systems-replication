/* ibmi_jrn_reader.c
 * ILE C — compile with: CRTCMOD MODULE(MYLIB/JRNREAD) SRCFILE(MYLIB/QCSRC)
 * Then: CRTPGM PGM(MYLIB/JRNREAD) MODULE(MYLIB/JRNREAD)
 *
 * Reads journal entries and sends them to a Linux target via sockets.
 * Requires: journal started on objects with STRJRN or CHGJRN.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* IBM i specific headers */
#include <qjosjrne.h>       /* Journal entry structures */
#include <qusec.h>          /* Error code structure */
#include <qyusjobo.h>       /* Journal object APIs */
#include <recio.h>          /* Record I/O */
#include <mih/rslvsp.h>     /* Resolve system pointer */

#define MAX_ENTRY_SIZE  (512 * 1024)    /* 512KB max entry */
#define TARGET_PORT     9100
#define MAGIC           0x49424D49      /* "IBMI" */
#define BATCH_SIZE      100             /* entries per batch */

/* Wire format for a replicated journal entry */
typedef struct {
    uint32_t magic;
    uint32_t entry_len;         /* total bytes following this header */
    uint64_t sequence_number;
    uint32_t entry_type;        /* WRITE, DELETE, COMMIT, etc. */
    uint32_t entry_code;        /* R=record level, F=file level, etc. */
    char     library[11];
    char     file[11];
    char     member[11];
    char     job_name[26];
    uint64_t timestamp;         /* microseconds since epoch */
    uint32_t data_offset;       /* offset within this packet to row data */
    uint32_t data_length;
    uint8_t  flags;             /* 0x01=before image, 0x02=after image */
} __attribute__((packed)) WireEntry;

/* Checkpoint file — tracks last successfully sent sequence number */
#define CHECKPOINT_FILE "/tmp/jrn_checkpoint"

uint64_t load_checkpoint(void) {
    FILE *f = fopen(CHECKPOINT_FILE, "r");
    if (!f) return 0;
    uint64_t seq = 0;
    fscanf(f, "%llu", (unsigned long long *)&seq);
    fclose(f);
    return seq;
}

void save_checkpoint(uint64_t seq) {
    FILE *f = fopen(CHECKPOINT_FILE, "w");
    if (!f) return;
    fprintf(f, "%llu\n", (unsigned long long)seq);
    fclose(f);
}

int connect_target(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

/* QjoRetrieveJournalEntries call wrapper.
 * IBM i API: retrieves a batch of journal entries starting at seq.
 * Returns number of entries retrieved, -1 on error.
 *
 * Output buffer format (RJNE0200):
 *   Offset 0:  Number of entries returned (binary 4)
 *   Offset 4:  Offset to first entry
 *   Then entries, each with a fixed header + variable data
 */
int retrieve_journal_entries(
        const char *journal_lib,
        const char *journal_name,
        uint64_t    start_seq,
        uint8_t    *out_buf,
        uint32_t    out_buf_len,
        uint32_t   *entries_returned)
{
    /* Build the journal name in IBM i format: 10-char name + 10-char lib */
    char jrn_qualified[20];
    memset(jrn_qualified, ' ', 20);
    memcpy(jrn_qualified,      journal_name, strlen(journal_name));
    memcpy(jrn_qualified + 10, journal_lib,  strlen(journal_lib));

    /* RJNE0200 format request */
    /* Selection criteria — JOENTTYP0100 */
    typedef struct {
        char    filler[4];
        char    jrn_lib[10];
        char    jrn_name[10];
        int32_t num_types;          /* -1 = all types */
    } JrnSelCriteria;

    JrnSelCriteria sel = {0};
    memcpy(sel.jrn_lib,  journal_lib,  10);
    memcpy(sel.jrn_name, journal_name, 10);
    sel.num_types = -1; /* All entry types */

    /* Starting sequence number parameter */
    /* IBM i uses a 20-byte char representation of sequence number */
    char seq_str[21];
    snprintf(seq_str, sizeof(seq_str), "%020llu",
             (unsigned long long)start_seq);

    /* Error code structure */
    Qus_EC_t errcode = {0};
    errcode.Bytes_Provided = sizeof(errcode);

    *entries_returned = 0;

    /* Call QjoRetrieveJournalEntries
     * Prototype: void QjoRetrieveJournalEntries(
     *   char *receiver_var,      -- output buffer
     *   int   receiver_len,      -- output buffer length
     *   char *format_name,       -- "RJNE0200"
     *   char *jrn_name,          -- qualified journal name
     *   char *jrn_enttype_info,  -- entry type filter
     *   char *selection_criteria,-- JOES0100 structure
     *   Qus_EC_t *error_code
     * )
     */
    QjoRetrieveJournalEntries(
        (char*)out_buf,
        out_buf_len,
        "RJNE0200",
        jrn_qualified,
        "*",            /* All entry types */
        seq_str,        /* Starting sequence */
        &errcode
    );

    if (errcode.Bytes_Available > 0) {
        fprintf(stderr, "QjoRetrieveJournalEntries error: %.7s\n",
                errcode.Exception_Id);
        return -1;
    }

    /* First 4 bytes = number of entries */
    memcpy(entries_returned, out_buf, 4);
    *entries_returned = ntohl(*entries_returned);  /* API returns big-endian */

    return 0;
}

/* Parse RJNE0200 format entry and build wire packet */
int pack_wire_entry(
        const uint8_t  *rjne_buf,   /* points to start of one RJNE0200 entry */
        WireEntry      *wire,
        uint8_t        *data_buf,
        uint32_t       *data_len)
{
    /* RJNE0200 entry layout offsets (from IBM documentation):
     * Offset 0:   Next entry offset (binary 4)
     * Offset 4:   Sequence number (char 20)
     * Offset 24:  Timestamp (char 26)
     * Offset 50:  Thread ID (char 10)
     * Offset 60:  System sequence number (binary 8)
     * Offset 68:  Count/RRN (binary 8)
     * Offset 76:  Flag (char 1)
     * Offset 77:  Entry type (char 2)
     * Offset 79:  Entry code (char 1)
     * Offset 80:  Library name (char 10)
     * Offset 90:  Object name (char 10)
     * Offset 100: Member name (char 10)
     * Offset 110: Job name (char 26)
     * Offset 136: Specific data offset (binary 4)
     * Offset 140: Specific data length (binary 4)
     * Offset 144: (specific data follows)
     */

    uint32_t next_offset;
    memcpy(&next_offset, rjne_buf + 0, 4);

    char seq_str[21] = {0};
    memcpy(seq_str, rjne_buf + 4, 20);
    uint64_t seq = strtoull(seq_str, NULL, 10);

    char entry_type[3] = {0};
    memcpy(entry_type, rjne_buf + 77, 2);

    char entry_code[2] = {0};
    memcpy(entry_code, rjne_buf + 79, 1);

    uint32_t data_offset_in_entry, specific_len;
    memcpy(&data_offset_in_entry, rjne_buf + 136, 4);
    memcpy(&specific_len,         rjne_buf + 140, 4);

    memset(wire, 0, sizeof(WireEntry));
    wire->magic           = htonl(MAGIC);
    wire->sequence_number = seq;
    wire->flags           = 0x02; /* after image */

    memcpy(wire->library, rjne_buf + 80,  10);
    memcpy(wire->file,    rjne_buf + 90,  10);
    memcpy(wire->member,  rjne_buf + 100, 10);
    memcpy(wire->job_name,rjne_buf + 110, 26);

    /* Trim trailing spaces (IBM i pads with spaces) */
    wire->library[10] = wire->file[10] = wire->member[10] = '\0';

    wire->entry_type = htonl(((uint32_t)entry_type[0] << 8) | entry_type[1]);
    wire->entry_code = htonl(entry_code[0]);

    /* Copy specific data (the actual row before/after image) */
    if (specific_len > 0 && specific_len <= MAX_ENTRY_SIZE) {
        memcpy(data_buf, rjne_buf + data_offset_in_entry, specific_len);
        *data_len = specific_len;
        wire->data_length = htonl(specific_len);
        wire->data_offset = htonl(sizeof(WireEntry));
    } else {
        *data_len = 0;
    }

    wire->entry_len = htonl(sizeof(WireEntry) + *data_len);

    return (int)next_offset;
}

ssize_t send_all(int fd, const void *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t s = send(fd, (const char*)buf + sent, len - sent, 0);
        if (s <= 0) return s;
        sent += s;
    }
    return sent;
}

int send_wire_entry(int sock, const WireEntry *wire,
                    const uint8_t *data, uint32_t data_len) {
    if (send_all(sock, wire, sizeof(*wire)) != sizeof(*wire)) return -1;
    if (data_len > 0)
        if (send_all(sock, data, data_len) != data_len) return -1;

    /* Wait for ACK */
    uint8_t ack;
    if (recv(sock, &ack, 1, MSG_WAITALL) != 1 || ack != 0xAC) return -1;
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr,
            "Usage: %s <jrn_lib> <jrn_name> <target_ip> <target_port>\n"
            "Example: %s MYLIB MYJRN 192.168.1.100 9100\n",
            argv[0], argv[0]);
        return 1;
    }

    const char *jrn_lib  = argv[1];
    const char *jrn_name = argv[2];
    const char *tgt_ip   = argv[3];
    int         tgt_port = atoi(argv[4]);

    uint64_t last_seq = load_checkpoint();
    printf("Starting from sequence: %llu\n", (unsigned long long)last_seq);

    uint8_t *rjne_buf  = malloc(4 * 1024 * 1024);   /* 4MB entry buffer */
    uint8_t *data_buf  = malloc(MAX_ENTRY_SIZE);
    if (!rjne_buf || !data_buf) { perror("malloc"); return 1; }

    int sock = connect_target(tgt_ip, tgt_port);
    if (sock < 0) { fprintf(stderr, "Cannot connect to target\n"); return 1; }

    printf("Connected to %s:%d\n", tgt_ip, tgt_port);

    while (1) {
        uint32_t entries_returned = 0;

        int rc = retrieve_journal_entries(
            jrn_lib, jrn_name,
            last_seq + 1,
            rjne_buf, 4 * 1024 * 1024,
            &entries_returned);

        if (rc < 0) {
            fprintf(stderr, "Error retrieving entries, retrying in 5s\n");
            sleep(5);
            continue;
        }

        if (entries_returned == 0) {
            /* No new entries — poll interval */
            usleep(500000);   /* 500ms */
            continue;
        }

        /* Walk the entries in RJNE0200 format */
        uint32_t offset = 4;  /* skip entry count */
        for (uint32_t i = 0; i < entries_returned; i++) {
            WireEntry wire;
            uint32_t  data_len = 0;

            int next = pack_wire_entry(rjne_buf + offset,
                                       &wire, data_buf, &data_len);

            if (send_wire_entry(sock, &wire, data_buf, data_len) < 0) {
                fprintf(stderr, "Send failed — reconnecting\n");
                close(sock);
                sleep(3);
                sock = connect_target(tgt_ip, tgt_port);
                if (sock < 0) { sleep(10); continue; }
                /* Retry this entry */
                send_wire_entry(sock, &wire, data_buf, data_len);
            }

            last_seq = ntohll(wire.sequence_number);
            save_checkpoint(last_seq);

            if (next == 0) break;
            offset += next;
        }

        printf("Applied %u entries, last seq: %llu\n",
               entries_returned, (unsigned long long)last_seq);
    }

    free(rjne_buf);
    free(data_buf);
    close(sock);
    return 0;
}
