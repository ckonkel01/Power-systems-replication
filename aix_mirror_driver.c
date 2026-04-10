/* aix_mirror_driver.c
 * AIX kernel block device driver — intercepts writes, mirrors to target.
 * Build with: make -f /usr/lpp/bos/kernext/conf/Makefile.kernext \
 *             DRIVER=aix_mirror_driver
 *
 * WARNING: Kernel code. A bug here panics the machine.
 * Test in a VM first. Always.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/device.h>
#include <sys/devinfo.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/lockl.h>
#include <sys/sleep.h>
#include <sys/sysmacros.h>
#include <sys/intr.h>
#include <net/if.h>
#include <netinet/in.h>

#define MIRROR_DEVNAME  "aixmirror"
#define MIRROR_MAGIC    0x4D495252   /* "MIRR" */
#define MIRROR_PORT     9001
#define MAX_PENDING_IOS 64

/* Per-device state */
typedef struct {
    dev_t       real_dev;           /* Underlying real device */
    int         mirror_sock;        /* Socket to Linux target */
    struct sockaddr_in target_addr;
    lock_t      io_lock;
    int         mirror_enabled;
    uint64_t    writes_intercepted;
    uint64_t    writes_failed;
} MirrorDev;

/* Network mirror header (matches Linux receiver) */
typedef struct {
    uint32_t magic;
    uint64_t blkno;         /* block number */
    uint32_t blkcount;      /* number of blocks */
    uint32_t blksize;       /* bytes per block */
    uint8_t  op;            /* 0=write, 1=discard */
} __attribute__((packed)) MirrorHdr;

static MirrorDev g_mirror = {0};

/* Send a write to the Linux mirror target.
 * Called from interrupt context — must be non-blocking.
 * Real implementation needs a kernel thread + queue.
 */
static void mirror_send_write(daddr_t blkno, uint32_t count,
                               uint32_t blksize, caddr_t data) {
    MirrorHdr hdr = {
        .magic    = MIRROR_MAGIC,
        .blkno    = blkno,
        .blkcount = count,
        .blksize  = blksize,
        .op       = 0
    };

    /* NOTE: In real kernel code you'd use a kernel-space socket
     * (ksocket on AIX 6.1+) and queue this to a kernel thread.
     * Direct socket calls from interrupt context are illegal.
     * This is the logical structure — not interrupt-safe as-is.
     */

    struct iovec iov[2] = {
        { .iov_base = &hdr,  .iov_len = sizeof(hdr)           },
        { .iov_base = data,  .iov_len = count * blksize        }
    };

    struct msghdr msg = {
        .msg_iov    = iov,
        .msg_iovlen = 2
    };

    /* ksend() is AIX 6.1+ kernel socket API */
    /* ksend(g_mirror.mirror_sock, &msg, 0); */

    g_mirror.writes_intercepted++;
}

/* Main strategy routine — called for every I/O to this device */
int mirror_strategy(struct buf *bp) {
    /* Pass-through to real device */
    bp->b_dev = g_mirror.real_dev;

    /* Intercept writes */
    if ((bp->b_flags & B_READ) == 0 && g_mirror.mirror_enabled) {
        mirror_send_write(
            bp->b_blkno,
            bp->b_bcount / 512,
            512,
            bp->b_un.b_addr
        );
    }

    /* Forward to underlying driver's strategy routine */
    return devstrat(bp);
}

/* ioctl for control (enable/disable mirror, set target IP, etc.) */
int mirror_ioctl(dev_t dev, int cmd, caddr_t arg,
                 int flag, chan_t chan, int ext) {
    switch (cmd) {
        case 0x4D01: { /* MIRROR_SET_TARGET */
            struct sockaddr_in *addr = (struct sockaddr_in *)arg;
            memcpy(&g_mirror.target_addr, addr, sizeof(*addr));
            return 0;
        }
        case 0x4D02: /* MIRROR_ENABLE  */
            g_mirror.mirror_enabled = 1;
            return 0;
        case 0x4D03: /* MIRROR_DISABLE */
            g_mirror.mirror_enabled = 0;
            return 0;
        case 0x4D04: { /* MIRROR_STATS */
            uint64_t stats[2] = {
                g_mirror.writes_intercepted,
                g_mirror.writes_failed
            };
            copyout(stats, arg, sizeof(stats));
            return 0;
        }
    }
    return EINVAL;
}

/* Driver entry points */
struct devsw mirror_devsw = {
    .d_open     = nodev,
    .d_close    = nodev,
    .d_read     = nodev,
    .d_write    = nodev,
    .d_ioctl    = mirror_ioctl,
    .d_strategy = mirror_strategy,
    .d_ttys     = NULL,
    .d_select   = nodev,
    .d_config   = nodev,
    .d_print    = nodev,
    .d_dump     = nodev,
    .d_mpx      = nodev,
    .d_revoke   = nodev,
    .d_dsdptr   = NULL,
    .d_selptr   = NULL,
    .d_opts     = DEV_MPSAFE
};

int mirror_init(void) {
    memset(&g_mirror, 0, sizeof(g_mirror));
    lockl_init(&g_mirror.io_lock, LOCK_ALLOC_PIN);
    /* Real device set via mkdev/cfgmgr at install time */
    return 0;
}
