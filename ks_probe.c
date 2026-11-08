/* ks_probe.c v2 — stronger KernelSnitch signal test.
 * - futexes on MAP_SHARED|MAP_ANONYMOUS (global hash => includes mm_struct)
 * - 256 waiters in a SINGLE bucket (amplification)
 * - 8192 probes + RE-PROBE of outliers (signal vs noise)
 * Safe. Build: -O2 -static -pie -fPIE -pthread
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
#include <sys/mman.h>
#include <stdlib.h>

#define SYS_FUTEX 98
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
/* NOTE: no FUTEX_PRIVATE_FLAG -> shared-anonymous -> global hash with mm_struct */

#define NWAIT 256
#define NPROBE 8192
#define PAGE 4096

static uint32_t *hold;             /* uaddr with NWAIT waiters */
static volatile int stop_hold;

static void *hold_fn(void *x){ (void)x;
    while(!stop_hold)
        syscall(SYS_FUTEX,hold,FUTEX_WAIT,0,NULL,NULL,0);
    return NULL;
}
static inline uint64_t now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
    return (uint64_t)t.tv_sec*1000000000ull+t.tv_nsec;}
static uint64_t probe_once(uint32_t*u){uint64_t a=now_ns();
    syscall(SYS_FUTEX,u,FUTEX_WAKE,1,NULL,NULL,0);return now_ns()-a;}
static int cmp(const void*a,const void*b){uint64_t x=*(uint64_t*)a,y=*(uint64_t*)b;return x<y?-1:x>y?1:0;}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    printf("=== ks_probe v2 (shared-anon, amp=%d) ===\n",NWAIT);
    cpu_set_t cs;CPU_ZERO(&cs);CPU_SET(0,&cs);sched_setaffinity(0,sizeof(cs),&cs);

    size_t sz=(size_t)PAGE*(NPROBE+64);
    uint8_t *sh=mmap(NULL,sz,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(sh==MAP_FAILED){printf("[!] mmap errno=%d\n",errno);return 1;}
    memset(sh,0,sz);
    hold=(uint32_t*)(sh+PAGE/2);               /* full bucket */

    pthread_t th[NWAIT];
    for(int i=0;i<NWAIT;i++) pthread_create(&th[i],NULL,hold_fn,NULL);
    usleep(400000);

    uint64_t *t=malloc(sizeof(uint64_t)*NPROBE);
    uint32_t **u=malloc(sizeof(uint32_t*)*NPROBE);
    for(int i=0;i<NPROBE;i++){
        u[i]=(uint32_t*)(sh+(size_t)(i+4)*PAGE+PAGE/2);
        uint64_t mn=~0ull;
        for(int k=0;k<7;k++){uint64_t d=probe_once(u[i]);if(d<mn)mn=d;}
        t[i]=mn;
    }
    stop_hold=1;
    for(int i=0;i<16;i++) syscall(SYS_FUTEX,hold,FUTEX_WAKE,NWAIT,NULL,NULL,0);
    for(int i=0;i<NWAIT;i++) pthread_join(th[i],NULL);

    uint64_t *s=malloc(sizeof(uint64_t)*NPROBE);memcpy(s,t,8*NPROBE);qsort(s,NPROBE,8,cmp);
    uint64_t med=s[NPROBE/2];
    printf("min=%llu p50=%llu p90=%llu p99=%llu max=%llu ns\n",
        (unsigned long long)s[0],(unsigned long long)med,(unsigned long long)s[NPROBE*9/10],
        (unsigned long long)s[NPROBE*99/100],(unsigned long long)s[NPROBE-1]);

    /* candidates: > med + med/2 */
    int cand=0, confirmed=0;
    for(int i=0;i<NPROBE;i++){
        if(t[i] > med + med/2){
            cand++;
            /* re-probe: 15 samples, min */
            uint64_t mn=~0ull; for(int k=0;k<15;k++){uint64_t d=probe_once(u[i]);if(d<mn)mn=d;}
            if(mn > med + med/4){ confirmed++; if(confirmed<=8)
                printf("  confirmed: idx=%d min=%llu (med=%llu)\n",i,(unsigned long long)mn,(unsigned long long)med); }
        }
    }
    printf("candidates=%d  CONFIRMED=%d  (if CONFIRMED>0 -> real signal)\n",cand,confirmed);
    return 0;
}
