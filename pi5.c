/* pi5.c — contended PI, no CPU pinning (avoid same-CPU deadlock), bounded loop,
 * SIGALRM hard stop. perf on main thread only. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include "kaaslr.h"
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif
#define RP 16
#define MAXO 400000
static uint64_t offs[MAXO]; static int no;
static volatile int fut=0, stop=0;
static inline long xf(void*u,int op,void*ts){ return syscall(98,u,op,0,ts,0,0); }
#define FLPI (6|128)
#define FUPI (7|128)
static void alrm(int s){ (void)s; stop=2; }

static void* holder(void*x){ (void)x;
    printf("[M] holder lock\n");
    xf(&fut,FLPI,0);
    printf("[M] holder holding\n");
    while(stop==0) usleep(500);
    xf(&fut,FUPI,0);
    printf("[M] holder released\n");
    return 0;
}
static void* contender(void*x){ (void)x; long n=0; struct timespec ts;
    printf("[M] contender start\n");
    while(stop==0){
        clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_nsec+=20000000; /*20ms*/
        if(ts.tv_nsec>=1000000000){ts.tv_sec++;ts.tv_nsec-=1000000000;}
        xf(&fut,FLPI,&ts); xf(&fut,FUPI,0); n++;
    }
    printf("[M] contender stop n=%ld\n",n); return 0;
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
    signal(SIGALRM,alrm); alarm(45);
    uint64_t kt=kaaslr_text_base(); for(int r=0;r<6&&!kt;r++) kt=kaaslr_text_base();
    printf("[M] _text=%#018llx\n",(unsigned long long)kt); if(!kt)return 1;
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CALLCHAIN; a.sample_period=1000;
    a.disabled=1; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    int fd=(int)syscall(__NR_perf_event_open,&a,0,-1,-1,0);
    if(fd<0){printf("[M] perf %d\n",errno);return 1;}
    size_t pg=sysconf(_SC_PAGESIZE), ds=RP*pg, ms=ds+pg;
    void*base=mmap(NULL,ms,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(base==MAP_FAILED){printf("[M] mmap %d\n",errno);return 1;}
    struct perf_event_mmap_page*meta=base;
    pthread_t h,c; pthread_create(&h,0,holder,0); usleep(30000);
    pthread_create(&c,0,contender,0); usleep(30000);
    printf("[M] perf on, main loop\n");
    ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0);
    for(int i=0;i<200 && stop==0 && no<MAXO;i++){
        struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_nsec+=20000000;
        if(ts.tv_nsec>=1000000000){ts.tv_sec++;ts.tv_nsec-=1000000000;}
        xf(&fut,FLPI,&ts); xf(&fut,FUPI,0);
        drain(base,pg,ds,meta,kt);
    }
    drain(base,pg,ds,meta,kt);
    ioctl(fd,PERF_EVENT_IOC_DISABLE,0);
    printf("[M] loop end offsets=%d\n",no);
    stop=1; pthread_join(c,0); pthread_join(h,0);
    munmap(base,ms); close(fd);
    struct{long lo,hi;const char*nm;}R[]={
        {0x9f153c,0x9f153c+0x200,"rb_insert_color"},
        {0x9f16ac,0x9f16ac+0x200,"rb_erase"},
        {0x14f7d0c,0x14f7d0c+0x200,"remove_waiter"},
        {0x14f81f4,0x14f81f4+0x200,"rt_mutex_adjust_prio_chain"},
        {0x277038,0x279200,"do_futex"},
        {0x27a8fc,0x27b600,"futex_lock_pi"},
    };
    for(unsigned r=0;r<sizeof(R)/sizeof(R[0]);r++){
        int c2=0;uint64_t mn=~0ull,mx=0;
        for(int i=0;i<no;i++)if((long)offs[i]>=R[r].lo&&(long)offs[i]<R[r].hi){c2++;if(offs[i]<mn)mn=offs[i];if(offs[i]>mx)mx=offs[i];}
        printf("HIT %-30s count=%-6d",R[r].nm,c2);
        if(c2)printf(" first=%#lx (+%#lx) last=%#lx",(unsigned long)mn,(unsigned long)(mn-R[r].lo),(unsigned long)mx);
        printf("\n");
    }
    return 0;
}
