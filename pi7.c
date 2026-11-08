/* pi7.c — per-thread perf inside the worker thread itself; worker does the PI
 * blocking. No CPU pinning, no shared-fd races. SIGALRM guard. */
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
#define RP 8
#define MAXO 400000
static uint64_t offs[MAXO]; static volatile int no=0;
static volatile int fut=0, go=0, stop=0;
static inline long xf(void*u,int op){ return syscall(98,u,op,0,0,0,0); }
#define FLPI (6|128)
#define FUPI (7|128)
static void alrm(int s){(void)s;stop=1;}
static uint64_t kt;

static void drain(void*base,size_t pg,size_t ds,struct perf_event_mmap_page*meta){
    char*d=(char*)base+pg; __sync_synchronize();
    uint64_t head=meta->data_head;
    while(meta->data_tail<head){
        struct perf_event_header*h=(void*)(d+(meta->data_tail%ds));
        if(h->size<sizeof(*h)){meta->data_tail=head;break;}
        if(h->type==PERF_RECORD_SAMPLE){
            char*q=(char*)h+sizeof(*h);
            uint64_t ip; memcpy(&ip,q,8); q+=8;
            uint64_t nr; memcpy(&nr,q,8); q+=8;
            if(ip>=0xffff000000000000UL && no<MAXO) offs[no++]=ip-kt;
            if(nr>64)nr=64;
            for(uint64_t k=0;k<nr;k++){uint64_t c;memcpy(&c,q,8);q+=8;
                if(c>=0xffff000000000000UL && no<MAXO) offs[no++]=c-kt;}
        }
        meta->data_tail+=h->size;
    }
}
struct ev { int fd; void*base; size_t pg,ds; struct perf_event_mmap_page*meta; };
static int ev_open(struct ev*e){
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CALLCHAIN; a.sample_period=200;
    a.disabled=0; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    int fd=(int)syscall(__NR_perf_event_open,&a,0,-1,-1,0);
    if(fd<0){ printf("[!] perf %d\n",errno); return -1; }
    e->pg=sysconf(_SC_PAGESIZE); e->ds=RP*e->pg;
    void*b=mmap(NULL,e->ds+e->pg,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(b==MAP_FAILED){ close(fd); return -1; }
    e->fd=fd; e->base=b; e->meta=b; return 0;
}
static void* holder(void*x){ (void)x;
    for(int r=0;r<200 && !stop;r++){
        xf(&fut,FLPI); go=1;
        usleep(2500);
        xf(&fut,FUPI);
        go=0;
        usleep(1200);
    }
    return 0;
}
static void* waiter(void*x){ (void)x;
    struct ev e; if(ev_open(&e)<0) return 0;
    printf("[M] waiter perf fd ok\n");
    for(int r=0;r<200 && !stop;r++){
        while(go==0 && !stop) usleep(100);
        xf(&fut,FLPI);       /* blocks until holder unlocks */
        xf(&fut,FUPI);
        drain(e.base,e.pg,e.ds,e.meta);
    }
    drain(e.base,e.pg,e.ds,e.meta);
    munmap(e.base,e.ds+e.pg); close(e.fd);
    printf("[M] waiter done\n");
    return 0;
}
int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    signal(SIGALRM,alrm); alarm(40);
    kt=kaaslr_text_base(); for(int r=0;r<6&&!kt;r++) kt=kaaslr_text_base();
    printf("[M] _text=%#018llx\n",(unsigned long long)kt); if(!kt)return 1;
    pthread_t h,w; pthread_create(&w,0,waiter,0); usleep(5000);
    pthread_create(&h,0,holder,0);
    while(!stop && no<MAXO) usleep(5000);
    stop=1; pthread_join(h,0); pthread_join(w,0);
    printf("[M] offsets=%d\n",(int)no);
    struct{long lo,hi;const char*nm;}R[]={
        {0x9f153c,0x9f153c+0x200,"rb_insert_color"},
        {0x9f16ac,0x9f16ac+0x200,"rb_erase"},
        {0x14f7d0c,0x14f7d0c+0x200,"remove_waiter"},
        {0x14f81f4,0x14f81f4+0x200,"rt_mutex_adjust_prio_chain"},
        {0x277038,0x279200,"do_futex"},
        {0x27a8fc,0x27b600,"futex_lock_pi"},
        {0x11470,0x11780,"el0t_64_sync"},
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
