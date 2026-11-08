/* futex_pi_perf2.c — contended PI; per-thread perf (one event per worker tid),
 * count hits within A.127 (5.15.170) function ranges. Safe: no requeue_pi. */
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
#define RP 8
#define MAXO 800000
static uint64_t offs[MAXO]; static int no;
static volatile int fut=0, stop=0;

static inline long xf(void*u,int op){ return syscall(98,u,op,0,0,0,0); }
#define FLPI (6|128)
#define FUPI (7|128)

struct Ev { int fd; void*base; size_t ds,pg; struct perf_event_mmap_page*meta; };
static uint64_t kt;

static void open_ev(struct Ev*e){
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CALLCHAIN; a.sample_period=2000;
    a.disabled=0; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    int fd=(int)syscall(__NR_perf_event_open,&a,0,-1,-1,0);   /* calling thread */
    e->fd=fd; e->base=MAP_FAILED; e->meta=0;
    if(fd<0) return;
    e->pg=sysconf(_SC_PAGESIZE); e->ds=RP*e->pg;
    void*b=mmap(NULL,e->ds+e->pg,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(b==MAP_FAILED){ close(fd); e->fd=-1; return; }
    e->base=b; e->meta=b;
}
static void drain(struct Ev*e){
    if(e->fd<0||e->base==MAP_FAILED) return;
    char*d=(char*)e->base+e->pg; __sync_synchronize();
    uint64_t head=e->meta->data_head;
    while(e->meta->data_tail<head){
        struct perf_event_header*h=(void*)(d+(e->meta->data_tail%e->ds));
        if(h->size<sizeof(*h)){e->meta->data_tail=head;break;}
        if(h->type==PERF_RECORD_SAMPLE){
            char*q=(char*)h+sizeof(*h);
            uint64_t ip; memcpy(&ip,q,8); q+=8;
            uint64_t nr; memcpy(&nr,q,8); q+=8;
            if(ip>=0xffff000000000000UL&&no<MAXO) offs[no++]=ip-kt;
            if(nr>32)nr=32;
            for(uint64_t k=0;k<nr;k++){uint64_t c;memcpy(&c,q,8);q+=8;
                if(c>=0xffff000000000000UL&&no<MAXO) offs[no++]=c-kt;}
        }
        e->meta->data_tail+=h->size;
    }
}
static void* worker(void*arg){
    int us=(int)(long)arg;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    struct Ev e; memset(&e,0,sizeof(e)); e.fd=-1;
    open_ev(&e);
    while(!stop){
        xf(&fut,FLPI); if(us) usleep(us); xf(&fut,FUPI);
        drain(&e);
    }
    drain(&e);
    if(e.fd>=0){ if(e.base!=MAP_FAILED) munmap(e.base,e.ds+e.pg); close(e.fd); }
    return 0;
}
static int cmpu(const void*x,const void*y){uint64_t A=*(uint64_t*)x,B=*(uint64_t*)y;return A<B?-1:A>B;}
int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    kt=kaaslr_text_base(); for(int r=0;r<6&&!kt;r++) kt=kaaslr_text_base();
    printf("[*] _text_runtime=%#018llx\n",(unsigned long long)kt);
    if(!kt) return 1;
    pthread_t a,b;
    pthread_create(&a,0,worker,(void*)200L);   /* owner: holder, brief */
    pthread_create(&b,0,worker,(void*)0L);     /* contender */
    for(int i=0;i<500 && no<MAXO;i++) usleep(5000);
    stop=1; pthread_join(a,0); pthread_join(b,0);
    printf("[*] offsets=%d\n",no);
    struct { long lo,hi; const char*nm; } R[]={
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
        int c=0; uint64_t mn=~0ull,mx=0;
        for(int i=0;i<no;i++) if((long)offs[i]>=R[r].lo&&(long)offs[i]<R[r].hi){c++;if(offs[i]<mn)mn=offs[i];if(offs[i]>mx)mx=offs[i];}
        printf("HIT %-30s count=%-7d",R[r].nm,c);
        if(c)printf(" [%#lx..%#lx]",(unsigned long)mn,(unsigned long)mx);
        printf("\n");
    }
    /* top offsets in general .text to see where we are */
    {
        static uint64_t o[20000]; static int cc[20000]; int n=0;
        uint64_t*so=malloc(sizeof(uint64_t)*no); memcpy(so,offs,sizeof(uint64_t)*no);
        qsort(so,no,sizeof(uint64_t),cmpu);
        for(int i=0;i<no;){uint64_t v=so[i];int c=1,j=i+1;while(j<no&&so[j]==v){c++;j++;}if(n<20000){o[n]=v;cc[n]=c;n++;}i=j;}
        free(so);
        printf("=== top 15 kernel offsets seen ===\n");
        for(int t=0;t<15;t++){int bi=-1;for(int k=0;k<n;k++)if(cc[k]>0&&(bi<0||cc[k]>cc[bi]))bi=k;if(bi<0)break;
            printf("%#010lx x%d\n",(unsigned long)o[bi],cc[bi]);cc[bi]=0;}
    }
    return 0;
}
