/* pi8.c — pi3-style (main blocks on LOCK_PI vs holder) but dump ALL offsets
 * in +-0x8000 windows around the 4 unconfirmed symbols. Safe, bounded. */
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
#define MAXO 500000
static uint64_t offs[MAXO]; static int no;
static volatile int fut=0, stop=0;
static inline long xf(void*u,int op){ return syscall(98,u,op,0,0,0,0); }
#define FLPI (6|128)
#define FUPI (7|128)
static void alrm(int s){(void)s;stop=1;}

static void* holder(void*x){ (void)x;
    xf(&fut,FLPI);
    while(!stop){ usleep(4000); xf(&fut,FUPI); usleep(4000); xf(&fut,FLPI); }
    xf(&fut,FUPI); return 0;
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
static int cmpu(const void*x,const void*y){uint64_t A=*(uint64_t*)x,B=*(uint64_t*)y;return A<B?-1:A>B;}
int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    signal(SIGALRM,alrm); alarm(45);
    uint64_t kt=kaaslr_text_base(); for(int r=0;r<6&&!kt;r++) kt=kaaslr_text_base();
    printf("[M] _text=%#018llx\n",(unsigned long long)kt); if(!kt)return 1;
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CALLCHAIN; a.sample_period=700;
    a.disabled=1; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    int fd=(int)syscall(__NR_perf_event_open,&a,0,-1,-1,0);
    if(fd<0){printf("[M] perf %d\n",errno);return 1;}
    size_t pg=sysconf(_SC_PAGESIZE), ds=RP*pg, ms=ds+pg;
    void*base=mmap(NULL,ms,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(base==MAP_FAILED){printf("[M] mmap %d\n",errno);return 1;}
    struct perf_event_mmap_page*meta=base;
    pthread_t h; pthread_create(&h,0,holder,0); usleep(30000);
    ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0);
    for(int i=0;i<300 && !stop && no<MAXO;i++){ xf(&fut,FLPI); xf(&fut,FUPI); drain(base,pg,ds,meta,kt); }
    drain(base,pg,ds,meta,kt);
    ioctl(fd,PERF_EVENT_IOC_DISABLE,0);
    stop=1; pthread_join(h,0); munmap(base,ms); close(fd);
    printf("[M] offsets=%d\n",no);
    uint64_t*so=malloc(sizeof(uint64_t)*(no?no:1)); memcpy(so,offs,sizeof(uint64_t)*no);
    qsort(so,no,sizeof(uint64_t),cmpu);
    struct{long s;const char*nm;}S[]={
        {0x9f153c,"rb_insert_color"},{0x9f16ac,"rb_erase"},
        {0x14f7d0c,"remove_waiter"},{0x14f81f4,"rt_mutex_adjust_prio_chain"},
        {0x277038,"do_futex"},{0x27a8fc,"futex_lock_pi"}};
    for(unsigned k=0;k<sizeof(S)/sizeof(S[0]);k++){
        long lo=S[k].s-0x8000, hi=S[k].s+0x8000; int c=0;
        printf("== %s (%#lx) window +-0x8000: ",S[k].nm,(unsigned long)S[k].s);
        /* count + first few distinct */
        int shown=0;
        for(int i=0;i<no;){
            uint64_t v=so[i]; int j=i+1; while(j<no&&so[j]==v)j++;
            if((long)v>=lo&&(long)v<hi){ c+=(j-i); if(shown<6){ printf("%#lx(x%d,+%ld) ",(unsigned long)v,j-i,(long)v-S[k].s); shown++; } }
            i=j;
        }
        printf(" total=%d\n",c);
    }
    /* also: top 10 offsets overall in 0x9e0000-0xa20000 and 0x14e0000-0x1520000 */
    struct{long lo,hi;const char*t;}Z[]={{0x9e0000,0xa20000,"rb-region"},{0x14e0000,0x1520000,"rtmutex-region"}};
    for(unsigned z=0;z<2;z++){
        printf("== top in %s ==\n",Z[z].t);
        int shown=0;
        for(int i=0;i<no && shown<10;){
            uint64_t v=so[i]; int j=i+1; while(j<no&&so[j]==v)j++;
            if((long)v>=Z[z].lo&&(long)v<Z[z].hi){ printf("   %#lx x%d\n",(unsigned long)v,j-i); shown++; }
            i=j;
        }
    }
    free(so);
    return 0;
}
