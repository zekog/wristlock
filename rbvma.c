/* rbvma.c — perf-validate rb_insert_color/rb_erase via VMA rbtree churn.
 * mmap/munmap MAP_FIXED_NOREPLACE in a loop in main thread; perf pid=0.
 * No writes to kernel objects. Safe. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
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
static volatile int stop=0;
static void alrm(int s){(void)s;stop=1;}

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
    signal(SIGALRM,alrm); alarm(60);
    uint64_t kt=kaaslr_text_base(); for(int r=0;r<6&&!kt;r++) kt=kaaslr_text_base();
    printf("[M] _text=%#018llx\n",(unsigned long long)kt); if(!kt)return 1;
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CALLCHAIN; a.sample_period=300;
    a.disabled=1; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    int fd=(int)syscall(__NR_perf_event_open,&a,0,-1,-1,0);
    if(fd<0){printf("[M] perf %d (%s)\n",errno,strerror(errno));return 1;}
    size_t pg=sysconf(_SC_PAGESIZE), ds=RP*pg, ms=ds+pg;
    void*base=mmap(NULL,ms,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(base==MAP_FAILED){printf("[M] mmap %d\n",errno);return 1;}
    struct perf_event_mmap_page*meta=base;
    printf("[M] perf on, mmap churn\n");
    ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0);
    uintptr_t hint=0x2000000000UL;
    long it=0;
    for(;it<200000 && !stop && no<MAXO;it++){
        void*p=mmap((void*)hint, 0x2000, PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
        if(p!=MAP_FAILED) munmap(p,0x2000);
        hint += 0x4000;
        if(hint>0x4000000000UL) hint=0x2000000000UL;
        if((it&0x3ff)==0) drain(base,pg,ds,meta,kt);
    }
    drain(base,pg,ds,meta,kt);
    ioctl(fd,PERF_EVENT_IOC_DISABLE,0);
    printf("[M] iters=%ld offsets=%d\n",it,no);
    munmap(base,ms); close(fd);
    struct{long lo,hi;const char*nm;}R[]={
        {0x9f153c,0x9f153c+0x400,"rb_insert_color"},
        {0x9f16ac,0x9f16ac+0x400,"rb_erase"},
        {0x9f0a00,0x9f2000,"rb region wide"},
        {0x11470,0x11780,"el0t_64_sync"},
        {0x277038,0x279200,"do_futex"},
    };
    for(unsigned r=0;r<sizeof(R)/sizeof(R[0]);r++){
        int c=0;uint64_t mn=~0ull,mx=0;
        for(int i=0;i<no;i++)if((long)offs[i]>=R[r].lo&&(long)offs[i]<R[r].hi){c++;if(offs[i]<mn)mn=offs[i];if(offs[i]>mx)mx=offs[i];}
        printf("HIT %-22s count=%-6d",R[r].nm,c);
        if(c)printf(" first=%#lx (+%#lx) last=%#lx",(unsigned long)mn,(unsigned long)(mn-R[r].lo),(unsigned long)mx);
        printf("\n");
    }
    /* distinct offsets in rb wide window */
    printf("=== distinct offsets in 0x9f0000..0x9f4000 ===\n");
    int shown=0;
    for(int i=0;i<no&&shown<25;){
        uint64_t v=offs[i]; int j=i+1; while(j<no&&offs[j]==v)j++;
        if((long)v>=0x9f0000&&(long)v<0x9f4000){printf("  %#08lx x%d\n",(unsigned long)v,j-i);shown++;}
        i=j;
    }
    return 0;
}
