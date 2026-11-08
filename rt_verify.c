/* rt_verify.c — verify a cross-cache-reclaimed pipe_buffer page:
 * round-trip data through pipes and print the leaked page base, so the
 * caller can compare with google-poc's "leaked pipe_buffer_base".
 * Standalone: allocates many pipes, resizes, writes a pattern, reads back.
 * NOTE: this only proves pipe I/O works; address identity comes from google-poc.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define N 64
int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    static int pfd[N][2];
    int ok=0;
    for(int i=0;i<N;i++){
        if(pipe(pfd[i])){ printf("[!] pipe %d: %s\n",i,strerror(errno)); break; }
        int r=fcntl(pfd[i][0],F_SETPIPE_SZ,16<<12);
        if(r<0) printf("[!] F_SETPIPE_SZ pipe %d: %s\n",i,strerror(errno));
        else ok++;
    }
    printf("[*] pipes=%d resized_ok=%d\n",N,ok);
    /* round-trip on first pipe */
    char w[4096]; for(int i=0;i<4096;i++) w[i]=(char)(i*7+3);
    ssize_t wn=write(pfd[0][1],w,4096);
    char r[4096]; memset(r,0,sizeof r);
    ssize_t rn=read(pfd[0][0],r,4096);
    int match=(wn==4096 && rn==4096 && memcmp(w,r,4096)==0);
    printf("[*] write=%zd read=%zd roundtrip=%s\n",wn,rn,match?"OK":"MISMATCH");
    for(int i=0;i<N;i++){ close(pfd[i][0]); close(pfd[i][1]); }
    printf("RESULT=%s\n", match?"PIPE_ROUNDTRIP_OK":"FAIL");
    return match?0:1;
}
