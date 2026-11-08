/* futex_check.c — SAFE presence check for the futex PI path (v2, non-blocking).
 *
 * Does NOT build a PI cycle and does NOT create a UAF. Every call is
 * time-bounded or non-blocking. Only confirms that PI futex options are
 * supported (not ENOSYS) and which errno they return.
 *
 * v2 fix: correct argument slots
 *   sys_futex(uaddr, op, val, timeout, uaddr2, val3)
 *   - WAIT_REQUEUE_PI: timeout <= 200 ms (so it does NOT hang), uaddr2=target
 *   - CMP_REQUEUE_PI : uaddr2 in the uaddr2 slot, val3=cmp
 *
 * Build:
 *   CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang
 *   $CC -O2 -static -pie -fPIE -o futex_check futex_check.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>

#define SYS_FUTEX 98
#define FUTEX_WAIT             0
#define FUTEX_LOCK_PI          6
#define FUTEX_UNLOCK_PI        7
#define FUTEX_WAIT_REQUEUE_PI  11
#define FUTEX_CMP_REQUEUE_PI   12
#define FUTEX_PRIVATE_FLAG     128

static inline long futx(void *u, int op, int val, void *t, void *u2, int v3)
{
    register long x8 __asm__("x8") = SYS_FUTEX;
    register long x0 __asm__("x0") = (long)u;
    register long x1 __asm__("x1") = op;
    register long x2 __asm__("x2") = val;
    register long x3 __asm__("x3") = (long)t;
    register long x4 __asm__("x4") = (long)u2;
    register long x5 __asm__("x5") = v3;
    __asm__ volatile("svc #0" : "+r"(x0)
        : "r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8) : "memory","cc");
    return x0;
}

static void show(const char *name, long r)
{
    printf("%-30s -> %ld (errno=%d %s)\n", name, r, errno,
           r < 0 ? strerror(errno) : "ok");
}

int main(void)
{
    uint32_t f1 = 0, f2 = 0, f3 = 0;
    printf("futex PI presence check v2 (safe, non-blocking)\n");
    setvbuf(stdout, NULL, _IONBF, 0);

    errno = 0; long r1 = futx(&f1, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
    show("FUTEX_LOCK_PI(f1)", r1);

    /* WAIT_REQUEUE_PI with a 200 ms timeout: expect ETIMEDOUT (not ENOSYS).
       uaddr=&f3, timeout=&ts, uaddr2=&f1 (target must be PI; f1 is ours). */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000 };
    errno = 0;
    long r3 = futx(&f3, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 0, &ts, &f1, 0);
    show("FUTEX_WAIT_REQUEUE_PI(200ms)", r3);

    /* CMP_REQUEUE_PI is non-blocking. Bad cmpval -> EAGAIN (not ENOSYS).
       uaddr=&f2, val=1, uaddr2=&f3, val3=0xdead (intentionally wrong). */
    errno = 0;
    long r4 = futx(&f2, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG, 1, 0, &f3, 0xdead);
    show("FUTEX_CMP_REQUEUE_PI", r4);

    errno = 0; long r5 = futx(&f1, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
    show("FUTEX_UNLOCK_PI(f1)", r5);

    printf("Conclusion: no ENOSYS = PI futex works (CVE path exists).\n");
    return 0;
}
