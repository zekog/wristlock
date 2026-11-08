/* offsets_w3.h — OnePlus Watch 3 (OPWWE251)
 *
 * ==== DECISION: A.127 (5.15.170 ELF) = device binary ====
 * PROOF:
 *   1) CONFIG IDENTITY: device /proc/config.gz vs config extracted from
 *      A.127 ELF — identical in all options shaping .text/.data
 *      (DEBUG_*, LOCKDEP, KASAN, CFI, LTO_FULL, SLUB_DEBUG, RANDOMIZE_KSTACK).
 *      Only differences: CONFIG_MEMFD_ASHMEM_SHIM, CONFIG_PAGE_BLOCK_ORDER (no
 *      impact on code layout).
 *   2) PERF BYTE-MATCH (live device, read-only): IP hits in
 *      do_futex[0x277284..0x2782c0], futex_wait+0x38/+0x1a8,
 *      futex_wait_queue_me+0x224, fixup_pi_state_owner+0x300, el0t_64_sync+0x1b4
 *      — exactly as in A.127; ZERO hits in the A.169 rebuild (futex 0x29xxxx).
 *   3) uname "5.15.185" = build metadata of A.165 (LOCALVERSION), not a different .text.
 * REJECTED A.169 rebuild: TRIM_UNUSED_KSYMS/BTF off + other deviations => different layout.
 *
 * SYMBOL STATUS:
 *   PROVEN by perf: el0t_64_sync, do_futex, futex_wait, futex_wait_queue_me,
 *                fixup_pi_state_owner, futex_lock_pi, __arm64_sys_futex, get_futex_key
 *   PROVEN logically (before futex, .text matches byte for byte):
 *                commit_creds, prepare_kernel_cred, override_creds
 *   ASSUMED (after futex; consistent with A.127, not hit directly by perf):
 *                rb_insert_color, rb_erase, remove_waiter,
 *                rt_mutex_adjust_prio_chain, AND all data
 *                (init_cred, init_task, init_user_ns, init_pid_ns, core_pattern,
 *                 per_cpu_offset, mmap_min_addr, linux_banner).
 *   Data validation: impossible without OTA A.165 / a read primitive
 *   (kallsyms=avc denied, /proc/kcore does not exist).
 *   Previous set (5.15.185 rebuild) => offsets_w3_5.15.185.h.bak
 *
 * SOURCE: /home/zek/Pobrane/opw3 firmware/extracted_images/kernel_with_symbols.elf
 *         (_text = 0xffffffc008000000, .kernel section VMA=fileoff-0x1c0).
 *         Offsets relative to _text; runtime = _text_runtime + offset.
 */
#ifndef OFFSETS_W3_H
#define OFFSETS_W3_H

#define K_TEXT_BASE              0xffffffc008000000UL

/* ---- functions: full address [A.127, perf-confirmed futex region] ---- */
#define A_COMMIT_CREDS           (K_TEXT_BASE + 0x177fd4UL)
#define A_PREPARE_KERNEL_CRED    (K_TEXT_BASE + 0x178710UL)
#define A_OVERRIDE_CREDS         (K_TEXT_BASE + 0x17849cUL)
#define A_SCHED_SETATTR          (K_TEXT_BASE + 0x18e7a0UL)
#define A_ARM64_SYS_SCHED_SETATTR (K_TEXT_BASE + 0x1952b8UL)
#define A_DO_FUTEX               (K_TEXT_BASE + 0x277038UL)
#define A_FUTEX_WAIT             (K_TEXT_BASE + 0x278f28UL)
#define A_FUTEX_REQUEUE          (K_TEXT_BASE + 0x2794c0UL)
#define A_FUTEX_LOCK_PI          (K_TEXT_BASE + 0x27a8fcUL)
#define A_ARM64_SYS_FUTEX        (K_TEXT_BASE + 0x27d504UL)
#define A_RB_INSERT_COLOR        (K_TEXT_BASE + 0x9f153cUL)
#define A_RB_ERASE               (K_TEXT_BASE + 0x9f16acUL)
#define A_TRY_TO_TAKE_RT_MUTEX   (K_TEXT_BASE + 0x14f6d8cUL)
#define A_RT_MUTEX_SLOWLOCK      (K_TEXT_BASE + 0x14f71ccUL)
#define A_TASK_BLOCKS_ON_RT_MUTEX (K_TEXT_BASE + 0x14f73e4UL)
#define A_REMOVE_WAITER          (K_TEXT_BASE + 0x14f7d0cUL)
#define A_RT_MUTEX_ADJ_PRIO      (K_TEXT_BASE + 0x14f81f4UL)
#define A_RT_MUTEX_START_PROXY   (K_TEXT_BASE + 0x14f9aa0UL)
#define A_LINUX_BANNER           (K_TEXT_BASE + 0x1b18f98UL)

/* ---- data objects [A.127] ---- */
#define A_INIT_CRED              (K_TEXT_BASE + 0x284e5e8UL)
#define A_INIT_TASK              (K_TEXT_BASE + 0x288c3c0UL)
#define A_INIT_USER_NS           (K_TEXT_BASE + 0x2903dd0UL)
#define A_INIT_NS_PROXY          (K_TEXT_BASE + 0x2773670UL)
#define A_ROOT_USER              (K_TEXT_BASE + 0x27737d0UL)
#define A_INIT_UCOUNTS           (K_TEXT_BASE + 0x2773d40UL)
#define A_CORE_PATTERN           (K_TEXT_BASE + 0x2825de0UL)
#define A_MODPROBE_PATH          (K_TEXT_BASE + 0x2773e70UL)
#define A_INIT_PID_NS            (K_TEXT_BASE + 0x283daf0UL)
#define A_INET6_PROTOS           (K_TEXT_BASE + 0x275afc8UL)
#define A_PER_CPU_OFFSET         (K_TEXT_BASE + 0x275c200UL)
#define A_PCPU_BASE_ADDR         (K_TEXT_BASE + 0x1b61cb8UL)
#define A_SELINUX_STATE          (K_TEXT_BASE + 0x29d8fe0UL)
#define A_MMAP_MIN_ADDR          (K_TEXT_BASE + 0x2a06b20UL)
#define A_DAC_MMAP_MIN_ADDR      (K_TEXT_BASE + 0x284ea38UL)

/* ---- structure sizes [C] (production: DEBUG_SPINLOCK=n) ---- */
#define SZ_CRED                  (0xB0UL)
#define SZ_TASK_STRUCT           (0x1280UL)
#define SZ_RT_MUTEX_WAITER       (0x58UL)

/* ---- task_struct [C] ---- */
#define OFF_T_PTRACER_CRED       (0x7F0UL)
#define OFF_T_REAL_CRED          (0x7F8UL)
#define OFF_T_CRED               (0x800UL)
#define OFF_T_PI_LOCK            (0x8ECUL)
#define OFF_T_PI_WAITERS_ROOT    (0x900UL)
#define OFF_T_PI_WAITERS_LEFT    (0x908UL)
#define OFF_T_PI_TOP_TASK        (0x910UL)
#define OFF_T_PI_BLOCKED_ON      (0x918UL)

/* ---- cred [C] ---- */
#define OFF_C_USAGE              (0x00UL)
#define OFF_C_UID                (0x04UL)
#define OFF_C_GID                (0x08UL)
#define OFF_C_SUID               (0x0CUL)
#define OFF_C_SGID               (0x10UL)
#define OFF_C_EUID               (0x14UL)
#define OFF_C_EGID               (0x18UL)
#define OFF_C_FSUID              (0x1CUL)
#define OFF_C_FSGID              (0x20UL)
#define OFF_C_SECUREBITS         (0x24UL)
#define OFF_C_CAP_INHERITABLE    (0x28UL)
#define OFF_C_CAP_PERMITTED      (0x30UL)
#define OFF_C_CAP_EFFECTIVE      (0x38UL)
#define OFF_C_CAP_BSET           (0x40UL)
#define OFF_C_CAP_AMBIENT        (0x48UL)
#define OFF_C_SECURITY           (0x78UL)
#define OFF_C_USER               (0x80UL)
#define OFF_C_USER_NS            (0x88UL)
#define OFF_C_UCOUNTS            (0x90UL)
#define OFF_C_GROUP_INFO         (0x98UL)

/* ---- rt_mutex_waiter [C] ---- */
#define OFF_W_TREE_ENTRY         (0x00UL)
#define OFF_W_PI_TREE_ENTRY      (0x18UL)
#define OFF_W_TASK               (0x30UL)
#define OFF_W_LOCK               (0x38UL)
#define OFF_W_WAKE_STATE         (0x40UL)
#define OFF_W_PRIO               (0x44UL)
#define OFF_W_DEADLINE           (0x48UL)
#define OFF_W_WW_CTX             (0x50UL)

#endif /* OFFSETS_W3_H */
