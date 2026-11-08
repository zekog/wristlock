# GhostLock / CVE-2026-43499 — port design for OnePlus Watch 3 (SW5100, GKI 5.15)

> Research document. Goal: root (UID 0) from userspace, without a bootloader unlock.
> Analysis by an RE session (REA CLI + Ghidra headless + objdump/readelf/ikconfig/pahole).
> Reference artifact: `/home/zek/Pobrane/opw3 firmware/extracted_images/kernel_with_symbols.elf`.
>
> **Note:** this is the original design document. Later findings (the real write primitive,
> the write-if-zero limitation, the CVE sweep, KGSL) are in `FINAL_REPORT.md`.

---

## 1. Vulnerability verdict (summary)

| Item                        | Value                                                                                                   |
| --------------------------- | ------------------------------------------------------------------------------------------------------- |
| Source version (`Makefile`) | 5.15.144                                                                                                |
| **Actual OTA binary**       | **5.15.170-android14-11-maybe-dirty**, clang 17.0.2, `SMP PREEMPT`, +LTO                                |
| `remove_waiter()`           | **UNPATCHED** (uses `current->pi_lock` / `current->pi_blocked_on`)                                      |
| Binary evidence             | `remove_waiter @ 0xffffffc0094f7d0c`: `mrs x20, sp_el0` → `add x22,x20,#0x8ec` → `str xzr,[x20,#0x918]` |
| `CONFIG_FUTEX_PI`           | `=y` (proxy path reachable; LTO inlines `rt_mutex_start_proxy_lock` into `futex_requeue`)               |
| **Verdict**                 | **VULNERABLE**                                                                                          |

**eFuse / secure boot: irrelevant.** This is a user→root LPE on a running system; secure boot only concerns booting unsigned images. The bootloader does NOT need to be unlocked.

### Obstacles for _this_ binary (from `scripts/extract-ikconfig`)

```
CONFIG_RANDOMIZE_BASE=y                       KASLR ON  -> a leak is needed
CONFIG_ARM64_PTR_AUTH(_KERNEL)=y              PAC ON
CONFIG_CFI_CLANG(_SHADOW)=y                   kCFI ON
CONFIG_ARM64_PAN=y                            PAN ON
CONFIG_VMAP_STACK=y + 4K pages                16 KB VMAP stack
CONFIG_KASAN=y + KASAN_HW_TAGS=y + ARM64_MTE=y  ⚠ debug/MTE build (see §6)
CONFIG_STATIC_USERMODEHELPER=y PATH=""        kills core_pattern/modprobe (DirtyMode)
CONFIG_HARDENED_USERCOPY=y
CONFIG_SLAB_FREELIST_{RANDOM,HARDENED}=y, SHUFFLE_PAGE_ALLOCATOR=y
# CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT is not set   ✅ stack randomization OFF
CONFIG_DEFAULT_MMAP_MIN_ADDR=32768
```

---

## 2. Offsets and addresses (from the W3 binary)

`_text = 0xffffffc008000000`

| Symbol                       | Address              | off. from `_text` |
| ---------------------------- | -------------------- | ----------------- |
| `commit_creds`               | `0xffffffc008177fd4` | `0x177fd4`        |
| `prepare_kernel_cred`        | `0xffffffc008178710` | `0x178710`        |
| `override_creds`             | `0xffffffc00817849c` | `0x17849c`        |
| `init_cred`                  | `0xffffffc00a84e5e8` | `0x284e5e8`       |
| `init_task`                  | `0xffffffc00a88c3c0` | `0x288c3c0`       |
| `init_pid_ns`                | `0xffffffc00a83daf0` | `0x283daf0`       |
| `__per_cpu_offset`           | `0xffffffc00a75c200` | `0x275c200`       |
| `pcpu_base_addr`             | `0xffffffc009b61cb8` | `0x1b61cb8`       |
| `core_pattern`               | `0xffffffc00a825de0` | `0x2825de0`       |
| `do_futex`                   | `0xffffffc008277038` | `0x277038`        |
| `futex_requeue`              | `0xffffffc0082794c0` | `0x2794c0`        |
| `futex_lock_pi`              | `0xffffffc00827a8fc` | `0x27a8fc`        |
| `futex_wait`                 | `0xffffffc008278f28` | `0x278f28`        |
| `requeue_pi_wake_futex`      | `0xffffffc00827d1e0` | `0x27d1e0`        |
| `rb_insert_color`            | `0xffffffc0089f153c` | `0x9f153c`        |
| `rb_erase`                   | `0xffffffc0089f16ac` | `0x9f16ac`        |
| `remove_waiter`              | `0xffffffc0094f7d0c` | `0x14f7d0c`       |
| `task_blocks_on_rt_mutex`    | `0xffffffc0094f73e4` | `0x14f73e4`       |
| `try_to_take_rt_mutex`       | `0xffffffc0094f6d8c` | `0x14f6d8c`       |
| `rt_mutex_slowlock`          | `0xffffffc0094f71cc` | `0x14f71cc`       |
| `rt_mutex_adjust_prio_chain` | `0xffffffc0094f81f4` | `0x14f81f4`       |
| `rt_mutex_start_proxy_lock`  | `0xffffffc0094f9aa0` | `0x14f9aa0`       |
| `sched_setattr`              | `0xffffffc00818e7a0` | `0x18e7a0`        |
| `__arm64_sys_sched_setattr`  | `0xffffffc0081952b8` | `0x1952b8`        |

Sizes: `sizeof(cred)=0xB0`, `sizeof(task_struct)=0x1280`, `sizeof(rt_mutex_waiter)=0x58`.

`task_struct`: `ptracer_cred=0x7F0`, `real_cred=0x7F8`, `cred=0x800`, `pi_lock=0x8EC`,
`wake_q=0x8F0`, `wake_q_count=0x8F8`, `pi_waiters.rb_root=0x900`, `rb_leftmost=0x908`,
`pi_top_task=0x910`, `pi_blocked_on=0x918`.

`cred`: `usage=0x00`, `uid=0x04`, `gid=0x08`, `suid=0x0C`, `sgid=0x10`, `euid=0x14`,
`egid=0x18`, `fsuid=0x1C`, `fsgid=0x20`, `securebits=0x24`, caps `0x28..0x4F`,
`security=0x78`, `user=0x80`, `user_ns=0x88`, `ucounts=0x90`, `group_info=0x98`, `rcu=0xA0`.

`rt_mutex_waiter`: `tree_entry=0x00` (rb_node, 0x18), `pi_tree_entry=0x18`,
`task=0x30`, `lock=0x38`, `wake_state=0x40`, `prio=0x44`, `deadline=0x48`, `ww_ctx=0x50`.

---

## 3. Bug mechanism

`remove_waiter()` clears `current->pi_blocked_on`. When called from
`rt_mutex_start_proxy_lock()` (proxy rollback from `futex_requeue()`), `current`
is the _requeuer_, not the _waiter_. Consequence: the waiter returns to user space with
`pi_blocked_on` pointing at its own, already freed stack frame
(`rt_mutex_waiter` from `FUTEX_WAIT_REQUEUE_PI`) → dangling pointer (stack UAF).
A later PI chain walk (e.g. `sched_setattr()`) dereferences it.

Required PI cycle: `waiter → f_pi_target → owner → f_pi_chain → waiter`
(3 futexes, 3 threads), closed by `FUTEX_CMP_REQUEUE_PI` with `-EDEADLK`.

---

## 4. Exploit chain

### 4.1 Trigger (concrete layout)

- `f1, f2, f3` — 3 futex words (PI).
- `T_owner1` locks `f1` (`FUTEX_LOCK_PI(f1)`), `T_owner2` locks `f2`.
- `T_waiter`: `FUTEX_WAIT_REQUEUE_PI(f1, 0, f2)` — waits on `f1`, target `f2`.
  Its `rt_mutex_waiter` lives on `T_waiter`'s stack (in `futex_wait_requeue_pi`, inlined into `futex_wait`).
- `T_requeuer`: `FUTEX_CMP_REQUEUE_PI(f2, f3, val)`, where `val == *f2` so that
  the requeue succeeds and builds the chain `waiter → f2-owner → ...`.
- Cycle closure (e.g. `T_owner2` has a PI wait on a futex owned by `T_requeuer`)
  → `rt_mutex_start_proxy_lock` returns `-EDEADLK` → rollback → **UAF**.

### 4.2 Reclaiming the freed stack frame

The stack is `VMAP_STACK` (16 KB, 4K pages). Techniques (simplest first):

1. **`writev` with 8 iovecs** — `iovstack[8]` (`struct iovec`, 16 B each) lands on
   the stack and fills the area overlapping the "ghost" `rt_mutex_waiter`
   with controlled bytes (as in the armv7 PoC). The frame shift must be matched
   to the 5.15/16 KB layout.
2. **`pselect()`/`ppoll()`** — copies a controlled `fd_set`/`pollfd` onto the stack
   (as public arm64 ports do — "pselect + sched_setattr").
3. **`prctl(PR_SET_NAME)`** — 15 controlled bytes (to tune `prio`).
   The reclaim must hit _the same_ stack address as the freed waiter; with
   `RANDOMIZE_KSTACK_OFFSET_DEFAULT` off the frame offset is deterministic.

### 4.3 Write primitive

A forged `rt_mutex_waiter` (on the stack) is inserted into the `pi_waiters` tree of a
crafted `rt_mutex`. `rb_insert_color()` / `rb_erase()` perform
`parent->rb_left = node` or `parent->rb_right = node` — a write of the **node address
(stack, controlled)** to an **address chosen** by the attacker (by crafting `parent`).
That yields a "constrained pointer write" whose value and target are attacker-controlled
(publicised by NebuSec).

**Update:** the actual store in A.127 was later localised to `task_blocks_on_rt_mutex`
(inlined `rb_link_node`) and `rt_mutex_adjust_prio_chain`, and shown to be
**write-if-zero**; see `FINAL_REPORT.md` sections 2.2-2.3 and 10.

### 4.4 Leak (KASLR + physmap)

Write-up: prefetch side-channel (`prfm` + timing) to determine the
`kernel image slide` and `physmap base`. Without it the §2 offsets are useless
(KASLR). Public arm64 ports use the ARM64 direct map (physmap) to write directly into
the physical pages of their targets.

### 4.5 Data-only final stage (on W3)

Because the stack is NX and CFI/PAC block PC hijack, the final stage must be purely
data. Two routes:

**A. Swap the `task->cred` pointer (cleanest).**
Write the address `current + 0x800` (`task_struct.cred`) = the address of a forged `cred`
crafted in the spray (on the stack/physmap), with `uid..fsgid = 0`,
`caps = 0xffffffffffffffff`, `user_ns = &init_user_ns`. After return `getuid()==0`.
Requires: a leak of `current` (task_struct) and the address of the forged cred.

**B. Direct write into `cred` through the physmap.**
With physmap-base + the physical address of `cred`, overwrite `uid..fsgid` and the CAP bits
directly in the physmap alias (as arm64 ports describe). Requires a leak of the physical
address of `cred`.

> `core_pattern`/DirtyMode and `modprobe_path` are ruled out: `STATIC_USERMODEHELPER=y`.

---

## 5. Code

- `offsets_w3.h` — all offsets/addresses.
- `ghostlock_w3.c` — skeleton: aarch64 syscalls, PI trigger, spray hooks,
  leak and final-stage stubs.

---

## 6. Obstacles and workarounds (arm64 / this binary)

| Defence                 | Impact                        | Workaround                                   |
| ----------------------- | ----------------------------- | -------------------------------------------- |
| KASLR                   | runtime-independent offset    | prefetch leak                                |
| PAC                     | you cannot forge LR/PC        | data-only attack                             |
| kCFI                    | indirect call checks the type | do not hijack function pointers; target data |
| PAN                     | no kernel write to user       | write into kernel objects / physmap          |
| **KASAN+MTE**           | ⚠ may catch the stack UAF     | **see below**                                |
| STATIC_USERMODEHELPER   | no `core_pattern`             | final stage A/B (cred)                       |
| HARDENED_USERCOPY       | limits spray via usercopy     | spray through other syscalls                 |
| RANDOMIZE_KSTACK_OFFSET | —                             | ✅ disabled → deterministic stack            |

**⚠ KASAN/MTE.** `CONFIG_KASAN=y` + `KASAN_HW_TAGS` + `ARM64_MTE=y` is
unusual for production Wear OS — it looks like a debug build. Practical note:
MTE requires ARMv8.5 in hardware; Snapdragon W5 (Cortex-A) may not have it, so
`KASAN_HW_TAGS` does not activate at runtime. **Verify on the device:**

```
adb shell zcat /proc/config.gz | grep -E "KASAN|MTE"
adb shell dmesg | grep -iE "KASAN|MTE"
```

If KASAN really works — the UAF will be caught and another path is needed.

**Verified:** W5 has no hardware MTE (`/proc/cpuinfo` lacks `mte`), and the UAF is
silent. `mte=0` must be passed to KernelSnitch/google-poc.

---

## 7. What remains open (honestly)

1. **VMAP 16 KB stack reclaim** — the exact frame shift for 5.15.170 must be
   measured on the device (iteratively, as in armv7 ports: 22 layouts).
2. **KASLR/physmap leak** — the prefetch needs calibration for W5.
3. **Final stage A vs B** — choice and stability on the device.
4. **KASAN/MTE** — see §6.
5. This is NOT a finished, tested exploit; it is a complete design + skeleton.

---

## 8. Build / test

```
NDK=/opt/android-sdk/ndk/28.2.13676358
CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang
$CC -O2 -static -pie -fPIE -o ghostlock64 ghostlock_w3.c -lpthread
adb push ghostlock64 /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/ghostlock64
adb shell /data/local/tmp/ghostlock64 ; adb shell id
```

**Note:** Watch 2 (tester) = kernel `5.15.185`, different offsets
(`cred=0x810`, `pi_lock=0x910`, `pi_blocked_on=0x950`, `task=0x1380`;
`commit_creds=0xffffffc0081a0fcc`, `prepare_kernel_cred=0xffffffc0081a045c`).
Build a separate binary for W2 or test on W3.
