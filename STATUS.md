# GhostLock (CVE-2026-43499) — work status on OnePlus Watch 3 (OPWWE251)

Date: 2026-11-06. Goal: root (UID 0) from userspace, without a bootloader unlock.

> **Note:** this file records the state as of 2026-11-06. Later findings
> (arbitrary-write analysis, write-if-zero limitation, CVE sweep, KGSL) are in
> `FINAL_REPORT.md`, which supersedes this document where they differ.

## 1. Goal and environment

|               |                                                                                                                                                                                                                                              |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Device        | OnePlus Watch 3 (OPWWE251), Snapdragon W5+ (monaco/SW5100)                                                                                                                                                                                   |
| Kernel (live) | **5.15.185-android14-11-maybe-dirty** (build A.165.260910, patch 2026-08-01)                                                                                                                                                                 |
| Config        | `CONFIG_FUTEX_PI=y`, `RT_MUTEXES=y`, `CFI_CLANG=y`, `PTR_AUTH(_KERNEL)=y`, `ARM64_PAN=y`, `VMAP_STACK=y`, `RANDOMIZE_BASE=y`, `KASAN=y`+`KASAN_HW_TAGS`(MTE, inactive on W5), `STATIC_USERMODEHELPER=y`, `# RANDOMIZE_KSTACK_OFFSET_DEFAULT` |
| SELinux       | Enforcing (blocks `/proc/iomem`, `/proc/kallsyms`, `/sys/module/*/sections/*`, dmesg)                                                                                                                                                        |
| Note          | `perf_event_paranoid = -1` -> unprivileged perf works (key to the leak)                                                                                                                                                                      |

The `opw3 firmware/` dump = **A.127 / 5.15.170** (not A.165!) — that is why offsets from the dump ELF do NOT match the device.

## 2. Vulnerability verdict: **VULNERABLE**

- `remove_waiter()` uses `current->pi_lock`/`current->pi_blocked_on` (not `waiter->task`) -> unpatched. Confirmed in the 5.15.185 source (Watch2 branch) and in disasm.
- `futex_check` on the device: `FUTEX_WAIT_REQUEUE_PI`/`FUTEX_CMP_REQUEUE_PI` work (not ENOSYS).

## 3. KASLR leak — **WORKS** (perf + callchain)

- Method: `perf_event_open(PERF_COUNT_HW_INSTRUCTIONS | PERF_SAMPLE_CALLCHAIN)`, `getpid` loop, deepest stack frame = `el0t_64_sync` (offset < 0x12000 from `_text`), `_text = round_down(root, 2MB)` (mode).
- Result for that boot: **`_text = 0xffffffeab7a00000`, slide = 0x2AAFA00000** (changes per boot).
- This **also confirms the rebuild offsets** in the entry region (`el0t_64_sync = 0x11470` hit).
- Code: `kaaslr.c`/`kaaslr.h`, wired into `ghostlock_w3.c` (stage 0).

## 4. Offsets (from the 5.15.185 rebuild + device config, clang r487747c)

**Structures — certain (~100%):** `cred`=0x800, `pi_lock`=0x8EC, `pi_blocked_on`=0x918, `sizeof(task_struct)`=0x1280, `sizeof(cred)`=0xB0, `sizeof(rt_mutex_waiter)`=0x58. (cred: uid=0x04 euid=0x14 cap_permitted=0x30 user_ns=0x88 security=0x78)
**Functions — high (~95%), entry region confirmed:** see `offsets_w3.h` (relative to `_text`).

## 5. Trigger — **-EDEADLK reached, but the UAF is silent**

`trigger_edeadlk.c` (MobiusM arm64 adaptation, 3 futexes/3 threads):

```
[M] FUTEX_CMP_REQUEUE_PI = -1 errno=35 (EDEADLK)   <- buggy proxy-rollback HAPPENED
[W] FUTEX_WAIT_REQUEUE_PI returned -1 errno=110 (ETIMEDOUT)
[M] UAF probe: FUTEX_LOCK_PI(cycle_futex)
[M] UAF probe returned (no panic)
```

- **✅ The `remove_waiter()` path on the proxy path is executed.**
- **No panic:** on 5.15.185 the freed stack page (VMAP_STACK) is **writable**, and KASAN/MTE are inactive -> the write to the freed frame succeeds (silent UAF). MobiusM's PoC panics only on kernels where the freed stack is read-only.
- This matches public watch ports (armv7 Huawei: "the second stage does not fault").

### 5a. RECLAIM — **WORKS (breakthrough)**

`reclaim_harness.c`: W overwrites the freed `rt_waiter` slot with a crafted
`rt_mutex_waiter` (`task=0x4141…`, `lock=0xdead…`) via `writev(-1, iov, 8)`
(iovstack), then M walks the PI chain.

```
=== pad=0/1/2 === probe returned (NO hit)
=== pad=3 === [M] UAF probe LOCK_PI(...)   <- here the WATCH RESTARTED
```

- **✅ pad=3 = HIT:** the PI chain walk read our controlled bytes and
  faulted on `waiter.task`/`waiter.lock` -> **the UAF is controllable**; the reclaim
  via `writev` iovstack covers the slot at shift `pad=3` (iovstack+0x30).
- This is the exploit's foundation: we control the contents of the forged waiter.

### 5b. HEAP LEAK — **WORKS (breakthrough)** [KernelSnitch]

On the device we ran `lukasmaar/kernelsnitch` (`kernelsnitch.arm.elf`, built with NDK clang,
`mm_struct_sz=1024`, `mm_slab_order=3`) -> **unprivileged `mm_struct` leak** (16 futex-hash
collisions -> offline `jhash2` brute force):

```
run1 mm_struct ffffff802fc48000
run2 mm_struct ffffff802fc49c00
run3 mm_struct ffffff8009bb1000
run4 mm_struct ffffff8009c9b800
```

- The config has **no `CONFIG_FUTEX_PRIVATE_HASH`** -> the global hash with `mm_struct` works.
- So we have: text KASLR (`_text`) **and** a heap pointer.

### 6. Where we are and what is next

- Instead of "poison" (`0xdead…`), put a **valid** `waiter.task`/`waiter.lock`
  (based on the heap leak) and craft `pi_tree_entry` so that
  `rt_mutex_enqueue_pi`/`rb_insert_color` perform a **controlled write**.
- Ultimately: **arbitrary R/W** (e.g. via cross-cache `pipe_buffer`/`msg_msg` as in
  `lukasmaar/kernelsnitch`) -> walk `init_task.tasks` (address from KASLR) to our
  `task_struct` -> overwrite `cred` (`init_cred`). `STATIC_USERMODEHELPER` rules out core_pattern.

## 6. Where we are and what is next

This is the **front** — where public arm64 ports (`pubglite55/oppo-ghostlock`) are blocked (CFI / write primitive). Further on-device iteration is required.

Next steps:

1. **Controlled reclaim** of the freed `W_rt_waiter` frame (writev iovstack / pselect fd_set) + a **crafted `rt_mutex_waiter`** such that the walk gives an **observable** effect (e.g. `waiter.lock = 0xdead…` -> fault -> panic = confirmation of UAF controllability). Offset scan.
2. Once the UAF is controllable -> **write primitive** (rb_insert/rb_erase writes the node address to a chosen address).
3. **Data-only final stage** (NX stack, CFI/PAC/PAN): swap `task->cred` for a forged cred / -> `init_cred`. `STATIC_USERMODEHELPER` rules out core_pattern.

## 7. Files

| File                        | Description                                        |
| --------------------------- | -------------------------------------------------- |
| `offsets_w3.h`              | all offsets (5.15.185)                             |
| `offsets` in `kaaslr.*`     | `_text` leak (perf+callchain)                      |
| `ghostlock_w3.c`            | skeleton: stage 0 (leak) ready; trigger/final TODO |
| `trigger_edeadlk.c`         | trigger reachability (proves -EDEADLK)             |
| `reclaim_harness.c`         | (experimental) reclaim + forged waiter + scan      |
| `verify_offsets.c`          | leak/KASLR tool (v5 callchain)                     |
| `futex_check.c`, `recon.sh` | diagnostics                                        |
| `DESIGN_ghostlock_w3.md`    | chain design                                       |

## 8. Risk / stability

- Panic -> reboot (reversible). Watchdog EDL after 2 failed boots, but **EDL exits by itself after ~10 s** -> also reversible.
- Run the trigger **manually, once** from `adb shell` (no autostart!) — otherwise a panic loop.
