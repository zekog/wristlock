# WRITEUP — GhostLock (CVE-2026-43499) on OnePlus Watch 3 (OPWWE251)

Goal: root (UID 0) from userspace, **without a bootloader unlock**. Research, 2026-11-06/07.

> Status: **pipeline built up to a controllable UAF + heap leak.** The final stage (READ -> `current` -> `cred`)
> is incomplete — we hit hard environmental barriers (SELinux, CFI/PAC/PAN).
>
> **Note:** this file records the state as of 2026-11-07. Later findings (arbitrary-write
> analysis, the write-if-zero limitation, the CVE sweep, KGSL) are in `FINAL_REPORT.md`.

---

## 1. Goal

|               |                                                                        |
| ------------- | ---------------------------------------------------------------------- |
| Device        | OnePlus Watch 3 (OPWWE251), Snapdragon W5+ (monaco/SW5100)             |
| Kernel (live) | **5.15.185-android14-11-maybe-dirty** (A.165.260910, patch 2026-08-01) |
| Arch          | arm64 (32-bit userspace)                                               |
| SELinux       | Enforcing (`u:r:shell:s0`)                                             |
| Bootloader    | `ro.oem_unlock_supported=1` — **excluded from the task**               |

## 2. Vulnerability — VULNERABLE

`remove_waiter()` (kernel/locking/rtmutex.c) uses `current->pi_lock`/`current->pi_blocked_on`
instead of `waiter->task->...`. Unpatched in 5.15.185 (confirmed in source and disasm).
Upstream fix: `3bfdc63936dd` ("rtmutex: Use waiter::task instead of current in remove_waiter()").

## 3. Offsets (5.15.185)

The OTA dump (`~/Pobrane/opw3 firmware/`) = **A.127 / 5.15.170** — does NOT match the device!
Offsets from a **rebuild**: Watch2 source (5.15.185) + **exact device config** (`/proc/config.gz`)

- clang r487747c. File `offsets_w3.h`.

* Structures (~100%): `cred`=0x800, `pi_lock`=0x8EC, `pi_blocked_on`=0x918, `task_struct`=0x1280,
  `cred`=0xB0, `rt_mutex_waiter`=0x58.
* Functions (~95%): `commit_creds`, `init_cred`, `init_task`, `rb_*`, `remove_waiter`, etc.

## 4. KASLR leak `_text` — WORKS

`perf_event_open(HW_INSTRUCTIONS | PERF_SAMPLE_CALLCHAIN)`, `getpid()` loop. Deepest stack frame
= `el0t_64_sync` (offset < 0x12000 from `_text`), `_text = round_down(root, 2MB)` (mode).
Code: `kaaslr.{c,h}`. (Requires `perf_event_paranoid=-1` — present here.)

## 5. Trigger -> `-EDEADLK` — WORKS

`trigger_edeadlk.c` (adaptation of **MobiusM/CVE-2026-43499**, arm64): 3 futexes/3 threads -> PI cycle ->
`FUTEX_CMP_REQUEUE_PI` = **-EDEADLK** -> proxy rollback `remove_waiter()` on the wrong task ->
dangling `W->pi_blocked_on`.

## 6. Controllable UAF / reclaim — WORKS

`reclaim_harness.c`: W overwrites the freed `rt_waiter` slot with a crafted `rt_mutex_waiter`
(`writev(-1, iov, 8)` -> iovstack), then M walks the PI chain.
**`pad=3` = hit** (the chain walk read our bytes -> panic). We control the contents of the
crafted structure.

## 7. Heap leak (`mm_struct`) — WORKS

Public implementation **`github.com/lukasmaar/kernelsnitch`** (aarch64 Android):

```bash
git clone https://github.com/lukasmaar/kernelsnitch
make -C kernelsnitch/exploits arm CC_ARM=<ndk-clang>
adb push kernelsnitch/exploits/kernelsnitch.arm.elf /data/local/tmp/
adb shell '/data/local/tmp/kernelsnitch.arm.elf 1024 3 1 4 16 0'
```

Result: `[+] mm_struct 0xffffff80...` (stable, 4/4 runs). Config has no `CONFIG_FUTEX_PRIVATE_HASH`
-> the global hash with `mm_struct` works.

## 8. Cross-cache -> controlled page — PARTIAL

`google-poc.arm.elf` (KernelSnitch) from `shell`: cross-cache to a **`sk_buff->frag` page WORKED**
(we have a controlled data page at a known address; `leaked mm_struct 0xffffff8068072000`).
BUT the `pipe_buffer` (READ) stage fails: `fcntl(F_SETPIPE_SZ)` -> **EPERM** (SELinux/unprivileged).

**Update:** with `mte=0` the cross-cache and pipe resize both succeed; see `FINAL_REPORT.md` section 2.1.

## 9. Barriers (why the final stage is not complete)

| Barrier                    | Impact                                                                                    |
| -------------------------- | ----------------------------------------------------------------------------------------- |
| SELinux `shell`            | `/proc/<pid>/mem` (garbage-collect sk_buff pipeline…), `F_SETPIPE_SZ` EPERM               |
| `kptr_restrict`            | `/proc/kallsyms`, `kstkesp/kstkeip`, `/proc/iomem`, `/sys/module/*/sections/*` = 0/denied |
| CFI (kCFI)                 | blocks function-pointer hijack (e.g. `inet6_protos` as in the NebuSec original)           |
| PAC                        | you cannot forge a return address                                                         |
| PAN                        | the kernel does not write directly into user memory                                       |
| `STATIC_USERMODEHELPER`    | rules out `core_pattern`/`modprobe_path` (DirtyMode)                                      |
| No `task_struct`/`current` | without READ we cannot find our `task_struct` (mm_struct has no back-pointer)             |

## 10. Roadmap to root (what remains)

1. **READ primitive** — work around the `F_SETPIPE_SZ` EPERM (`untrusted_app`/APK variant) OR use the
   already obtained **controlled page** (sk_buff) as the crafted structure for the UAF.
2. **Find `current`** — with READ: walk `init_task.tasks` (address from KASLR).
3. **Overwrite `cred`** — data-only (NX stack, CFI/PAC/PAN): a crafted `cred` (uid 0, full caps,
   `user_ns=&init_user_ns`) and write its address into `task->cred` (offset 0x800).

## 11. Artifacts

| File                                               | Role                                           |
| -------------------------------------------------- | ---------------------------------------------- |
| `offsets_w3.h`                                     | 5.15.185 offsets                               |
| `kaaslr.{c,h}`                                     | `_text` leak (perf+callchain)                  |
| `ghostlock_w3.c`                                   | exploit skeleton (stage 0 = KASLR leak, ready) |
| `trigger_edeadlk.c`                                | trigger -> EDEADLK                             |
| `reclaim_harness.c`                                | reclaim + forged waiter + scan (pad=3 hit)     |
| `verify_offsets.c`, `leak_regs.c`                  | perf/leak tools                                |
| `ks_probe.c`                                       | KernelSnitch signal probe                      |
| `futex_check.c`, `recon.sh`                        | diagnostics                                    |
| `STATUS.md`, `DESIGN_ghostlock_w3.md`, `README.md` | documentation                                  |

## 12. Sources

- CVE: NVD / NebuSec `ionstack-part-2` / AlmaLinux advisory.
- Trigger: **MobiusM/CVE-2026-43499** (arm64).
- Heap leak: **lukasmaar/kernelsnitch** + **isec-tugraz/KernelSnitch** (NDSS 2025).
- arm64 ports: `pubglite55/oppo-ghostlock`, `x-spy/CVE-2026-43499-popsicle`.

## 13. Honest assessment

We built a **real pipeline**: confirmed vulnerability -> offsets -> KASLR leak -> EDEADLK trigger ->
controllable UAF -> heap leak. That is far more than reconnaissance. The final stage, however, is
**weeks of research** with environmental barriers; **guaranteed root is unlock+Magisk** (excluded by you).

**Update (see `FINAL_REPORT.md`):** the write primitive was analysed in depth and turned out to be
**write-if-zero**; no root-granting target exists on this kernel. Magisk is also **not** compatible
with the tethered goal, since it provides persistent root.
