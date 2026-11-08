# FINAL REPORT — GhostLock / DirtyFrag on OnePlus Watch 3 (OPWWE251)

Date: 2026-11-08. Goal: **TETHERED root (uid 0)** — must disappear after reboot. No bootloader unlock.
Result: **root NOT achieved.** Below is exactly what works, what does not, and why.

---

## 0. Device state (at end of work)

|           |                                                                   |
| --------- | ----------------------------------------------------------------- |
| Model     | OnePlus Watch 3, OPWWE251 (Snapdragon W5+, monaco)                |
| Build     | A.165.260910, patch 2026-08-01                                    |
| `uname`   | 5.15.185-android14-11-maybe-dirty                                 |
| Userspace | 32-bit (`ro.zygote=zygote32`), 64-bit kernel (aarch64 exec works) |
| SELinux   | Enforcing                                                         |
| State     | clean, boot_completed=1, zero persistent changes                  |

**Non-persistence is the target property (tethered), not a defect.** Everything lives in RAM; a reset (both buttons, 15 s) restores stock — this is expected behaviour, not failure.

---

## 1. DirtyFrag (CVE-2026-43284) — CLOSED

### What worked (confirmed on the live device)

- `IpSecManager` via `app_process` as `shell` (uid 2000): SPI + UDP-encap + AES-256-CBC/HMAC-SHA256 transform. No USER_NS, no caps.
- **Page-cache write**: `RESULT=PAGECACHE_WRITE_OK`, file opened `O_RDONLY`, 16/16 B, whole blobs 262/464 B.
- Patch of `/system/lib/libbase.so` @ file-offset **0xd554** (`~LogMessage`, Thumb, 512 B) — stable, revert works.
- **Code-exec in init (pid 1, uid 0)**: Thumb payload runs, creates sockets, `accept()` returns.
- init→shell channel worked (received `OK15`).

### Why it is closed

| Barrier                    | Evidence                                                          |
| -------------------------- | ----------------------------------------------------------------- |
| `exec` from init           | `avc: denied { execute_no_trans } scontext=u:r:init:s0`           |
| Kernel modules             | even a **no-op unsigned module** → panic (`MODULE_SIG_PROTECT`)   |
| `enforce=0` from init      | reboot (platform restores enforcing)                              |
| setuid/file-caps           | all writable filesystems are `nosuid`                             |
| `~LogMessage` under a lock | a payload doing `open()`/`bind()` deadlocks init → watchdog       |
| Payload size limit         | **≤ 512 B** (`~LogMessage` size); larger ones overwrite `LogLine` |

**Conclusion: init-root is a dead end.**

---

## 2. GhostLock (CVE-2026-43499) — foundations OK, final stage blocked

### 2.1 What is CONFIRMED on the live device

| Element                 | Method                             | Result                             |
| ----------------------- | ---------------------------------- | ---------------------------------- |
| KASLR leak `_text`      | perf + callchain                   | ✅ `el0t_64_sync+0x1b4`, 11k+ hits |
| Heap leak `mm_struct`   | KernelSnitch (aarch64, **mte=0**)  | ✅ `ffffff8008bd7400`              |
| Controlled order-3 page | google-poc (**mte=0**)             | ✅ `ffffff8044de8000`              |
| Pipe round-trip         | `F_SETPIPE_SZ` + write/read        | ✅ 64/64, `PIPE_ROUNDTRIP_OK`      |
| Controllable UAF        | reclaim `writev` iovstack, `pad=3` | ✅ (from earlier sessions)         |

### 2.2 Write primitive — CONFIRMED BY DISASM (A.127)

In `task_blocks_on_rt_mutex` (inlined `rb_link_node`), **empty-tree** path:

```asm
4f751c: stp  xzr, xzr, [x21, #0x8]   ; waiter->rb_right=0, rb_left=0
4f7520: str  xzr, [x21]              ; waiter->__rb_parent_color=0
4f7524: str  x21, [x1]               ; *(lock+0x8) = waiter_addr
4f7528: str  x21, [x19, #0x10]       ; *(lock+0x10) = waiter_addr
4f7530: bl   rb_insert_color         ; fast-path root: str 1,[waiter]; ret
4f7534: str  x21, [x20, #0x918]      ; task->pi_blocked_on = waiter
```

where `x21 = waiter` (base, never modified), `x19 = lock`, `x1 = lock+8`.

### 2.3 Why this does NOT give arbitrary write (key finding)

**Precondition for the empty branch:** `*(lock+8) == 0`.

But **before** that store the kernel reads from the forged lock:

- `ldr x8,[x1]` — `lock+8` (must be 0),
- `ldr x27,[x19,#0x10]` — `lock+0x10` (owner; only when `lock+8 != 0`),
- in `rt_mutex_adjust_prio_chain`: **`ldr x28,[x19,#0x918]`** + `cbz` — requires a sane value.

**Conclusion:** `lock` **must** be in controlled memory (or be a real `rt_mutex`), because the kernel dereferences `lock+0x918` and `lock+0x10`. With a forged lock pointing into `.data` (e.g. `netdev_rss_key-8`) → **garbage deref → panic**.

Additionally: on the `FUTEX_LOCK_PI` path (`rt_mutex_slowlock`) the `lock` comes **from the futex** (real), and `waiter->lock` is **overwritten** by the kernel (`stp x20,x19,[x21,#0x30]`) — so the forged lock is not used there at all.

**Effect: the store is limited to `lock+8`, where `lock` lies in our controlled page.** That is a mechanism canary, not a path to `current->cred`.

### 2.4 What is missing for root

1. **Read primitive** — without reading kernel memory we can neither verify anything nor find `current`.
2. **`current` address** — without it there is nowhere to write `cred` (`current+0x800`).
3. **Arbitrary write** — the current primitive is too narrow.

**Read via `pipe_buffer`** (corrupting `len`/`page`) requires controlled-write **first**, and that one is narrow → **chicken-and-egg**.
The **`pipe_buffer` address** is **unverified**: in `google-poc.c` without the LKM `pipe_buffer_base` is actually `mm_struct_base` (misleading label); the real verification (`pipe_buffer_leak`) exists only inside the `#ifndef ANDROID_APP_NO_LKM` block.

---

## 3. Version contradiction (UNRESOLVED)

- `uname` / fingerprint: **5.15.185**, A.165.260910.
- **Perf on the live device matches the A.127 ELF (5.15.170) byte-for-byte**:
  `do_futex` @ 0x277038, `futex_wait+0x38/+0x1a8`, `futex_wait_queue_me+0x224`,
  `fixup_pi_state_owner+0x300`, `el0t_64_sync+0x1b4` — 48k+ hits.
- Device config == A.127 config (identical except `CONFIG_MEMFD_ASHMEM_SHIM` and `CONFIG_PAGE_BLOCK_ORDER`, neither affects code).
- **A.127 was adopted as the device binary** (`offsets_w3.h`); `uname` = metadata.
- **No A.165 OTA locally** → no independent confirmation.

**This is an assumption, not proof.** Without the A.165 OTA it cannot be closed.

---

## 4. Offsets (A.127, `_text = 0xffffffc008000000`)

File: `offsets_w3.h`. Backup of the old set: `offsets_w3_5.15.185.h.bak`.

| symbol                       | offset      | status                    |
| ---------------------------- | ----------- | ------------------------- |
| `el0t_64_sync`               | `0x11470`   | ✅ PROVEN perf            |
| `do_futex`                   | `0x277038`  | ✅ PROVEN perf            |
| `futex_wait`                 | `0x278f28`  | ✅ PROVEN perf            |
| `futex_requeue`              | `0x2794c0`  | ✅ PROVEN perf            |
| `futex_lock_pi`              | `0x27a8fc`  | ✅ PROVEN perf            |
| `__arm64_sys_futex`          | `0x27d504`  | ✅ PROVEN perf            |
| `commit_creds`               | `0x177fd4`  | 🟡 logical (before futex) |
| `prepare_kernel_cred`        | `0x178710`  | 🟡 logical                |
| `override_creds`             | `0x17849c`  | 🟡 logical                |
| `rb_insert_color`            | `0x9f153c`  | ⚠️ ASSUMED (0 perf hits)  |
| `rb_erase`                   | `0x9f16ac`  | ⚠️ ASSUMED                |
| `remove_waiter`              | `0x14f7d0c` | ⚠️ ASSUMED                |
| `rt_mutex_adjust_prio_chain` | `0x14f81f4` | ⚠️ ASSUMED                |
| `init_cred`                  | `0x284e5e8` | ⚠️ ASSUMED (data)         |
| `init_task`                  | `0x288c3c0` | ⚠️ ASSUMED                |
| `init_user_ns`               | `0x2903dd0` | ⚠️ ASSUMED                |
| `linux_banner`               | `0x1b18f98` | ⚠️ ASSUMED                |
| `core_pattern`               | `0x2825de0` | ⚠️ ASSUMED                |
| `mmap_min_addr`              | `0x2a06b20` | ⚠️ ASSUMED                |

**Structures** (production, `DEBUG_SPINLOCK=n`): `cred=0x800`, `pi_lock=0x8EC`,
`pi_blocked_on=0x918`, `sizeof(task_struct)=0x1280`, `sizeof(cred)=0xB0`,
`sizeof(rt_mutex_waiter)=0x58`.

---

## 5. Environmental barriers (measured)

| Barrier                             | Consequence                                                                                     |
| ----------------------------------- | ----------------------------------------------------------------------------------------------- |
| `/proc/kallsyms`                    | `avc: denied read scontext=u:r:init:s0` — no device symbols                                     |
| `/proc/kcore`                       | `# CONFIG_PROC_KCORE is not set` — the file does not exist                                      |
| `/proc/sys/*` for `shell`           | almost everything `Permission denied` (only `pid_max`, `random/boot_id`, `net/core/*` readable) |
| `CONFIG_USER_NS`                    | `not set` → no userns/caps                                                                      |
| `CONFIG_PANIC_ON_OOPS=y`            | every oops = immediate reboot                                                                   |
| `CONFIG_MODULE_SIG_PROTECT=y`       | unsigned module → panic                                                                         |
| `nosuid` on `/data`, `/dev`, `/mnt` | setuid/file-caps ruled out                                                                      |
| `netdev_rss_key`                    | zero, but **lazy-init** (`net_get_random_once`) → race with RX                                  |
| `pid_max`                           | 4 B, non-zero (32768) → empty branch will not trigger                                           |

---

## 6. Pitfalls we hit (for successors)

1. **`atoi("0xd554")` = 0** — hex parser; the first patch therefore went to offset 0 and killed libbase (recovery via `LD_LIBRARY_PATH` + reboot).
2. **VADDR ≠ file-offset** — in the A.127 ELF `.kernel` has VMA `0xffffffc008000000` at file-offset `0x1c0`; for `libbase.so` the text-LOAD delta is `0x1000`.
3. **Payload > 512 B** overwrites `LogLine` → chaos.
4. **`~LogMessage` is sometimes called under a lock** — doing work inside the payload deadlocks init.
5. **Hijacking libbase blocks `app_process`** — a second deploy requires a reboot.
6. **`mte=1` breaks cross-cache** on W5 (no hardware MTE) — use `mte=0`.
7. **`perf pid=0` samples only the main thread** — work in other threads is invisible.
8. **`google-poc` without the LKM does not verify cross-cache** — `pipe_buffer_base` is `mm_struct_base`.
9. **`rb_insert_color` is a 6-instruction fast path** — practically uncatchable by sampling.
10. **Reading `/dev/block/*` from init wedges storage** → softlock (2×). Do not do it.

---

## 7. Files

| File                                                                       | Role                                                        |
| -------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `offsets_w3.h`                                                             | A.127 offsets (with status notes)                           |
| `offsets_w3_5.15.185.h.bak`                                                | previous set (5.15.185 rebuild)                             |
| `kaaslr.c/.h`                                                              | `_text` leak via perf                                       |
| `trigger_edeadlk.c`                                                        | trigger → `-EDEADLK`                                        |
| `reclaim_harness.c`                                                        | reclaim + forged waiter (pad=3)                             |
| `futex_perf.c`, `futex_pi_perf*.c`, `piB.c`, `piC.c`, `rbvma.c`, `pi4-8.c` | perf validation (results: futex PROVEN, rb/rtmutex ASSUMED) |
| `rt_verify.c`                                                              | pipe round-trip                                             |
| `vendor/kernelsnitch/`                                                     | KernelSnitch + google-poc (aarch64, `mte=0`)                |
| `vendor/kernelsnitch/exploits/google-poc-canary.c`                         | canary (stop at sk_buff frag, MSG_PEEK)                     |

---

## 8. Recommendations

**To continue GhostLock:**

1. Obtain the **A.165 OTA** → `vmlinux-to-elf` → close the offsets and the version contradiction.
2. Build a **read primitive** independent of controlled-write (otherwise chicken-and-egg).
3. Find **`current`** (e.g. via `init_task.tasks` once read works).
4. Only then `current->cred`.

**Alternatives:**

- Another LPE in this kernel giving full arbitrary R/W.
- **DirtyFrag + root file-service in init** (section 9) — the most promising path to _tethered_ root.

**Note:** Magisk / bootloader unlock is **not** an alternative for the tethered goal — Magisk gives **persistent** root. Here the goal is the opposite: root must **disappear** after reboot.

**What NOT to do:** `/dev/block/*` from init, kernel modules, `enforce=0`, `/proc/kcore`.

---

## 9. The TETHERED root path that was opened (and not used)

This is the most important section for the "root must disappear after reboot" goal.

### 9.1 Why this is the right path for tethered

Everything we do lives **only in the page cache (RAM)**:

- `/system` is `ro` + **dm-verity** → the kernel **will not write** a modified page to disk,
- reboot = page cache vanishes = init loads the original from the partition,
- **root disappears automatically after reboot — exactly as intended.**

This is not a limitation. It is **precisely the definition of a tethered jailbreak**. Nothing needs to be "cleaned up" — reboot is the return-to-stock mechanism.

### 9.2 What we have and what is missing

**We have (confirmed):**

- page-cache write (DirtyFrag),
- patch of `~LogMessage` in `/system/lib/libbase.so` @ `0xd554`,
- **code-exec in init as uid 0** (Thumb payload ≤ 512 B, `getpid()==1`),
- a working init→shell channel (received `OK15`),
- `accept()` in the init child works.

**Blocking (each measured):**

| Barrier                             | Fact                               |
| ----------------------------------- | ---------------------------------- |
| `exec` from init                    | `avc: denied { execute_no_trans }` |
| writing to a unix socket from init  | does not arrive (peer label)       |
| `enforce=0` from init               | reboot                             |
| FS socket `/dev/socket/*` from init | reboot                             |
| work in `~LogMessage` under a lock  | deadlock → watchdog                |

### 9.3 The unused path: root file-service WITHOUT exec

Key observation: **we have code-exec in init (uid 0) and `accept()` works.** We do not need `exec` to have root — we need **init to perform privileged operations on request**.

**Design:**

1. The payload in init (outside the lock — in the fork child, which is stable) opens a **channel** (`accept` is proven to work).
2. Instead of sending data, the child **reads commands** and executes **syscalls as uid 0**: `open/read/write/rename/chmod/chown/unlink`.
3. The shell sends commands and receives results.

**Why this could work even though the relay did not:** the problem was **writing from init to the socket** (peer label). But **reading** (init reads a command) and **file operations** (init opens files as uid 0) are different permissions. To be verified: whether init can `read()` from an accepted socket.

**What this gives in practice (tethered root):**

- reading root files (`/data/system/*`, `/data/misc/*`),
- writing files that `shell` cannot touch,
- the ability to install a daemon that starts as root in this session,
- **everything disappears after reboot.**

**What it does not give:** a true `uid 0` shell (the `init` SELinux domain cannot be "dropped" to `shell`). It is **functional root** (access to root's resources), not `id -u == 0`.

### 9.4 What to check first (safe, no risk)

1. Whether the init child can **`read()`** from an accepted socket (if yes — the channel is bidirectional toward init).
2. Whether init can **`open()`** files in `/data/system` (test: `open` + `read` + marker-socket with the result, as in `payload13b`).
3. Whether init can **`write()`** to files in `/data` (test as above).

All three tests are **read-only or write to a test file** — zero risk to the system. If any passes, we have a working root file-service.

### 9.5 Risk

- Any new payload in init **may** restart the watch (as before) — but **not permanently**.
- The 512 B payload limit forces simplicity (or a trampoline into a larger `.text` region).
- **Zero risk of permanent damage** — everything in RAM.

---

## 10. BREAKTHROUGH: a real arbitrary write in `rt_mutex_adjust_prio_chain`

Date: 2026-11-08 (second session). Discovered by analysing the A.127 disasm.

### 10.1 Chain (complete, verified by disasm)

```
sched_setattr()                         [userspace, uid 2000]
  -> rt_mutex_adjust_pi(task=current)   [0x94f9e70]
       ldr x8,[x19,#0x918]              ; task->pi_blocked_on  <- UAF dangling
       ldr x21,[x8,#0x38]               ; waiter->lock         <- FORGED
       bl  rt_mutex_adjust_prio_chain(x0=x21)
  -> rt_mutex_adjust_prio_chain(lock)   [0x94f81f4]
       82b8: ldr x28,[x19,#0x918]      ; lock->pi_blocked_on
       82e4: ldr x8,[x19,#0x900]       ; lock->pi_waiters.rb_root  (must be != 0)
       8bac: add x24,x19,#0x900        ; link = lock+0x900
       8c24: str x0,[x24]              ; *** *(lock+0x900) = &waiter->pi_tree_entry ***
```

### 10.2 Why this is ARBITRARY (and not limited to lock+8)

The previous primitive (`task_blocks_on_rt_mutex`) took `lock` from the futex
argument and required a readable `lock+0x918` -> limited to the controlled page.

Here `lock` comes from **`waiter->lock`, where the waiter is from the UAF** — i.e.
**fully controlled**. The stored value is `&waiter->pi_tree_entry`
(a controlled pointer) and the address is `lock+0x900` = **any** (since `lock` is any).

**=> `*(any_address) = controlled_pointer` (8 B).**

### 10.3 Entry conditions (all in the controlled page)

| Field                             | Offset | Required                            |
| --------------------------------- | ------ | ----------------------------------- |
| `lock+0x900` (pi_waiters.rb_root) | 0x900  | != 0 (pointer to a forged rb_node)  |
| `lock+0x918` (pi_blocked_on)      | 0x918  | != 0 (pointer to the forged waiter) |
| `waiter->lock`                    | 0x38   | == lock (self-ref)                  |
| `waiter->prio`                    | 0x44   | != task->prio (forces the branch)   |
| `waiter->task`                    | 0x30   | == task (for `cmp x24,x8`)          |

### 10.4 What is still missing for root

1. **`current` address** — unknown. Without it we do not know where `current+0x800` is.
2. **Read primitive** — `adjust_prio_chain` has `rb_next` (0x94f858c) on a forged
   tree; a read could potentially be built from it, but it needs analysis.

### 10.5 Status

- [x] GhostLock trigger (-EDEADLK)
- [x] Controllable UAF (reclaim pad=3)
- [x] Controlled page (order-3, mte=0)
- [x] **Arbitrary write (adjust_prio_chain, `*(lock+0x900)=&waiter->pi_tree_entry`)**
- [ ] Read primitive / `current` address
- [ ] `current->cred = &fake_cred`

### 10.6 CORRECTION (verified after the above)

The claim in 10.2 was **refined by further disasm analysis**: the write is
**conditional**. The rb-tree descent loop terminates only when the candidate
link slot is NULL:

```asm
8ae0: ldr x11,[lock+0x900]   ; parent
8aec: cbz x11, +0xa50        ; parent==0 -> empty branch (store at lock+0x900)
8b30: add x10,x9,#0x8        ; x10 = parent+8
8b34: ldr x11,[x10]          ; parent->rb_right
8b38: cbnz x11, +0x910       ; != 0 -> keep descending (deref!)
8b48: str x0,[x10]           ; store only here
```

Therefore the primitive is in fact **write-if-zero**:
`*(target) = controlled_pointer`, **only when `*(target) == 0`**.

This is still useful (empty `.bss` fields, empty lists) but **cannot target
`selinux_state`** (`enforcing` is 1) nor `current->cred` (non-NULL pointer).

### 10.7 Targets evaluated for write-if-zero (all rejected)

| Target                          | Zero?          | Usable?                          |
| ------------------------------- | -------------- | -------------------------------- |
| `selinux_state+0` (`enforcing`) | ❌ =1          | —                                |
| `selinux_state+0x28` (`avc`)    | ❌ set at init | —                                |
| `security_hook_heads`           | ✅ NULL        | ❌ CFI blocks a fake hook        |
| `cred_jar`                      | ❌ set at init | —                                |
| `.bss` (2282 symbols)           | ✅ mostly      | ❌ no root-granting target found |
| `init_cred`                     | ❌             | —                                |

**Conclusion: write-if-zero has no root-granting target on this kernel.**

---

## 11. Attack surface of `shell` (uid 2000) — measured

**Openable device nodes:** `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`,
`/dev/ptmx`, `/dev/kgsl-3d0` (GPU).

**Everything else denied by SELinux:** `/dev/ashmem`, `/dev/binder`, `/dev/fuse`,
`/dev/dma_heap/*`, `/dev/net/tun`, `/dev/vhost-net`, `/dev/uinput`.

**Removed from the kernel config (deliberate hardening):** `CRYPTO_USER`, `TLS`,
`RDS`, `AF_RXRPC`, `SYSVIPC`, `POSIX_MQUEUE`, `NF_TABLES`, `EBTABLES`, `N_GSM`,
`AF_KCM`, `WATCH_QUEUE`, `CONFIG_USER_NS`, unprivileged BPF, `CONFIG_DEVMEM`,
`CONFIG_PROC_KCORE`.

**CVE checked and rejected:**

| CVE                                 | Rejection reason                        |
| ----------------------------------- | --------------------------------------- |
| CVE-2026-31431 (Copy Fail)          | `CRYPTO_USER_API_AEAD=n`                |
| CVE-2026-43494 (PinTheft)           | `RDS=n`                                 |
| CVE-2026-43500 (RxRPC)              | `AF_RXRPC=n`                            |
| CVE-2025-39964 (crypto-socket)      | `CRYPTO_USER=n`                         |
| CVE-2025-39682 (kernel TLS)         | `TLS=n`                                 |
| CVE-2026-53266 (ebtables)           | `EBTABLES` absent                       |
| CVE-2026-46242 (Bad Epoll)          | introduced in **6.4**                   |
| CVE-2026-64262 (fuse-uring)         | **6.14+**                               |
| CVE-2026-89791 (perf UAF)           | introduced in **6.18** (`perf_mmap_rb`) |
| CVE-2024-23380 (KGSL)               | fixed 2024-07 (device patch 2026-08)    |
| CVE-2026-21385 (Qualcomm GPU 0-day) | fixed 2026-03                           |

**KGSL remains the only unblocked surface**, but every public CVE for it is
already patched; anything newer (e.g. the 2026-09 Qualcomm set) has no public
detail or PoC and would require original fuzzing research.
