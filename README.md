# wristlock

Kernel exploitation research on the **OnePlus Watch 3 (OPWWE251, Snapdragon W5+)**
with a single goal: **tethered root** (uid 0 that disappears on reboot) from
userspace, **without unlocking the bootloader**.

> **Outcome: root was NOT achieved.** This repository is a complete, honest record
> of what works, what does not, and precisely which barrier stopped each path.
> Negative results here are the deliverable.

## Why "wristlock"

`wrist` (the form factor) + `lock` (the target subsystem — `rt_mutex` / futex PI).
It also reads as "wrist + lock", which is what the whole project is about: a
kernel lock bug on a watch.

## Two vulnerabilities, both closed

| Vulnerability                                                | Status                             | Why it stopped                                                                             |
| ------------------------------------------------------------ | ---------------------------------- | ------------------------------------------------------------------------------------------ |
| **DirtyFrag** (CVE-2026-43284) — xfrm-ESP page-cache write   | ✅ primitive works on-device       | init code-exec reached, but `exec`, kernel modules, `enforce=0` and setuid are all blocked |
| **GhostLock** (CVE-2026-43499) — `remove_waiter()` stack UAF | ✅ UAF + write primitive confirmed | the write is **write-if-zero**; no root-granting target exists on this kernel              |

## What was actually achieved on the live device

| Element                                                           | Result                                                         |
| ----------------------------------------------------------------- | -------------------------------------------------------------- |
| DirtyFrag page-cache write (unprivileged, `O_RDONLY` file)        | ✅ `RESULT=PAGECACHE_WRITE_OK`                                 |
| `~LogMessage` patch in `/system/lib/libbase.so` (offset `0xd554`) | ✅ stable, revert works                                        |
| Code execution inside `init` (pid 1, uid 0)                       | ✅ payload runs, sockets, `accept()` returns                   |
| KASLR leak (`_text`) via perf + callchain                         | ✅ `el0t_64_sync+0x1b4`                                        |
| Heap leak (`mm_struct`) via KernelSnitch (`mte=0`)                | ✅ `ffffff8008bd7400`                                          |
| Controlled order-3 page (google-poc, `mte=0`)                     | ✅ `ffffff8044de8000`                                          |
| GhostLock trigger (`-EDEADLK`) + controllable UAF                 | ✅ reclaim hits at `pad=3`                                     |
| Write primitive                                                   | ✅ confirmed by disasm — but **conditional on `*(target)==0`** |

## The key finding

The `rt_mutex` write primitive in this kernel is **not arbitrary**:

```asm
; task_blocks_on_rt_mutex / rt_mutex_adjust_prio_chain, A.127
8b34: ldr  x11, [x10]      ; parent->rb_right
8b38: cbnz x11, +0x910     ; non-NULL -> keep descending (deref!)
8b48: str  x0,  [x10]      ; store ONLY when the slot is NULL
```

So it is `*(target) = controlled_pointer` **only when `*(target) == 0`**.
That rules out `selinux_state` (`enforcing == 1`), `current->cred`
(non-NULL pointer), `modprobe_path`, `core_pattern`, and every other useful target.
The targets that _are_ zero (`.bss`, empty lists) give no root, and hook-list
injection is blocked by kCFI.

Full analysis: [`FINAL_REPORT.md`](FINAL_REPORT.md).

## CVE sweep (all rejected)

Checked against the device config and patch level (2026-08-01):

| CVE                                    | Rejection reason                    |
| -------------------------------------- | ----------------------------------- |
| CVE-2026-31431 (Copy Fail)             | `CRYPTO_USER_API_AEAD=n`            |
| CVE-2026-43494 (PinTheft)              | `RDS=n`                             |
| CVE-2026-43500 (RxRPC)                 | `AF_RXRPC=n`                        |
| CVE-2025-39964 (crypto-socket)         | `CRYPTO_USER=n`                     |
| CVE-2025-39682 (kernel TLS)            | `TLS=n`                             |
| CVE-2026-53266 (ebtables)              | `EBTABLES` absent                   |
| CVE-2026-46242 (Bad Epoll)             | introduced in 6.4                   |
| CVE-2026-64262 (fuse-uring)            | 6.14+                               |
| CVE-2026-89791 (perf UAF)              | introduced in 6.18                  |
| CVE-2024-23380 / CVE-2026-21385 (KGSL) | fixed before the device patch level |

`/dev/kgsl-3d0` remains open to `shell`, but every public KGSL CVE is patched;
anything newer has no public detail or PoC.

## Unresolved: version contradiction

`uname` says **5.15.185 (A.165)**, but perf on the live device matches the
**A.127 (5.15.170)** ELF byte-for-byte (`do_futex`, `futex_wait`,
`futex_wait_queue_me`, `fixup_pi_state_owner`), and the device config is
identical to A.127's except for two options that do not affect code.
A.127 was adopted as the device binary. **No A.165 OTA was available**, so this
is an assumption, not proof.

## Repository layout

| Path                                                                            | Purpose                                                     |
| ------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `FINAL_REPORT.md`                                                               | **start here** — full findings, barriers, CVE sweep         |
| `DESIGN_ghostlock_w3.md`                                                        | original port design                                        |
| `STATUS.md`, `WRITEUP.md`                                                       | intermediate snapshots (dated)                              |
| `offsets_w3.h`                                                                  | A.127 offsets with per-symbol confidence                    |
| `offsets_w3_5.15.185.h.bak`                                                     | previous offset set (superseded)                            |
| `kaaslr.c/.h`                                                                   | `_text` leak via perf                                       |
| `trigger_edeadlk.c`                                                             | GhostLock trigger (`-EDEADLK`)                              |
| `reclaim_harness.c`                                                             | stack reclaim + forged waiter (`pad=3`)                     |
| `futex_perf.c`, `futex_pi_*.c`, `pi4..8.c`, `piB.c`, `piC.c`, `rbvma.c`         | perf validation harnesses                                   |
| `rt_verify.c`, `futex_check.c`, `ks_probe.c`, `leak_regs.c`, `verify_offsets.c` | diagnostics                                                 |
| `phase1.c`                                                                      | write-primitive attempt (documents the write-if-zero limit) |
| `recon.sh`                                                                      | device recon                                                |

## Building

```bash
NDK=/opt/android-sdk/ndk/28.2.13676358
CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang

$CC -O2 -static -pie -fPIE -o ghostlock64 ghostlock_w3.c kaaslr.c
$CC -O1 -static -pie -fPIE -pthread -o trigger_edeadlk trigger_edeadlk.c kaaslr.c
$CC -O1 -static -pie -fPIE -pthread -o reclaim_harness reclaim_harness.c kaaslr.c
```

## Third-party tools (not vendored)

The heap leak and cross-cache work rely on **KernelSnitch**:

```bash
git clone https://github.com/lukasmaar/kernelsnitch
make -C kernelsnitch/exploits arm \
  CC_ARM=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang \
  LDLIBS_COMMON=
adb push kernelsnitch/exploits/kernelsnitch.arm.elf /data/local/tmp/
adb shell '/data/local/tmp/kernelsnitch.arm.elf 1024 3 1 4 16 0'   # mte must be 0
```

`mte=0` is mandatory on W5 — it has no hardware MTE, and `mte=1` makes the
cross-cache step fail.

## Safety

Everything in this research lives in RAM. A reset (both buttons for ~15 s)
restores stock; `/system` is read-only with dm-verity, so nothing is written to
disk. **Do not** read `/dev/block/*` from init — that wedges storage and
softlocks the watch (it happened twice here).

## Credits

- GhostLock trigger adapted from **MobiusM/CVE-2026-43499**.
- Heap leak: **lukasmaar/kernelsnitch**, **isec-tugraz/KernelSnitch**.
- Technique lineage: **NebuSec/CyberMeowfia**, arm64 ports
  `pubglite55/oppo-ghostlock`, `x-spy/CVE-2026-43499-popsicle`.
- DirtyFrag: **V4bel/dirtyfrag**, **diabl0w/DFRoot**, **combeng6th/DirtyInit**.

## License

MIT — see [LICENSE](LICENSE).
