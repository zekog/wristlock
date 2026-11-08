#!/system/bin/sh
# recon.sh — collect ground truth from the watch (safe, modifies nothing).
# Uruchom:  adb push recon.sh /data/local/tmp/ ; adb shell sh /data/local/tmp/recon.sh
echo "==================== IDENTITY ===================="
echo -n "ro.product.device   : "; getprop ro.product.device
echo -n "ro.product.model    : "; getprop ro.product.model
echo -n "ro.build.fingerprint: "; getprop ro.build.fingerprint
echo -n "ro.build.version.security_patch: "; getprop ro.build.version.security_patch
echo "==================== KERNEL ===================="
uname -a
cat /proc/version
echo "==================== USER / SELINUX ===================="
id
getenforce
echo "==================== MITIGATION SWITCHES ===================="
echo -n "kptr_restrict      : "; cat /proc/sys/kernel/kptr_restrict 2>/dev/null
echo -n "randomize_va_space : "; cat /proc/sys/kernel/randomize_va_space 2>/dev/null
echo -n "mmap_min_addr      : "; cat /proc/sys/vm/mmap_min_addr 2>/dev/null
echo -n "perf_event_paranoid: "; cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null
echo -n "dmesg_restrict     : "; cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
echo "==================== CONFIG (KASAN/MTE/CFI/PAC...) ===================="
if [ -r /proc/config.gz ]; then
  zcat /proc/config.gz | grep -E "KASAN|ARM64_MTE|FUTEX|RT_MUTEXES|CFI_CLANG|PTR_AUTH|ARM64_PAN|VMAP_STACK|RANDOMIZE_KSTACK|RANDOMIZE_BASE|STATIC_USERMODEHELPER|HARDENED_USERCOPY|SELINUX_DEVELOP"
else
  echo "(brak /proc/config.gz)"
fi
echo "==================== KALLSYMS (is there a real slide?) ===================="
head -3 /proc/kallsyms 2>/dev/null
grep -m1 " commit_creds" /proc/kallsyms 2>/dev/null
grep -m1 " remove_waiter" /proc/kallsyms 2>/dev/null
grep -m1 " init_cred"    /proc/kallsyms 2>/dev/null
echo "==================== DMESG (KASAN/MTE/versja) ===================="
dmesg 2>/dev/null | grep -iE "KASAN|MTE|Linux version|hardware tag|tag-based" | head -20
echo "==================== MODULES ===================="
head -20 /proc/modules 2>/dev/null
echo "==================== DONE ===================="
