#!/bin/sh
set -eu
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -print)
version=${kernel##*/vmlinuz-}
test -f "$kernel"
grep -qx CONFIG_SECURITY_LOCKDOWN_LSM=y "/boot/config-$version"
if gzip -t "$kernel" >/dev/null 2>&1; then gzip -dc "$kernel" >kernel.img; else cp "$kernel" kernel.img; fi
mkdir -p fs/bin fs/dev fs/proc fs/sys
cp "$(command -v busybox)" fs/bin/busybox
cat >fs/init <<'INIT'
#!/bin/busybox sh
set -eu
b=/bin/busybox
$b mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
$b mount -t proc proc /proc
$b mount -t sysfs sysfs /sys
$b mount -t securityfs securityfs /sys/kernel/security
mode=$($b cat /sys/kernel/security/lockdown)
printf 'SAF-LOCKDOWN: %s\n' "$mode"
printf 'SAF-KERNEL: %s\n' "$($b uname -r)"
test -r /proc/uptime
echo 'SAF-LOCKDOWN: public-operational-read'
$b poweroff -f
INIT
chmod 0755 fs/init
(cd fs && find . -print0 | cpio --null -o --owner=0:0 -H newc 2>/dev/null | gzip -n) >fixture.cpio.gz
boot() {
    if ! timeout 30s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 256M \
      -nodefaults -display none -serial stdio -monitor none -nic none \
      -kernel kernel.img -initrd fixture.cpio.gz \
      -append "console=ttyAMA0 rdinit=/init panic=-1 loglevel=4 $1" >"$2" 2>&1; then
        tail -28 "$2" >&2
        exit 1
    fi
}
require() { grep -Fq "$2" "$1" || { tail -28 "$1" >&2; exit 1; }; }
boot '' baseline.log
require baseline.log 'SAF-LOCKDOWN: [none]'
echo baseline_reports_none
boot lockdown=integrity governed.log
require governed.log 'SAF-LOCKDOWN: none [integrity]'
echo configured_guest_reports_integrity
require baseline.log "SAF-KERNEL: $version"
require governed.log "SAF-KERNEL: $version"
require governed.log 'SAF-LOCKDOWN: public-operational-read'
echo same_kernel_retains_public_read
