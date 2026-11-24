#!/bin/sh
set -eu
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -print)
version=${kernel##*/vmlinuz-}
test -f "$kernel"
if gzip -t "$kernel" >/dev/null 2>&1; then gzip -dc "$kernel" >kernel.img; else cp "$kernel" kernel.img; fi
mkdir -p fs/bin fs/dev fs/proc fs/modules
cp "$(command -v busybox)" fs/bin/busybox
for name in loop dummy; do
    test -z "$(modinfo -k "$version" -F depends "$name")"
    printf 'packaged_module %s\n' "$name"
    module=$(modinfo -k "$version" -n "$name")
    case "$module" in
        *.xz) xz -dc "$module" >"fs/modules/$name.ko" ;;
        *.zst) zstd -q -dc "$module" >"fs/modules/$name.ko" ;;
        *.gz) gzip -dc "$module" >"fs/modules/$name.ko" ;;
        *) cp "$module" "fs/modules/$name.ko" ;;
    esac
done
cat >fs/init <<'INIT'
#!/bin/busybox sh
set -eu
b=/bin/busybox
$b mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
$b mount -t proc proc /proc
loaded() { $b grep -q "^$1 " /proc/modules; }
gate=/proc/sys/kernel/modules_disabled
test "$($b cat "$gate")" = 0
echo 'SAF-MODULE: boot-starts-unfrozen'
printf 'SAF-KERNEL: %s\n' "$($b uname -r)"
$b insmod /modules/loop.ko
loaded loop
echo 'SAF-MODULE: approved-boot-module-present'
if $b grep -q 'saf.freeze=1' /proc/cmdline; then
    echo 1 >"$gate"
    test "$($b cat "$gate")" = 1
    echo 'SAF-MODULE: observed-freeze'
    if $b insmod /modules/dummy.ko numdummies=0 2>/load-error; then exit 1; fi
    $b grep -q 'Operation not permitted' /load-error || { $b cat /load-error; exit 1; }
    ! loaded dummy
    echo 'SAF-MODULE: post-boot-load-denied'

    printf '0\n' >/lower-request
    if $b dd if=/lower-request of="$gate" conv=notrunc 2>/lower-error; then exit 1; fi
    test "$($b cat "$gate")" = 1
    echo 'SAF-MODULE: freeze-remains-after-lower-request'
else
    $b insmod /modules/dummy.ko numdummies=0
    loaded dummy
    echo 'SAF-MODULE: baseline-load-allowed'
fi
loaded loop
test -b /dev/loop0
$b truncate -s 4096 /fixture-owned.img
printf 'owned-boot-module-marker\n' | $b dd of=/fixture-owned.img conv=notrunc 2>/dev/null
$b losetup /dev/loop0 /fixture-owned.img
$b dd if=/dev/loop0 bs=25 count=1 2>/dev/null | $b grep -xq 'owned-boot-module-marker'
$b losetup -d /dev/loop0
echo 'SAF-MODULE: approved-loop-read-succeeded'
if test "$($b cat "$gate")" = 1; then
    if $b rmmod loop 2>/unload-error; then exit 1; fi
    $b grep -q 'Operation not permitted' /unload-error || { $b cat /unload-error; exit 1; }
    loaded loop
    echo 'SAF-MODULE: approved-unload-denied'
else
    $b rmmod loop
    ! loaded loop
    echo 'SAF-MODULE: baseline-unload-allowed'
fi
$b poweroff -f
INIT
chmod 0755 fs/init
(cd fs && find . -print0 | cpio --null -o --owner=0:0 -H newc 2>/dev/null | gzip -n) >fixture.cpio.gz
boot() {
    if ! timeout 30s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 256M \
      -nodefaults -display none -serial stdio -monitor none -nic none \
      -kernel kernel.img -initrd fixture.cpio.gz \
      -append "console=ttyAMA0 rdinit=/init panic=-1 loglevel=4 saf.freeze=$1" >"$2" 2>&1; then
        tail -28 "$2" >&2
        exit 1
    fi
}
require() { grep -Fq "$2" "$1" || { tail -28 "$1" >&2; exit 1; }; }
boot 0 baseline.log
require baseline.log 'SAF-MODULE: baseline-load-allowed'
require baseline.log 'SAF-MODULE: baseline-unload-allowed'
require baseline.log 'SAF-MODULE: approved-loop-read-succeeded'
boot 1 governed.log
boot 1 fresh-boot.log
for log in governed.log fresh-boot.log; do
    require "$log" 'SAF-MODULE: boot-starts-unfrozen'
    require "$log" 'SAF-MODULE: approved-boot-module-present'
    require "$log" 'SAF-MODULE: observed-freeze'
    require "$log" 'SAF-MODULE: post-boot-load-denied'
    require "$log" 'SAF-MODULE: freeze-remains-after-lower-request'
    require "$log" 'SAF-MODULE: approved-unload-denied'
    require "$log" 'SAF-MODULE: approved-loop-read-succeeded'
done
for log in baseline.log governed.log fresh-boot.log; do
    require "$log" "SAF-KERNEL: $version"
    sed -n '/^SAF-/p' "$log" | tr -d '\r' | sed "s/^/guest $log /"
done
