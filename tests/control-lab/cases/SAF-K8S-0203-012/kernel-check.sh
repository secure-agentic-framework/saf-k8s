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
$b insmod /modules/loop.ko
loaded loop
echo 'SAF-MODULE: approved-boot-module-present'
if $b grep -q 'saf.freeze=1' /proc/cmdline; then
    echo 1 >"$gate"
    test "$($b cat "$gate")" = 1
    if $b insmod /modules/dummy.ko numdummies=0; then
        echo 'SAF-MODULE: unexpected-post-boot-load'
        $b poweroff -f
    fi
    ! loaded dummy
    echo 'SAF-MODULE: post-boot-load-denied'
else
    $b insmod /modules/dummy.ko numdummies=0
    loaded dummy
    echo 'SAF-MODULE: baseline-load-allowed'
fi
loaded loop
echo 'SAF-MODULE: approved-module-remains-present'
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
echo baseline_stock_module_loaded
boot 1 governed.log
require governed.log 'SAF-MODULE: post-boot-load-denied'
echo post_boot_loading_denied
require governed.log 'SAF-MODULE: approved-boot-module-present'
require governed.log 'SAF-MODULE: approved-module-remains-present'
echo approved_module_retained
