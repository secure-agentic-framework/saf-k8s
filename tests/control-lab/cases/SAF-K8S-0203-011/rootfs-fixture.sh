#!/bin/sh
set -eu
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -print)
version=${kernel##*/vmlinuz-}
test -f "$kernel"
if gzip -t "$kernel" >/dev/null 2>&1; then
    gzip -dc "$kernel" >kernel.img
else
    cp "$kernel" kernel.img
fi

mkdir -p initramfs/bin initramfs/dev initramfs/proc initramfs/sys initramfs/newroot initramfs/modules
cp "$(command -v busybox)" initramfs/bin/busybox
: > initramfs/modules/load
modprobe -S "$version" --show-depends --all virtio_mmio virtio_blk ext4 | awk '$1=="insmod" && !seen[$2]++ {print $2}' >module-paths
while IFS= read -r module; do
    item=${module##*/}
    name=${item%%.ko*}.ko
    case "$item" in
        *.xz) xz -dc "$module" >"initramfs/modules/$name" ;;
        *.zst) zstd -q -dc "$module" >"initramfs/modules/$name" ;;
        *.gz) gzip -dc "$module" >"initramfs/modules/$name" ;;
        *) cp "$module" "initramfs/modules/$name" ;;
    esac
    printf '%s\n' "$name" >>initramfs/modules/load
done <module-paths
cat >initramfs/init <<'INIT'
#!/bin/busybox sh
set -eu
b=/bin/busybox
$b mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
$b mount -t proc proc /proc
$b mount -t sysfs sysfs /sys
while IFS= read -r name; do
    $b insmod "/modules/$name"
done </modules/load
for tick in 1 2 3 4 5; do
    test -b /dev/vda && test -b /dev/vdb && break
    $b sleep 1
done
root_mode=ro
for word in $($b cat /proc/cmdline); do
    if test "$word" = "saf.mode=baseline"; then root_mode=rw; fi
done
root_device=
state_device=
for device in /dev/vda /dev/vdb; do
    # These fixture disks use ext4, whose superblock volume label starts at byte 1144.
    label=$($b dd if="$device" bs=1 skip=1144 count=16 2>/dev/null | $b tr -d '\000')
    case "$label" in
        SAFROOT) root_device="$device" ;;
        SAFSTATE) state_device="$device" ;;
    esac
done
test -n "$root_device" && test -n "$state_device"
export SAF_STATE_DEVICE="$state_device"
$b mount -t ext4 -o "$root_mode" "$root_device" /newroot
$b mount --move /dev /newroot/dev
$b mount --move /proc /newroot/proc
$b mount --move /sys /newroot/sys
exec $b switch_root /newroot /sbin/init
INIT
chmod 0755 initramfs/init
(cd initramfs && find . -print0 | cpio --null -o --owner=0:0 -H newc 2>/dev/null | gzip -n) >fixture.cpio.gz

mkdir -p rootfiles/bin rootfiles/sbin rootfiles/etc rootfiles/dev rootfiles/proc rootfiles/sys rootfiles/state state-empty
cp initramfs/bin/busybox rootfiles/bin/busybox
cat >rootfiles/sbin/init <<'GUEST'
#!/bin/busybox sh
set -eu
b=/bin/busybox
$b cat /etc/fixture-release
if $b touch /fixture-write-marker 2>/dev/null; then
    echo 'SAF-ROOT-WRITE: allowed'
else
    echo 'SAF-ROOT-WRITE: denied'
fi
if $b grep -q ' / ext4 ro[, ]' /proc/mounts; then
    echo 'SAF-ROOT-MOUNT: ro'
else
    echo 'SAF-ROOT-MOUNT: rw'
fi
$b mount -t ext4 "$SAF_STATE_DEVICE" /state
if $b grep -q '^fixture durable public state$' /state/marker 2>/dev/null; then
    echo 'SAF-STATE: retained'
else
    echo 'fixture durable public state' >/state/marker
    echo 'SAF-STATE: written'
fi
$b sync
$b poweroff -f
GUEST
chmod 0755 rootfiles/sbin/init
make_image() {
    truncate -s 24M "$1"
    mkfs.ext4 -q -F -L "$3" -d "$2" "$1"
}
printf '%s\n' 'SAF-ROOT-RELEASE: version-one' >rootfiles/etc/fixture-release
make_image first.img rootfiles SAFROOT
cp first.img baseline.img
printf '%s\n' 'SAF-ROOT-RELEASE: version-two' >rootfiles/etc/fixture-release
make_image replacement.img rootfiles SAFROOT
make_image writable.img state-empty SAFSTATE
cp writable.img baseline-state.img
sha256sum first.img replacement.img >expected-root.sha256

boot() {
    root="$1" state="$2" mode="$3" log="$4" readonly="$5"
    if ! timeout 32s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 256M \
      -nodefaults -display none -serial stdio -monitor none -nic none \
      -kernel kernel.img -initrd fixture.cpio.gz \
      -append "console=ttyAMA0 rdinit=/init panic=-1 loglevel=4 saf.mode=$mode" \
      -drive "if=none,id=root,file=$root,format=raw,readonly=$readonly" -device virtio-blk-device,drive=root \
      -drive "if=none,id=state,file=$state,format=raw" -device virtio-blk-device,drive=state >"$log" 2>&1; then
        tail -32 "$log" >&2
        exit 1
    fi
}
require() {
    grep -Fq "$2" "$1" || { tail -28 "$1" >&2; exit 1; }
}
boot baseline.img baseline-state.img baseline baseline.log off
require baseline.log 'SAF-ROOT-MOUNT: rw'
require baseline.log 'SAF-ROOT-WRITE: allowed'
echo writable_baseline_changed

boot first.img writable.img protected first.log on
require first.log 'SAF-ROOT-RELEASE: version-one'
require first.log 'SAF-ROOT-MOUNT: ro'
require first.log 'SAF-ROOT-WRITE: denied'
require first.log 'SAF-STATE: written'
echo verified_root_denied_and_state_written

boot replacement.img writable.img protected replacement.log on
require replacement.log 'SAF-ROOT-RELEASE: version-two'
require replacement.log 'SAF-ROOT-MOUNT: ro'
require replacement.log 'SAF-ROOT-WRITE: denied'
require replacement.log 'SAF-STATE: retained'
sha256sum -c expected-root.sha256 >/dev/null
echo approved_root_replaced_and_state_retained
