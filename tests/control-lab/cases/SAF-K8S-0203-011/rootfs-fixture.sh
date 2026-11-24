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
if $b grep -q 'version-two' /etc/fixture-release; then
    echo 'public state updated on release two' >/state/release-two
    echo 'SAF-UPDATE-STATE: written'
elif $b grep -q '^public state updated on release two$' /state/release-two 2>/dev/null; then
    echo 'SAF-UPDATE-STATE: retained'
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
openssl genpkey -algorithm ED25519 -out fixture-signing.key
openssl pkey -in fixture-signing.key -pubout -out fixture-signing.pub
manifest() {
    slot="$1" image="$2"
    digest=$(sha256sum "$image" | cut -d ' ' -f 1)
    printf '%s %s\n' "$slot" "$digest" >"$slot.manifest"
    openssl pkeyutl -sign -rawin -inkey fixture-signing.key -in "$slot.manifest" -out "$slot.sig"
}
manifest version-one first.img
manifest version-two replacement.img
rm fixture-signing.key

# Verify the signature before using the claimed identity or digest.
verify_root() {
    slot="$1" image="$2" manifest_file="$3" signature="$4"
    openssl pkeyutl -verify -rawin -pubin -inkey fixture-signing.pub \
        -in "$manifest_file" -sigfile "$signature" >/dev/null 2>&1 || return 11
    digest=$(sha256sum "$image" | cut -d ' ' -f 1)
    expected="$slot $digest"
    [ "$(cat "$manifest_file")" = "$expected" ] || return 12
}
approved_boot() {
    slot="$1" root="$2" log="$3"
    verify_root "$slot" "$root" "$slot.manifest" "$slot.sig"
    printf 'manifest %s\n' "$(cat "$slot.manifest")"
    boot "$root" writable.img protected "$log" on
    sed -n '/^SAF-/p' "$log" | tr -d '\r' | sed "s/^/guest $log /"
    require "$log" "SAF-ROOT-RELEASE: $slot"
    require "$log" 'SAF-ROOT-MOUNT: ro'
    require "$log" 'SAF-ROOT-WRITE: denied'
}

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
sed -n '/^SAF-/p' baseline.log | tr -d '\r' | sed 's/^/guest baseline.log /'
require baseline.log 'SAF-ROOT-MOUNT: rw'
require baseline.log 'SAF-ROOT-WRITE: allowed'

cp version-two.manifest changed.manifest
printf '\nchanged fixture metadata\n' >>changed.manifest
bad_signature=0
verify_root version-two replacement.img changed.manifest version-two.sig || bad_signature=$?
test "$bad_signature" = 11
echo modified_manifest_signature_rejected

cp replacement.img changed.img
printf 'changed public fixture image' | dd of=changed.img bs=1 seek=0 conv=notrunc status=none
bad_digest=0
verify_root version-two changed.img version-two.manifest version-two.sig || bad_digest=$?
test "$bad_digest" = 12
echo modified_image_digest_rejected
rm changed.img

approved_boot version-one first.img first.log
require first.log 'SAF-STATE: written'
approved_boot version-two replacement.img replacement.log
require replacement.log 'SAF-STATE: retained'
require replacement.log 'SAF-UPDATE-STATE: written'
approved_boot version-one first.img rollback.log
require rollback.log 'SAF-STATE: retained'
require rollback.log 'SAF-UPDATE-STATE: retained'

verify_root version-one first.img version-one.manifest version-one.sig
verify_root version-two replacement.img version-two.manifest version-two.sig
echo both_signed_root_images_unchanged
