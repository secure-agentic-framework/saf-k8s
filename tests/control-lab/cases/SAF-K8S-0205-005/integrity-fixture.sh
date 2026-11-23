#!/bin/sh
set -eu
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
original=/fixture/marker.o
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out local-key.pem
openssl pkey -in local-key.pem -pubout -out local-anchor.pem
openssl dgst -sha256 -sign local-key.pem -out marker.sig "$original"
cp "$original" changed.o
printf '%s\n' 'Public fixture integrity comparison' >>changed.o
if openssl dgst -sha256 -verify local-anchor.pem -signature marker.sig changed.o >/dev/null 2>&1; then
    echo 'The changed object unexpectedly matched the approved signature' >&2
    exit 1
fi
echo modified_object_rejected_before_load
openssl dgst -sha256 -verify local-anchor.pem -signature marker.sig "$original" >/dev/null
echo approved_object_verifies

kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -print)
version=${kernel##*/vmlinuz-}
grep -qx 'CONFIG_BPF_SYSCALL=y' "/boot/config-$version"
if gzip -t "$kernel" >/dev/null 2>&1; then gzip -dc "$kernel" >kernel.img; else cp "$kernel" kernel.img; fi
mkdir -p fs/bin fs/dev fs/proc fs/sys
cp "$(command -v busybox)" fs/bin/busybox
tool=$(command -v bpftool)
cp "$tool" fs/bin/bpftool
ldd "$tool" | awk '$1 ~ /^\// {print $1} $2=="=>" && $3 ~ /^\// {print $3}' >libraries
while IFS= read -r library; do
    mkdir -p "$(dirname "fs$library")"
    cp -L "$library" "fs$library"
done <libraries
cp "$original" fs/marker.o
cmp "$original" fs/marker.o
cat >fs/init <<'INIT'
#!/bin/busybox sh
set -eu
b=/bin/busybox
$b mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
trap '$b poweroff -f' EXIT
$b mount -t proc proc /proc
$b mount -t sysfs sysfs /sys
$b mount -t bpf bpf /sys/fs/bpf
test ! -e /sys/fs/bpf/saf_marker
/bin/bpftool prog load /marker.o /sys/fs/bpf/saf_marker
echo 'SAF-BPF-LOAD: succeeded'
/bin/bpftool -j prog show pinned /sys/fs/bpf/saf_marker
$b rm /sys/fs/bpf/saf_marker
test ! -e /sys/fs/bpf/saf_marker
echo 'SAF-BPF-CLEANUP: pin removed'
$b poweroff -f
INIT
chmod 0755 fs/init
(cd fs && find . -print0 | cpio --null -o --owner=0:0 -H newc 2>/dev/null | gzip -n) >fixture.cpio.gz
if ! timeout 32s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 256M \
      -nodefaults -display none -serial stdio -monitor none -nic none \
      -kernel kernel.img -initrd fixture.cpio.gz \
      -append 'console=ttyAMA0 rdinit=/init panic=-1 loglevel=4' >guest.log 2>&1; then
    tail -32 guest.log >&2
    exit 1
fi
for expected in 'SAF-BPF-LOAD: succeeded' '"type":"socket_filter"' '"name":"saf_marker"' 'SAF-BPF-CLEANUP: pin removed'; do
    grep -Fq "$expected" guest.log || { tail -32 guest.log >&2; exit 1; }
done
echo approved_program_loaded_and_observed
