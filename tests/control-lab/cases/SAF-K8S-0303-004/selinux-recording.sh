#!/bin/sh
set -eu
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

kernel=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -print)
version=${kernel##*/vmlinuz-}
grep -qx 'CONFIG_SECURITY_SELINUX=y' "/boot/config-$version"
if gzip -t "$kernel" >/dev/null 2>&1; then gzip -dc "$kernel" >kernel.img; else cp "$kernel" kernel.img; fi
mkdir -p fs/bin fs/dev fs/etc/selinux fs/fixture fs/proc fs/sys fs/tmp fs/var/lib fs/usr/libexec/selinux
cp /usr/bin/busybox fs/bin/busybox
for executable in /usr/sbin/load_policy /usr/sbin/setenforce /usr/bin/chcon /usr/bin/runcon /usr/sbin/semodule /usr/sbin/setfiles /usr/sbin/sefcontext_compile /usr/libexec/selinux/hll/pp; do
    case "$executable" in
        /usr/libexec/*)
            mkdir -p "fs$(dirname "$executable")"
            cp "$executable" "fs$executable" ;;
        *) cp "$executable" "fs/bin/${executable##*/}" ;;
    esac
    ldd "$executable" | awk '$1 ~ /^\// {print $1} $2=="=>" && $3 ~ /^\// {print $3}' >libraries
    while IFS= read -r library; do
        mkdir -p "$(dirname "fs$library")"
        cp -L "$library" "fs$library"
    done <libraries
done
policy=$(find /etc/selinux/default/policy -name 'policy.*' -type f)
mkdir -p fs/etc/selinux/default/policy
cp "$policy" fs/etc/selinux/default/policy/
cp -R /etc/selinux/. fs/etc/selinux/
ln -s bin fs/sbin
printf '\ndisable-genhomedircon = true\n' >>fs/etc/selinux/semanage.conf
cp -R /usr/local/share/saf/selinux-store fs/var/lib/selinux
# The pinned reference store, policy and libexec converter are used only in the guest.
cp /fixture/selinux-base.cil /fixture/selinux-approved.txt fs/fixture/
digest=$(sha256sum "$policy" | awk '{print $1}')
for name in startup recovery incidental; do
    printf 'owned %s canary\n' "$name" >"fs/fixture/$name"
    chmod 0644 "fs/fixture/$name"
done
: >fs/fixture/request
: >fs/fixture/result
cat >fs/fixture/record-worker <<'WORKER'
set -eu
b=/bin/busybox
IFS= read -r current </proc/self/attr/current || :
test "$current" = "$1"
printf 'ready %s\n' "$$" >/fixture/result
sequence=0
while :; do
    if ! read -r next target </fixture/request || test "$next" = "$sequence"; then
        "$b" sleep .1
        continue
    fi
    sequence=$next
    case "$target" in startup|recovery|incidental) ;; stop) exit 0 ;; *) exit 12 ;; esac
    decision=denied
    if { IFS= read -r text <"/fixture/$target" && test "$text" = "owned $target canary"; }; then
        decision=allowed
    fi
    printf '%s %s\n' "$sequence" "$decision" >/fixture/result
done
WORKER
cat >fs/init <<'INIT'
#!/bin/busybox sh
set -eu
b=/bin/busybox
export PATH=/bin
"$b" mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
trap '"$b" dmesg | "$b" grep -i "avc:" | "$b" tail -20; "$b" poweroff -f' EXIT
"$b" mount -t proc proc /proc
printf '0\n' >/proc/sys/kernel/printk_ratelimit
"$b" mount -t sysfs sysfs /sys
"$b" mount -t securityfs securityfs /sys/kernel/security
"$b" mount -t selinuxfs selinuxfs /sys/fs/selinux
"$b" grep -wq selinux /sys/kernel/security/lsm
/bin/load_policy -i
/bin/semodule -n -i /fixture/selinux-base.cil
/bin/load_policy
base_policy=$("$b" find /etc/selinux/default/policy -name 'policy.*' -type f)
"$b" cp "$base_policy" /tmp/approved-baseline.policy
baseline_digest=$("$b" sha256sum /tmp/approved-baseline.policy | "$b" cut -d' ' -f1)
/bin/setenforce 0
test "$("$b" cat /sys/fs/selinux/enforce)" = 0
level=s0:c10,c20
subject=system_u:system_r:container_t:$level
/bin/chcon system_u:object_r:container_file_t:s0 /bin/busybox /fixture /fixture/record-worker /fixture/request
/bin/chcon "system_u:object_r:container_file_t:$level" /fixture/result
for name in startup recovery incidental; do
    /bin/chcon "system_u:object_r:saf_record_${name}_t:$level" "/fixture/$name"
    test "$("$b" stat -c '%u:%g:%a' "/fixture/$name")" = 0:0:644
done
printf 'SAF-SELINUX-RECORD-INPUT: %s %s\n' \
    "$("$b" sha256sum /fixture/selinux-base.cil | "$b" cut -d' ' -f1)" \
    "$("$b" sha256sum /fixture/selinux-approved.txt | "$b" cut -d' ' -f1)"

/bin/runcon "$subject" /bin/busybox sh /fixture/record-worker "$subject" &
worker=$!
wait_result() {
    for attempt in $("$b" seq 1 50); do
        if "$b" grep -Fxq "$*" /fixture/result; then return; fi
        "$b" sleep .1
    done
    echo "SAF-SELINUX-RECORD-ERROR: expected $*"
    "$b" cat /fixture/result
    exit 1
}
wait_result ready "$worker"
sequence=0
probe() {
    sequence=$((sequence + 1))
    "$b" dmesg -c >/dev/null
    printf '%s %s\n' "$sequence" "$1" >/fixture/request
    wait_result "$sequence" "$2"
}
require_avc() {
    for attempt in $("$b" seq 1 20); do
        avc=$("$b" dmesg | "$b" grep 'avc:.*denied.*{[^}]*read[^}]*}' |
            "$b" grep -F "pid=$worker " | "$b" grep -F "name=\"$1\"" |
            "$b" grep -F "scontext=$subject " |
            "$b" grep -F "tcontext=system_u:object_r:saf_record_${1}_t:$level " |
            "$b" grep -F "tclass=file permissive=$2" || :)
        if test -n "$avc"; then
            printf 'SAF-SELINUX-RECORDED-AVC-%s: %s\n' "$2" "$avc"
            return
        fi
        "$b" sleep .1
    done
    echo "SAF-SELINUX-RECORD-ERROR: missing attributable AVC for $1 in mode $2"
    exit 1
}
record() {
    probe "$1" allowed
    require_avc "$1" 1
    printf '%s\n' "$1" >>/tmp/observed
}
deny() {
    probe "$1" denied
    require_avc "$1" 0
}
derive() {
    while IFS= read -r name; do
        case "$name" in startup|recovery) ;; *) exit 13 ;; esac
        if "$b" grep -Fxq "$name" /tmp/observed; then
            printf '(allow container_t saf_record_%s_t (file (open read)))\n' "$name"
        fi
    done </fixture/selinux-approved.txt >"$1"
}
install_rules() {
    "$b" cp "$1" /tmp/saf_record_rules.cil
    /bin/semodule -n -i /tmp/saf_record_rules.cil
    /bin/load_policy
}
record startup
record incidental
derive /tmp/initial.cil
test "$("$b" wc -l </tmp/initial.cil)" -eq 1
install_rules /tmp/initial.cil
/bin/setenforce 1
test "$("$b" cat /sys/fs/selinux/enforce)" = 1
probe startup allowed
deny recovery
deny incidental
echo 'SAF-SELINUX-RECORD: the initial enforcing profile excludes incidental and unobserved recovery reads'

/bin/setenforce 0
test "$("$b" cat /sys/fs/selinux/enforce)" = 0
/bin/load_policy
record recovery
derive /tmp/final.cil
test "$("$b" wc -l </tmp/final.cil)" -eq 2
install_rules /tmp/final.cil
/bin/setenforce 1
test "$("$b" cat /sys/fs/selinux/enforce)" = 1
probe startup allowed
probe recovery allowed
deny incidental
printf 'SAF-SELINUX-RECORD-PROFILES: %s %s\n' \
    "$("$b" sha256sum /tmp/initial.cil | "$b" cut -d' ' -f1)" \
    "$("$b" sha256sum /tmp/final.cil | "$b" cut -d' ' -f1)"
echo 'SAF-SELINUX-RECORD: the derived enforcing profile keeps both approved reads and denies the incidental read'

# Restore the saved policy using SELinux's kernel policy loader while enforcing.
test "$("$b" sha256sum /tmp/approved-baseline.policy | "$b" cut -d' ' -f1)" = "$baseline_digest"
# libselinux converts the reference binary to the kernel-supported policy version.
"$b" cp /tmp/approved-baseline.policy "$base_policy"
/bin/load_policy
test "$("$b" cat /sys/fs/selinux/enforce)" = 1
deny startup
deny recovery
printf '%s stop\n' "$((sequence + 1))" >/fixture/request
wait "$worker"
echo 'SAF-SELINUX-RECORD: restoring the saved policy restores the previous enforcement decisions'
"$b" poweroff -f
INIT
chmod 0755 fs/init
(cd fs && find . -print0 | cpio --null -o --owner=0:0 -H newc 2>/dev/null | gzip -n) >fixture.cpio.gz
if ! timeout 285s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 384M \
      -nodefaults -display none -serial stdio -monitor none -nic none \
      -kernel kernel.img -initrd fixture.cpio.gz \
      -append 'console=ttyAMA0 rdinit=/init panic=-1 loglevel=5 audit=1 audit_backlog_limit=4096 enforcing=0 lsm=selinux' >guest.log 2>&1; then
    tail -65 guest.log >&2
    exit 1
fi
tr -d '\r' <guest.log >guest-lines.log
if grep -Eq 'audit_lost=[1-9][0-9]*' guest-lines.log; then
    grep -E 'audit_lost=[1-9][0-9]*' guest-lines.log >&2
    exit 1
fi
for expected in \
    'SAF-SELINUX-RECORD: the initial enforcing profile excludes incidental and unobserved recovery reads' \
    'SAF-SELINUX-RECORD: the derived enforcing profile keeps both approved reads and denies the incidental read' \
    'SAF-SELINUX-RECORD: restoring the saved policy restores the previous enforcement decisions'; do
    grep -Fxq "$expected" guest-lines.log || { tail -100 guest.log >&2; exit 1; }
done
grep -E '^SAF-SELINUX-(RECORD(:|-INPUT:|-PROFILES:)|RECORDED-AVC-[01]:)' guest-lines.log
