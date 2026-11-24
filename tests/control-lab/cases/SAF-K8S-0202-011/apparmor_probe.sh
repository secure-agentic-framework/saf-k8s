#!/bin/bash
set -euo pipefail
export LC_ALL=C

profile=saf-k8s-0202-011-fixture
work="$(mktemp -d /tmp/saf-oci-0202-011.XXXXXX)"
profile_loaded=false
cleanup() {
    if "$profile_loaded"; then
        apparmor_parser -R "$work/profile"
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

test "$(systemd-detect-virt)" = apple
test "$(dpkg --print-architecture)" = arm64
test "$(cat /sys/module/apparmor/parameters/enabled)" = Y
case ",$(cat /sys/kernel/security/lsm)," in
    *,apparmor,*) ;;
    *) exit 42 ;;
esac
parser_version="$(dpkg-query -W -f='${Version}' apparmor)"
kernel="$(uname -r)"
runc_version="$(dpkg-query -W -f='${Version}' runc)"
busybox_version="$(dpkg-query -W -f='${Version}' busybox-static)"
! grep -Fqx "$profile (enforce)" /sys/kernel/security/apparmor/profiles
mkdir -p "$work/state"

make_bundle() {
    bundle="$1"
    process_profile="$2"
    root="$bundle/rootfs"
    mkdir -p "$root/bin" "$root/proc" "$root/canary"
    install -m 0755 "$(command -v busybox)" "$root/bin/busybox"
    : > "$root/canary/allowed.marker"
    : > "$root/canary/denied.marker"
    chown 65532:65532 "$root/canary" "$root/canary/"*.marker
    chmod 0750 "$root/canary"
    chmod 0660 "$root/canary/"*.marker
    cat > "$root/probe.sh" <<'INNER'
set -eu
test "$(/bin/busybox id -u)" = 65532
label=$(/bin/busybox cat /proc/self/attr/current)
allowed=false
other=false
if (printf allowed-ok > /canary/allowed.marker); then allowed=true; fi
if (printf other-ok > /canary/denied.marker); then other=true; fi
printf 'SAF_PROCESS:%s:%s:%s\n' "$label" "$allowed" "$other"
INNER
    chmod 0444 "$root/probe.sh"
    cat > "$bundle/config.json" <<INNER
{
  "ociVersion": "1.0.2",
  "root": {"path": "rootfs", "readonly": false},
  "process": {
    "terminal": false,
    "user": {"uid": 65532, "gid": 65532, "additionalGids": []},
    "args": ["/bin/busybox", "sh", "/probe.sh"],
    "env": ["PATH=/bin", "LC_ALL=C"],
    "cwd": "/",
    "capabilities": {"bounding": [], "effective": [], "inheritable": [], "permitted": [], "ambient": []},
    "noNewPrivileges": true,
    "apparmorProfile": "$process_profile"
  },
  "hostname": "saf-oci-fixture",
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=1024k"]}
  ],
  "linux": {"namespaces": [
    {"type": "pid"}, {"type": "mount"}, {"type": "ipc"}, {"type": "uts"}, {"type": "network"}
  ]}
}
INNER
}

run_marker() {
    phase="$1"
    requested_profile="$2"
    process_label="$3"
    other_write="$4"
    bundle="$work/$phase"
    make_bundle "$bundle" "$requested_profile"
    printf "Checking OCI phase %s\n" "$phase"
    if ! runc --root "$work/state" run --bundle "$bundle" "saf-oci-$phase" </dev/null > "$bundle/result"; then
        printf 'The OCI marker failed in %s\n' "$phase" >&2
        cat "$bundle/result"
        return 1
    fi
    if ! grep -Fqx "SAF_PROCESS:$process_label:true:$other_write" "$bundle/result"; then
        printf 'The OCI label or writes differed in %s\n' "$phase" >&2
        cat "$bundle/result"
        return 1
    fi
    test "$(cat "$bundle/rootfs/canary/allowed.marker")" = allowed-ok
    if "$other_write"; then
        test "$(cat "$bundle/rootfs/canary/denied.marker")" = other-ok
    else
        test ! -s "$bundle/rootfs/canary/denied.marker"
    fi
}

run_marker baseline "" "runc (unconfined)" true
cat > "$work/profile" <<'PROFILE'
profile saf-k8s-0202-011-fixture flags=(attach_disconnected,mediate_deleted) {
  file,
  deny /canary/denied.marker w,
  deny /tmp/saf-oci-0202-011.*/**/rootfs/canary/denied.marker w,
}
PROFILE
profile_sha256="$(sha256sum "$work/profile" | cut -d ' ' -f 1)"
apparmor_parser -a "$work/profile"
profile_loaded=true
grep -Fqx "$profile (enforce)" /sys/kernel/security/apparmor/profiles
run_marker enforced "$profile" "$profile (enforce)" false
apparmor_parser -R "$work/profile"
profile_loaded=false
! grep -Fqx "$profile (enforce)" /sys/kernel/security/apparmor/profiles
run_marker recovery "" "runc (unconfined)" true

printf 'SAF_RESULT={"guest_arch":"arm64","kernel":"%s","apparmor_enabled":true,"apparmor_active":true,"parser_version":"%s","runc_version":"%s","busybox_static_version":"%s","baseline_both_writes":true,"process_profile_enforcing":true,"allowed_write":true,"denied_write":true,"profile_removed":true,"recovery_both_writes":true,"profile_sha256":"%s"}\n' \
    "$kernel" "$parser_version" "$runc_version" "$busybox_version" "$profile_sha256"
