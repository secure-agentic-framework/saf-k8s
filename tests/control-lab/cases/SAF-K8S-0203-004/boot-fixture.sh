#!/bin/sh
set -eu
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
firmware=/usr/share/AAVMF
guid=2067fbb7-5652-4b54-9de5-f24c522a7ac8
openssl req -new -x509 -newkey rsa:2048 -nodes -days 2 -sha256 \
    -subj '/CN=SAF disposable verified boot signer' -keyout signer.key -out signer.crt 2>openssl.log
cp "$firmware/AAVMF_VARS.fd" baseline.vars
virt-fw-vars --input "$firmware/AAVMF_VARS.fd" --output approved.vars \
    --set-pk "$guid" signer.crt --add-kek "$guid" signer.crt --add-db "$guid" signer.crt \
    --no-microsoft --secure-boot >vars.log 2>&1 || { cat vars.log >&2; exit 1; }
cp approved.vars denied.vars
mkdir -p unsigned/EFI/BOOT signed/EFI/BOOT
cp /fixture/marker.efi unsigned/EFI/BOOT/BOOTAA64.EFI
sbsign --key signer.key --cert signer.crt --output signed/EFI/BOOT/BOOTAA64.EFI \
    unsigned/EFI/BOOT/BOOTAA64.EFI >sign.log 2>&1 || { cat sign.log >&2; exit 1; }
sbverify --cert signer.crt signed/EFI/BOOT/BOOTAA64.EFI >verify.log 2>&1 || { cat verify.log >&2; exit 1; }


openssl req -new -x509 -newkey rsa:2048 -nodes -days 2 -sha256 \
    -subj '/CN=SAF disposable replacement signer' -keyout replacement.key -out replacement.crt 2>replacement-cert.log
virt-fw-vars --input "$firmware/AAVMF_VARS.fd" --output replacement.vars \
    --set-pk "$guid" replacement.crt --add-kek "$guid" replacement.crt --add-db "$guid" replacement.crt \
    --no-microsoft --secure-boot >replacement-vars.log 2>&1 || { cat replacement-vars.log >&2; exit 1; }
cp approved.vars wrong-signer.vars
cp replacement.vars old-signer.vars
mkdir -p replacement/EFI/BOOT
sbsign --key replacement.key --cert replacement.crt --output replacement/EFI/BOOT/BOOTAA64.EFI \
    unsigned/EFI/BOOT/BOOTAA64.EFI >replacement-sign.log 2>&1 || { cat replacement-sign.log >&2; exit 1; }
sbverify --cert replacement.crt replacement/EFI/BOOT/BOOTAA64.EFI >replacement-verify.log 2>&1 || {
    cat replacement-verify.log >&2
    exit 1
}
printf 'original_signer %s\n' "$(openssl x509 -in signer.crt -sha256 -fingerprint -noout | cut -d= -f2 | tr -d :)"
printf 'replacement_signer %s\n' "$(openssl x509 -in replacement.crt -sha256 -fingerprint -noout | cut -d= -f2 | tr -d :)"
sha256sum "$firmware/AAVMF_CODE.secboot.fd" | awk '{print "firmware_sha256 " $1}'
rm signer.key replacement.key

boot() {
    vars="$1"
    disk="$2"
    output="$3"
    wanted="$4"
    status=0
    : >"$output"
    timeout 75s qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57 -m 256M \
      -nodefaults -display none -serial stdio -monitor none -nic none \
      -drive "if=pflash,format=raw,file=$firmware/AAVMF_CODE.secboot.fd,readonly=on" \
      -drive "if=pflash,format=raw,file=$vars" \
      -drive "if=none,id=bootfs,file=fat:$work/$disk,format=raw,readonly=on" \
      -device virtio-blk-device,drive=bootfs,bootindex=1 >"$output" 2>&1 &
    boot_pid=$!
    while kill -0 "$boot_pid" 2>/dev/null; do
        if grep -Eiq "$wanted" "$output"; then
            kill "$boot_pid" 2>/dev/null || true
            wait "$boot_pid" || true
            return
        fi
        sleep 0.4
    done
    wait "$boot_pid" || status=$?
    if test "$status" -ne 0 && test "$status" -ne 124; then
        tail -25 "$output" >&2
        exit "$status"
    fi
}
denial="BdsDxe: failed to load Boot[0-9A-Fa-f]+ .*: (Security Violation|Access Denied)"
boot baseline.vars unsigned baseline.log "SAF-BOOT-MARKER: disabled"
grep -Fq 'SAF-BOOT-MARKER: disabled' baseline.log || { tail -25 baseline.log >&2; exit 1; }
echo unsigned_runs_without_enforcement

boot denied.vars unsigned denied.log "$denial"
if grep -Fq 'SAF-BOOT-MARKER:' denied.log; then
    echo 'Unsigned fixture unexpectedly executed with enforcement selected' >&2
    exit 1
fi
grep -Eiq 'Security Violation|Access Denied' denied.log || { tail -25 denied.log >&2; exit 1; }
echo enforcement_refuses_unsigned

boot approved.vars signed approved.log "SAF-BOOT-MARKER: enforcing"
grep -Fq 'SAF-BOOT-MARKER: enforcing' approved.log || { tail -25 approved.log >&2; exit 1; }
echo signed_runs_under_enforcement

require_boot_denial() {
    if grep -Fq 'SAF-BOOT-MARKER:' "$1"; then
        printf 'Fixture signer unexpectedly executed under policy %s\n' "$1" >&2
        exit 1
    fi
    grep -Eiq 'Security Violation|Access Denied' "$1" || { tail -25 "$1" >&2; exit 1; }
}
boot wrong-signer.vars replacement unenrolled.log "$denial"
require_boot_denial unenrolled.log
echo replacement_denied_by_original_allowlist

boot replacement.vars replacement rotated.log "SAF-BOOT-MARKER: enforcing"
grep -Fq 'SAF-BOOT-MARKER: enforcing' rotated.log || { tail -25 rotated.log >&2; exit 1; }
echo replacement_allowed_by_revised_allowlist

boot old-signer.vars signed removed.log "$denial"
require_boot_denial removed.log
echo original_denied_after_allowlist_replacement
