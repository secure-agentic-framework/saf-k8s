#!/bin/sh
set -eu
umask 077
plain=/backup-work/plain.raw
recovered=/backup-work/recovered.raw
vault=/backup-vault/fixture-backup.luks
marker=synthetic-cedar-v1
good=/backup-keys/approved
bad=/backup-keys/unrelated
grep -aFq "$marker" "$plain"
echo plaintext_marker_visible
head -c 32 /dev/urandom | base64 > "$good"
head -c 32 /dev/urandom | base64 > "$bad"
trap 'rm -f "$good" "$bad" /backup-work/wrong.raw /backup-work/wrong.err' EXIT
qemu-img convert --object secret,id=offline,file="$good" -f raw -O luks -o key-secret=offline "$plain" "$vault"
test "$(od -An -tx1 -N6 "$vault" | tr -d ' \n')" = 4c554b53babe
if grep -aFq "$marker" "$vault"; then exit 2; fi
echo luks_media_marker_hidden
if qemu-img convert --object secret,id=offline,file="$bad" --image-opts -O raw   "driver=luks,file.driver=file,file.filename=$vault,key-secret=offline" /backup-work/wrong.raw 2>/backup-work/wrong.err; then
  exit 3
fi
grep -Eiq 'invalid password|no key available|incorrect password' /backup-work/wrong.err
echo unrelated_key_denied
qemu-img convert --object secret,id=offline,file="$good" --image-opts -O raw   "driver=luks,file.driver=file,file.filename=$vault,key-secret=offline" "$recovered"
cmp "$plain" "$recovered"
rm "$plain"
echo approved_key_roundtrip
test "$(ls -A /backup-vault)" = fixture-backup.luks
echo persistent_vault_ciphertext_only
