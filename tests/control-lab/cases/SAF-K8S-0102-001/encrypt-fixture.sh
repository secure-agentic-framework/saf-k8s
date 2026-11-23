#!/bin/sh
set -eu
umask 077
cd /work
truncate -s 16M plain.img
mkfs.ext4 -q -F -d /work/fixture-files plain.img
marker='saf owned etcd disk marker v1'
grep -aFq "$marker" plain.img
echo plain_marker_present

head -c 32 /dev/urandom | base64 > /fixture-keys/current
head -c 32 /dev/urandom | base64 > /fixture-keys/incorrect
trap 'rm -f /fixture-keys/current /fixture-keys/incorrect' EXIT
qemu-img convert --object secret,id=offline,file=/fixture-keys/current \
  -f raw -O luks -o key-secret=offline plain.img protected.img
test "$(od -An -tx1 -N6 protected.img | tr -d ' \n')" = '4c554b53babe'
if grep -aFq "$marker" protected.img; then
  echo 'Public marker remained visible in protected image' >&2
  exit 1
fi
echo luks_image_and_hidden_marker

if qemu-img convert --object secret,id=offline,file=/fixture-keys/incorrect --image-opts \
    -O raw 'driver=luks,file.driver=file,file.filename=protected.img,key-secret=offline' wrong.img 2>wrong-error; then
  echo 'Wrong key unexpectedly opened protected image' >&2
  exit 1
fi
grep -Eiq 'invalid password|no key available|incorrect password' wrong-error
echo wrong_key_denied

qemu-img convert --object secret,id=offline,file=/fixture-keys/current --image-opts \
  -O raw 'driver=luks,file.driver=file,file.filename=protected.img,key-secret=offline' restored.img
cmp plain.img restored.img >/dev/null
echo exact_restore_with_separate_key
