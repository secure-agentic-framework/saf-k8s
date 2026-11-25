set -Eeuo pipefail
fixture=$1
export LIMA_HOME=$(mktemp -d /private/tmp/saf-etcd-vm.XXXXXXXX)
printf '%s\n' "$LIMA_HOME" > "$fixture/current-lima-root"
vm=saf-etcd
cleanup() {
  if limactl list -q 2>/dev/null | rg -Fxq "$vm"; then
    limactl stop --force "$vm" >> "$fixture/guest-cleanup.log" 2>&1 || true
    limactl delete --force "$vm" >> "$fixture/guest-cleanup.log" 2>&1
  fi
}
trap cleanup EXIT
limactl start --tty=false --name="$vm" --plain --mount-none --cpus=2 --memory=3.5 "$fixture/test-vm.yaml" > "$fixture/guest-start.log" 2>&1
limactl shell "$vm" sudo env SAF_K8S_0102_001_DISPOSABLE_GUEST=I_OWN_THIS_DISPOSABLE_VM bash -s < "$fixture/bootstrap.sh" > "$fixture/guest-bootstrap.log" 2>&1
for arm in 1 2; do
  limactl shell "$vm" sudo env SAF_K8S_0102_001_DISPOSABLE_GUEST=I_OWN_THIS_DISPOSABLE_VM bash -s < "$fixture/live-etcd-luks.sh" > "$fixture/live-etcd-luks-proof-$arm.log" 2>&1
  rg -x 'GUEST_FIXTURE_CLEANUP=true' "$fixture/live-etcd-luks-proof-$arm.log"
done
cleanup
trap - EXIT
test -z "$(limactl list -q 2>/dev/null)"
printf 'OWNED_VM_DELETED=true\n' >> "$fixture/guest-cleanup.log"
