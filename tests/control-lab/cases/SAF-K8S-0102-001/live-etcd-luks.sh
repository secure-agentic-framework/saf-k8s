#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
die() { printf 'ERROR %s\n' "$*" >&2; exit 1; }

[[ "${SAF_K8S_0102_001_DISPOSABLE_GUEST:-}" = I_OWN_THIS_DISPOSABLE_VM ]] || die 'disposable guest opt-in required'
[[ "$(id -u)" = 0 ]] || die 'root required in the guest'
systemd-detect-virt --vm >/dev/null || die 'a virtual machine is required'
[[ -z "$(findmnt -rn -t virtiofs,9p || true)" ]] || die 'the guest must have no host shares'
for command in cryptsetup losetup truncate mkfs.ext4 mount umount findmnt grep openssl timeout kind kubectl docker python3; do
  command -v "$command" >/dev/null || die "missing guest command $command"
done
unset DOCKER_HOST DOCKER_CONTEXT KUBECONFIG KIND_CLUSTER_NAME
export KIND_EXPERIMENTAL_PROVIDER=docker
[[ "$(docker context show)" = default &&
   "$(docker context inspect default --format '{{ .Endpoints.docker.Host }}')" = unix:///var/run/docker.sock ]] || die 'only the guest-local default Docker context is supported'

work=$(mktemp -d /var/tmp/saf-k8s-0102-001.XXXXXXXX)
plain="$work/ordinary.ext4"
encrypted="$work/protected.luks"
storage="$work/etcd"
data="$storage/data"
key="$work/owned.key"
wrong="$work/wrong.key"
nonce=$(openssl rand -hex 6)
mapper="saf-etcd-$nonce"
name="saf-etcd-$nonce"
node="$name-control-plane"
image="kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
marker="SAF owned native etcd fixture marker $nonce"
config="$work/kind.yaml"
kubeconfig="$work/kubeconfig"
loop=''
active=0
mounted=0
mapped=0
clean() {
  local result=$?
  trap - EXIT INT TERM HUP
  if (( active )); then
    kind delete cluster --name "$name" --kubeconfig "$kubeconfig" || result=1
  fi
  if (( mounted )); then umount "$storage" || result=1; fi
  if (( mapped )); then cryptsetup close "$mapper" || result=1; fi
  if [[ -n "$loop" ]]; then losetup -d "$loop" || result=1; fi
  if ! findmnt --mountpoint "$storage" >/dev/null; then
    [[ "$work" =~ ^/var/tmp/saf-k8s-0102-001\.[A-Za-z0-9]+$ ]] && rm -rf -- "$work"
  fi
  [[ ! -e "$work" ]] || result=1
  if (( result == 0 )); then printf 'GUEST_FIXTURE_CLEANUP=true\n'; fi
  exit "$result"
}
trap clean EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
install -d -m700 "$storage"

cat > "$config" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: $data
    containerPath: /var/lib/etcd
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta4
  kind: ClusterConfiguration
  etcd:
    local:
      dataDir: /var/lib/etcd
      extraArgs:
      - name: wal-dir
        value: /var/lib/etcd/fixture-wal
EOF

api() { kubectl --kubeconfig "$kubeconfig" --context "kind-$name" --request-timeout=8s "$@"; }
await_api() {
  for _ in {1..36}; do
    if [[ "$(api get --raw=/readyz 2>/dev/null || true)" = ok ]]; then return; fi
    sleep 2
  done
  die 'native API did not return ready'
}
contains_marker() {
  local file=$1 result=0
  grep -aFq -- "$marker" "$file" || result=$?
  [[ "$result" = 0 ]]
}
verify_paths_and_write() {
  install -d -m700 "$data"
  active=1
  kind create cluster --config "$config" --name "$name" --image "$image" \
    --kubeconfig "$kubeconfig" --wait 100s > "$work/cluster-create.log" 2>&1 || {
    tail -25 "$work/cluster-create.log" >&2
    die 'owned Kind bootstrap did not complete'
  }
  local flags
  flags=$(docker exec "$node" cat /etc/kubernetes/manifests/etcd.yaml)
  grep -q -- '--data-dir=/var/lib/etcd$' <<< "$flags" || die 'unexpected live backend directory'
  grep -q -- '--wal-dir=/var/lib/etcd/fixture-wal$' <<< "$flags" || die 'unexpected live WAL directory'
  docker inspect "$node" --format '{{range .Mounts}}{{if eq .Destination "/var/lib/etcd"}}{{.Source}}{{end}}{{end}}' \
    | grep -Fxq -- "$data" || die 'live node storage mount did not match the owned backing'
  api -n kube-system get pod "etcd-$node" -o json | python3 -c '
import json
import sys

pod = json.load(sys.stdin)
target = "/var/lib/etcd"
containers = [c for c in pod["spec"]["containers"] if c["name"] == "etcd"]
assert len(containers) == 1
assert "--data-dir=" + target in containers[0]["command"]
assert "--wal-dir=" + target + "/fixture-wal" in containers[0]["command"]
volumes = [v for v in pod["spec"]["volumes"] if v.get("hostPath", {}).get("path") == target]
assert len(volumes) == 1
mounts = [m for m in containers[0]["volumeMounts"] if m["name"] == volumes[0]["name"]]
assert len(mounts) == 1 and mounts[0]["mountPath"] == target and not mounts[0].get("readOnly")
'
  api create namespace saf-encrypted-etcd-fixture >/dev/null
  api -n saf-encrypted-etcd-fixture create configmap marker --from-literal="fixture=$marker" >/dev/null
  verify_marker
}
verify_marker() {
  [[ "$(api -n saf-encrypted-etcd-fixture get configmap marker -o jsonpath='{.data.fixture}')" = "$marker" ]] \
    || die 'native API returned an unexpected value'
}
stop_node() {
  docker stop -t 30 "$node" >/dev/null
  sync
  [[ "$(docker inspect "$node" --format '{{.State.Running}}')" = false ]] || die 'owned node did not stop'
}
verify_file_markers() {
  contains_marker "$data/member/snap/db" || die 'effective native etcd backend file did not contain the expected marker'
  local matches=0 file
  for file in "$data"/fixture-wal/*.wal; do
    if [[ -f "$file" ]] && contains_marker "$file"; then (( ++matches )); fi
  done
  (( matches > 0 )) || die 'no effective native etcd WAL contained the expected marker'
}
delete_cluster() {
  kind delete cluster --name "$name" --kubeconfig "$kubeconfig" > "$work/cluster-delete.log" 2>&1
  if docker inspect "$node" --format '{{.Name}}' >/dev/null 2>&1; then
    die 'owned node remains after Kind cleanup'
  fi
  active=0
}

truncate -s 384M "$plain"
mkfs.ext4 -q -F "$plain"
mount -o loop "$plain" "$storage"
mounted=1
verify_paths_and_write
plain_cluster="$name"
stop_node
verify_file_markers
delete_cluster
umount "$storage"
mounted=0
contains_marker "$plain" || die 'plaintext backing failed the exact marker control'
printf 'PLAINTEXT_BACKEND_WAL_AND_IMAGE_VISIBLE=true\n'

name="$name-enc"
node="$name-control-plane"
truncate -s 512M "$encrypted"
openssl rand -out "$key" 64
openssl rand -out "$wrong" 64
loop=$(losetup --find --show "$encrypted")
cryptsetup luksFormat --type luks2 --batch-mode --key-file "$key" "$loop"
cryptsetup open --key-file "$key" "$loop" "$mapper"
mapped=1
mkfs.ext4 -q -F "/dev/mapper/$mapper"
mount "/dev/mapper/$mapper" "$storage"
mounted=1
[[ "$(readlink -f "$(findmnt -rn -o SOURCE --mountpoint "$storage")")" = "$(readlink -f "/dev/mapper/$mapper")" ]] \
  || die 'guest filesystem does not resolve to the owned encrypted mapper'
verify_paths_and_write
stop_node
verify_file_markers
printf 'LIVE_ETCD_BACKEND_AND_WAL_MAPPED_AND_READABLE=true\n'
umount "$storage"
mounted=0
cryptsetup close "$mapper"
mapped=0
result=0
grep -aFq -- "$marker" "$encrypted" || result=$?
[[ "$result" = 1 ]] || die 'encrypted raw disk contains the marker or failed to read'
printf 'EXACT_MARKER_ABSENT_FROM_CLOSED_RAW_LUKS=true\n'
result=0
cryptsetup open --test-passphrase --key-file "$wrong" "$loop" > "$work/wrong-key.log" 2>&1 || result=$?
[[ "$result" -ne 0 && ! -e "/dev/mapper/$mapper" ]] || die 'wrong key was accepted or mapper appeared'
printf 'WRONG_KEY_REFUSED=true\n'
cryptsetup open --key-file "$key" "$loop" "$mapper"
mapped=1
mount "/dev/mapper/$mapper" "$storage"
mounted=1
docker start "$node" >/dev/null
await_api
verify_marker
printf 'NATIVE_API_READS_EXACT_MARKER_AFTER_REOPEN=true\n'
delete_cluster
printf 'PLAIN_CLUSTER=%s\nENCRYPTED_CLUSTER=%s\n' "$plain_cluster" "$name"
