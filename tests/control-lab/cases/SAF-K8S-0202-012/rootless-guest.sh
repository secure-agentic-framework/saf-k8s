#!/bin/bash
set -euo pipefail
test "$(uname -m)" = aarch64
test "$(id -u)" != 0
test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs
work=$(mktemp -d /tmp/saf-rootless.XXXXXX)
name="safr-${work##*.}"
name="${name,,}"
kind="$work/kind-linux-arm64"
kubectl="$work/kubectl"
node="${name}-control-plane"
image="docker.io/kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
export KIND_EXPERIMENTAL_PROVIDER=podman
export KUBECONFIG="$work/kubeconfig"
function cleanup {
    local status=$?
    if [ -x "$kind" ]; then
        "$kind" delete cluster --name "$name" --kubeconfig "$KUBECONFIG" || status=1
        local observed
        observed=$(podman ps -aq --filter "name=^$node\$") || status=1
        if [ -n "$observed" ]; then
            status=1
        elif [ "$status" -eq 0 ]; then
            printf 'owned_node_deleted=true\n'
        fi
    fi
    rm -rf -- "$work"
    return "$status"
}
trap cleanup EXIT
kind_base=https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-arm64
kube_base=https://dl.k8s.io/release/v1.37.0/bin/linux/arm64/kubectl
curl -fsSL --retry 2 --max-time 120 "$kind_base" -o "$kind"
curl -fsSL --retry 2 --max-time 30 "${kind_base}.sha256sum" -o "$work/kind.sha256"
curl -fsSL --retry 2 --max-time 120 "$kube_base" -o "$kubectl"
curl -fsSL --retry 2 --max-time 30 "${kube_base}.sha256" -o "$work/kubectl.sha256"
for pair in "kind:$kind" "kubectl:$kubectl"; do
    tool=${pair%%:*}
    file=${pair#*:}
    checksum=$(awk 'NR == 1 {print $1}' "$work/$tool.sha256")
    [[ "$checksum" =~ ^[0-9a-f]{64}$ ]]
    printf '%s  %s\n' "$checksum" "$file" | sha256sum -c
    printf '%s_sha256=%s\n' "$tool" "$checksum"
    chmod 755 "$file"
done

test "$(podman info --format '{{.Host.Security.Rootless}}')" = true
printf 'host_kernel=%s\n' "$(uname -r)"
podman version --format 'podman_version={{.Client.Version}}'
podman info --format 'rootless={{.Host.Security.Rootless}} cgroups={{.Host.CgroupsVersion}} manager={{.Host.CgroupManager}}'
"$kind" version
mkdir -p "$HOME/.config/containers"
printf '[containers]\nlog_driver = "k8s-file"\n' > "$HOME/.config/containers/containers.conf"
timeout 420s systemd-run --user --scope -p Delegate=yes "$kind" create cluster \
    --name "$name" --kubeconfig "$KUBECONFIG" --image "$image" --wait 150s
kube() { "$kubectl" --kubeconfig "$KUBECONFIG" --context "kind-$name" "$@"; }
kube wait --for=condition=Ready "node/$node" --timeout=90s
kube -n kube-system rollout status daemonset/kindnet --timeout=90s
kube -n kube-system rollout status daemonset/kube-proxy --timeout=90s
reported=$(kube get node "$node" -o 'jsonpath={.status.nodeInfo.runningInUserNamespace}')
printf 'reported_running_in_user_namespace=%s\n' "$reported"
test "$reported" = true
printf 'kubelet_version=%s\n' "$(kube get node "$node" -o 'jsonpath={.status.nodeInfo.kubeletVersion}')"
printf 'container_runtime=%s\n' "$(kube get node "$node" -o 'jsonpath={.status.nodeInfo.containerRuntimeVersion}')"

host_namespace=$(readlink /proc/self/ns/user)
node_pid=$(podman container inspect "$node" --format '{{.State.Pid}}')
node_namespace=$(readlink "/proc/$node_pid/ns/user")
test "$node_namespace" != "$host_namespace"
printf 'node_namespace_differs_from_guest_initial=true\n'
printf 'node_uid_map=%s\n' "$(awk '{printf "%s:%s:%s ", $1,$2,$3}' "/proc/$node_pid/uid_map")"
printf 'node_gid_map=%s\n' "$(awk '{printf "%s:%s:%s ", $1,$2,$3}' "/proc/$node_pid/gid_map")"
test "$(awk '$1 == 0 {print $2}' "/proc/$node_pid/uid_map")" = "$(id -u)"
test "$(awk '$1 == 0 {print $2}' "/proc/$node_pid/gid_map")" = "$(id -g)"
for process in kubelet containerd kube-proxy kindnetd; do
    actual=$(podman exec "$node" sh -ec 'proc=$(pgrep -xo "$1"); readlink "/proc/$proc/ns/user"' sh "$process")
    test "$actual" = "$node_namespace"
    printf 'same_namespace_%s=true\n' "$process"
done

# The guest collects process evidence and delegates the Node write to a separate identity.
kube create namespace saf-rootless
label=saf.test.node-restriction.kubernetes.io/rootless
issuer=system:serviceaccount:saf-rootless:eligibility-issuer
node_uid=$(kube get node "$node" -o 'jsonpath={.metadata.uid}')
test -n "$node_uid"
kube -n saf-rootless create serviceaccount eligibility-issuer
kube create clusterrole saf-rootless-eligibility \
    --verb=get,patch --resource=nodes --resource-name="$node"
kube create clusterrolebinding saf-rootless-eligibility --clusterrole=saf-rootless-eligibility \
    --serviceaccount=saf-rootless:eligibility-issuer
test "$(kube --as="$issuer" auth can-i patch "node/$node")" = yes
test "$(kube --as="$issuer" auth can-i patch node/unverified-fixture-node)" = no
printf 'issuer_is_independent_and_node_scoped=true\n'

# On the owned node, server-side dry-run reaches NodeRestriction with a fixture
# node identity. An ordinary label is the authorization control for the comparison.
node_client=(--as="system:node:$node" --as-group=system:nodes --as-group=system:authenticated)
kube "${node_client[@]}" label node "$node" saf.test/ordinary=fixture --dry-run=server -o name |
    grep -Fx "node/$node"
if deny=$(kube "${node_client[@]}" label node "$node" "$label=verified" --dry-run=server 2>&1); then
    printf 'The node identity could write the protected rootless label\n' >&2
    exit 1
fi
printf '%s\n' "$deny" | grep -F 'is not allowed to modify labels' | grep -F "$label"
printf 'node_restriction_denied_own_label=true\n'

evidence_deadline() {
    local renew process actual
    test "$(kube get node "$node" -o 'jsonpath={.metadata.uid}')" = "$node_uid" || return 1
    test "$(kube get node "$node" -o 'jsonpath={.status.nodeInfo.runningInUserNamespace}')" = true || return 1
    test "$(kube get node "$node" -o 'jsonpath={.status.conditions[?(@.type=="Ready")].status}')" = True || return 1
    test "$(readlink "/proc/$node_pid/ns/user")" = "$node_namespace" || return 1
    for process in kubelet containerd kube-proxy kindnetd; do
        actual=$(podman exec "$node" sh -ec 'proc=$(pgrep -xo "$1"); readlink "/proc/$proc/ns/user"' sh "$process") || return 1
        test "$actual" = "$node_namespace" || return 1
    done
    renew=$(kube -n kube-node-lease get lease "$node" -o 'jsonpath={.spec.renewTime}') || return 1
    test -n "$renew" || return 1
    local last_renew
    last_renew=$(date -u -d "$renew" +%s) || return 1
    # A fixture-specific freshness limit allows ordinary kubelet renewals.
    printf '%s\n' "$((last_renew + 90))"
}
reconcile() {
    local deadline=$1
    local now
    now=$(date -u +%s)
    if [[ "$deadline" =~ ^[0-9]+$ ]] && (( now <= deadline )); then
        kube --as="$issuer" label node "$node" "$label=verified" --overwrite
    else
        kube --as="$issuer" label node "$node" "$label-"
    fi
}
pod_image=docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
create_workload() {
    local pod_name=$1
    local payload=${2:-"printf 'saf-rootless-eligible'"}
    kube -n saf-rootless create -f - <<POD
apiVersion: v1
kind: Pod
metadata:
  name: $pod_name
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  nodeSelector:
    $label: verified
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: check
    image: $pod_image
    command: ["sh", "-c", "$payload"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: [ALL]
POD
}
cannot_schedule() {
    local pod_name=$1
    kube -n saf-rootless wait --timeout=30s \
      '--for=jsonpath={.status.conditions[?(@.type=="PodScheduled")].reason}=Unschedulable' "pod/$pod_name" >/dev/null
    test -z "$(kube -n saf-rootless get pod "$pod_name" -o 'jsonpath={.spec.nodeName}')"
}
create_workload enrolled
cannot_schedule enrolled
printf 'unlabelled_node_workload_pending=true\n'
first_deadline=$(evidence_deadline)
reconcile "$first_deadline"
kube -n saf-rootless wait --timeout=100s '--for=jsonpath={.status.phase}=Succeeded' pod/enrolled
test "$(kube -n saf-rootless get pod enrolled -o 'jsonpath={.spec.nodeName}')" = "$node"
test "$(kube -n saf-rootless logs pod/enrolled)" = saf-rootless-eligible
printf 'verified_label_workload_succeeded=true\n'

create_workload retained 'sleep 240'
kube -n saf-rootless wait --timeout=30s --for=condition=Ready pod/retained
prior_uid=$(kube -n saf-rootless get pod retained -o 'jsonpath={.metadata.uid}')
test -n "$prior_uid"
stale_deadline=$(($(date -u +%s) - 1))
reconcile "$stale_deadline"
create_workload post-revocation
cannot_schedule post-revocation
printf 'stale_evidence_revoked_new_placement=true\n'
test "$(kube -n saf-rootless get pod retained -o 'jsonpath={.metadata.uid},{.spec.nodeName},{.status.phase}')" = "$prior_uid,$node,Running"
printf 'previous_workload_remained_running=true\n'

renewed_deadline=$(evidence_deadline)
reconcile "$renewed_deadline"
kube -n saf-rootless wait --timeout=45s '--for=jsonpath={.status.phase}=Succeeded' pod/post-revocation
test "$(kube -n saf-rootless logs pod/post-revocation)" = saf-rootless-eligible
printf 'fresh_evidence_restored_pending_placement=true\n'

reconcile ""
create_workload missing-evidence
cannot_schedule missing-evidence
printf 'absent_evidence_revoked_new_placement=true\n'
