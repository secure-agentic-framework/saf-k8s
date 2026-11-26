#!/usr/bin/env bash
# Run as root only in the dedicated Linux guest used by guest-fixture.sh.
set -Eeuo pipefail
test "${SAF_K8S_0701_003_DISPOSABLE_GUEST:-}" = I_OWN_THIS_DISPOSABLE_VM
test "$(id -u)" = 0
test -z "$(findmnt -rn -t virtiofs,9p || true)"
work=$1
disk_mount=$2
[[ "$work" =~ ^/var/tmp/saf-k8s-0701-003\.[A-Za-z0-9]+$ ]]
test "$disk_mount" = "$work/mount"
source=$(findmnt -n -o SOURCE --mountpoint "$disk_mount")
[[ "$source" == /dev/mapper/saf-crypt-* ]]
kind_bin=$(command -v kind)
kubectl_bin=$(command -v kubectl)
unset DOCKER_HOST DOCKER_CONTEXT
test "$(docker context inspect default --format '{{.Endpoints.docker.Host}}')" = unix:///var/run/docker.sock
cluster="saf-crypt-$(openssl rand -hex 6)"
config="$work/kind.yaml"
export KUBECONFIG="$work/kubeconfig"
export KIND_EXPERIMENTAL_PROVIDER=docker
storage="$disk_mount/provisioner"
install -d -m 0755 "$storage"
cat > "$config" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: $storage
        containerPath: /var/local-path-provisioner
EOF
teardown_cluster() {
  "$kind_bin" delete cluster --name "$cluster" --kubeconfig "$KUBECONFIG" >/dev/null
  if "$kind_bin" get clusters | grep -Fxq "$cluster"; then
    printf '%s\n' 'Could not verify removal of the owned kind cluster' >&2
    return 1
  fi
}
trap teardown_cluster EXIT
"$kind_bin" create cluster --name "$cluster" --kubeconfig "$KUBECONFIG" --config "$config" --wait 120s \
    --image kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5
kube() { "$kubectl_bin" --kubeconfig "$KUBECONFIG" --context "kind-$cluster" "$@"; }

printf 'PV_PROBE_KUBERNETES=%s\n' "$(kube get --raw /version | python3 -c 'import json,sys;print(json.load(sys.stdin)["gitVersion"])')"
kube create namespace saf-encrypted-volume
kube apply -f - <<'YAML'
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: saf-luks-retain
provisioner: rancher.io/local-path
reclaimPolicy: Retain
volumeBindingMode: WaitForFirstConsumer
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: fixture-storage
  namespace: saf-encrypted-volume
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: saf-luks-retain
  resources:
    requests:
      storage: 8Mi
---
apiVersion: v1
kind: Pod
metadata:
  name: synthetic-writer
  namespace: saf-encrypted-volume
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: writer
      image: docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
      command:
        - /bin/sh
        - -ec
        - |
          printf '%s\n' 'SAF synthetic Kubernetes PV marker on encrypted backing' > /fixture/pod-marker.txt
          test "$(cat /fixture/pod-marker.txt)" = 'SAF synthetic Kubernetes PV marker on encrypted backing'
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
        seccompProfile:
          type: RuntimeDefault
      volumeMounts:
        - name: disk
          mountPath: /fixture
  volumes:
    - name: disk
      persistentVolumeClaim:
        claimName: fixture-storage
YAML
kube -n saf-encrypted-volume wait --for=jsonpath='{.status.phase}'=Succeeded pod/synthetic-writer --timeout=120s
volume=$(kube -n saf-encrypted-volume get pvc fixture-storage -o jsonpath='{.spec.volumeName}')
[[ "$volume" =~ ^pvc-[0-9a-f-]+$ ]]
uid=$(kube -n saf-encrypted-volume get pvc fixture-storage -o jsonpath='{.metadata.uid}')
test "$uid" = "$(kube get pv "$volume" -o jsonpath='{.spec.claimRef.uid}')"
path=$(kube get pv "$volume" -o jsonpath='{.spec.hostPath.path}')
leaf="${volume}_saf-encrypted-volume_fixture-storage"
test "$path" = "/var/local-path-provisioner/$leaf"
test "$(cat "$storage/$leaf/pod-marker.txt")" = 'SAF synthetic Kubernetes PV marker on encrypted backing'
printf 'PV_PROBE_BOUND_AND_POD_WRITTEN=true\n'
printf '%s\n' "provisioner/$leaf/pod-marker.txt" > "$work/pv-relative-path"
teardown_cluster
trap - EXIT
printf 'PV_PROBE_CLUSTER_DELETED=true\n'
