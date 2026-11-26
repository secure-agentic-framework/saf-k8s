#!/usr/bin/env bash
# Run only inside the dedicated disposable Linux guest, with one owned LUKS mapper mounted.
set -Eeuo pipefail
umask 077
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
test "${SAF_K8S_0701_003_DISPOSABLE_GUEST:-}" = I_OWN_THIS_DISPOSABLE_VM || die 'dedicated guest opt-in required'
test "$(id -u)" = 0 || die 'root required inside the disposable guest'
test -z "$(findmnt -rn -t virtiofs,9p || true)" || die 'the VM must have no mounted host shares'
phase=${1:?phase must be write or reopen}
work=${2:?owned work directory required}
disk_mount=${3:?mounted LUKS directory required}
arm=${4:?independent arm label required}
[[ "$phase" == write || "$phase" == reopen ]] || die 'unsupported phase'
[[ "$arm" == arm-a || "$arm" == arm-b ]] || die 'unsupported independent arm label'
[[ "$work" =~ ^/var/tmp/saf-k8s-0701-003\.[A-Za-z0-9]+$ ]] || die 'unexpected owned work path'
test "$disk_mount" = "$work/mount" || die 'unexpected mapper mount path'
for cmd in docker kind kubectl openssl python3 findmnt realpath; do command -v "$cmd" >/dev/null || die "required guest command missing: $cmd"; done
source=$(findmnt -n -o SOURCE --mountpoint "$disk_mount")
[[ "$source" == /dev/mapper/saf-crypt-* ]] || die 'Qdrant host path is not under the expected LUKS mapper'

QDRANT_IMAGE='docker.io/qdrant/qdrant:v1.20.2-unprivileged@sha256:3bbf3b2673892bc593c300c402462332dd9d06e42096dc48b48907ecff287c5a'
QDRANT_LOCAL='saf-k8s-fixture/qdrant:1.20.2-3bbf3b267389'
PYTHON_IMAGE='docker.io/library/python:3.13.2-alpine'
QDRANT_HOST_PATH='/var/local-path-provisioner/qdrant-pv'
QDRANT_GUEST_PATH="$disk_mount/provisioner/qdrant-pv"
SC='saf-qdrant-guest-luks'
PV='saf-qdrant-guest-luks-pv'
PVC='fixture-qdrant-luks-data'
QDRANT='fixture-qdrant-live'
SERVICE='fixture-qdrant-tls'
COLLECTION='fixture-transport-synthetic'
MARKER='synthetic-cedar-v1'

if [[ "$phase" == write ]]; then
  install -d -o 1000 -g 1000 -m 0750 "$QDRANT_GUEST_PATH"
  test -z "$(find "$QDRANT_GUEST_PATH" -mindepth 1 -maxdepth 1 -print -quit)" || die 'write-phase Qdrant directory is not empty'
else
  test -d "$QDRANT_GUEST_PATH" || die 'reopen-phase Qdrant directory is missing'
  test -n "$(find "$QDRANT_GUEST_PATH" -mindepth 1 -maxdepth 1 -print -quit)" || die 'reopen-phase Qdrant storage is empty'
fi
[[ "$(realpath "$QDRANT_GUEST_PATH")" == "$QDRANT_GUEST_PATH" ]] || die 'Qdrant backing path is not canonical'

# Use the official unprivileged ARM64 artifact for the same Qdrant release.
# Verify the pinned image platform and image ID before loading into Kind.
if ! docker image inspect "$QDRANT_IMAGE" >/dev/null 2>&1; then docker pull "$QDRANT_IMAGE"; fi
qdrant_id=$(docker image inspect --format '{{.Id}}' "$QDRANT_IMAGE")
test -n "$qdrant_id" || die 'pinned Qdrant image is unavailable'
test "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$QDRANT_IMAGE")" = linux/arm64 \
  || die 'the pinned Qdrant image must execute natively in the ARM64 guest'
docker image tag "$QDRANT_IMAGE" "$QDRANT_LOCAL"
test "$(docker image inspect --format '{{.Id}}' "$QDRANT_LOCAL")" = "$qdrant_id" || die 'local Qdrant tag differs from pinned image'
qdrant_image_pin_verified=true

# Match the same architecture-specific Python 3.13.2 Alpine fixture loader used
# by SAF-K8S-0908-001/0909-010.
arch=$(docker info --format '{{.Architecture}}')
case "$arch" in
  aarch64|arm64) python_digest='91f983b2a023903433f6227b6c6056cedda4a335f1348d4ffbede021ab11602b' ;;
  x86_64|amd64) python_digest='8a34ebceda7d48c11d6ec7f322807032f1f152ef121ea7f628cbd72643affd57' ;;
  *) die 'no pinned Python fixture image matches guest Docker architecture' ;;
esac
python_ref="$PYTHON_IMAGE@sha256:$python_digest"
python_local="saf-k8s-fixture/python:3.13.2-${python_digest:0:12}"
if ! docker image inspect "$python_ref" >/dev/null 2>&1; then docker pull "$python_ref"; fi
python_id=$(docker image inspect --format '{{.Id}}' "$python_ref")
test -n "$python_id" || die 'pinned Python image is unavailable'
docker image tag "$python_ref" "$python_local"
test "$(docker image inspect --format '{{.Id}}' "$python_local")" = "$python_id" || die 'local Python tag differs from pinned image'
fixture_image_pin_verified=true

unset DOCKER_HOST DOCKER_CONTEXT
export KIND_EXPERIMENTAL_PROVIDER=docker
test "$(docker context inspect default --format '{{.Endpoints.docker.Host}}')" = unix:///var/run/docker.sock || die 'unexpected Docker endpoint'
cluster="saf-qdrant-${phase}-$(openssl rand -hex 6)"
config="$work/qdrant-${phase}-kind.yaml"
kubeconfig="$work/qdrant-${phase}.kubeconfig"
phase_dir="$work/qdrant-$phase"
cat > "$config" <<EOF_CONFIG
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: $disk_mount/provisioner
        containerPath: /var/local-path-provisioner
EOF_CONFIG
if kind get clusters | grep -Fxq "$cluster"; then die 'fresh Qdrant cluster name is already in use'; fi
cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  if kind get clusters | grep -Fxq "$cluster"; then
    kind delete cluster --name "$cluster" --kubeconfig "$kubeconfig" >/dev/null || status=1
  fi
  if kind get clusters | grep -Fxq "$cluster"; then
    printf 'ERROR: owned Qdrant cluster remains: %s\n' "$cluster" >&2
    status=1
  fi
  rm -rf -- "$work/qdrant-$phase"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
kind create cluster --name "$cluster" --kubeconfig "$kubeconfig" --config "$config" --wait 120s \
  --image kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5
kube() { kubectl --kubeconfig "$kubeconfig" --context "kind-$cluster" "$@"; }
create_immutable_configmap() {
  kube -n saf-test create configmap "$@" --dry-run=client -o json |
    python3 -c 'import json,sys; resource=json.load(sys.stdin); resource["immutable"]=True; json.dump(resource,sys.stdout)' |
    kube -n saf-test create -f - -o name >/dev/null
}
kind load docker-image "$QDRANT_LOCAL" --name "$cluster"
kind load docker-image "$python_local" --name "$cluster"
version=$(kube get --raw /version | python3 -c 'import json,sys; print(json.load(sys.stdin)["gitVersion"])')
test "$version" = v1.36.1 || die 'unexpected Kubernetes version in Qdrant guest cluster'
kubernetes_version_verified=true
node="${cluster}-control-plane"
node_mounts=$(docker inspect "$node" --format '{{json .Mounts}}')
python3 - "$disk_mount/provisioner" "$node_mounts" <<'PY_MOUNT'
import json,os,sys
expected=os.path.realpath(sys.argv[1])
mounts=json.loads(sys.argv[2])
assert any(os.path.realpath(item.get("Source","")) == expected
           and item.get("Destination") == "/var/local-path-provisioner"
           and item.get("RW") is True for item in mounts)
PY_MOUNT
kind_node_mount_verified=true
docker exec "$node" test -d "$QDRANT_HOST_PATH" || die 'the owned Kind node cannot see the mounted Qdrant directory'
kube create namespace saf-test >/dev/null

# This is a static PV, not a dynamically allocated local-path volume. The same
# guest path is bound afresh in each cluster phase and is never deleted here.
kube apply -f - >/dev/null <<EOF_PV
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: $SC
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: Immediate
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: $PV
spec:
  capacity:
    storage: 1Gi
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: $SC
  hostPath:
    path: $QDRANT_HOST_PATH
    type: Directory
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values:
                - $node
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $PVC
  namespace: saf-test
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: $SC
  volumeName: $PV
  resources:
    requests:
      storage: 1Gi
EOF_PV
kube -n saf-test wait --for=jsonpath='{.status.phase}'=Bound "pvc/$PVC" --timeout=120s
claim_json=$(kube -n saf-test get pvc "$PVC" -o json)
pv_json=$(kube get pv "$PV" -o json)
claim_uid=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["metadata"]["uid"])' <<<"$claim_json")
test "$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["spec"]["volumeName"])' <<<"$claim_json")" = "$PV" || die 'PVC did not bind to the exact Qdrant PV'
test "$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["spec"]["hostPath"]["path"])' <<<"$pv_json")" = "$QDRANT_HOST_PATH" || die 'Qdrant PV hostPath differs from the reviewed encrypted mount'
test "$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["spec"]["claimRef"]["uid"])' <<<"$pv_json")" = "$claim_uid" || die 'PV claim reference UID does not match the Qdrant claim'
test "$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"][0]["values"][0])' <<<"$pv_json")" = "$node" || die 'PV node affinity does not bind to this fresh cluster node'

install -d -m 0700 "$phase_dir"
cert="$phase_dir/tls.crt"
private_key="$phase_dir/tls.key"
api_key="$phase_dir/api-key"
openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
  -subj "/CN=$SERVICE.saf-test.svc" \
  -addext "subjectAltName=DNS:$SERVICE.saf-test.svc" \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign' \
  -keyout "$private_key" -out "$cert" >/dev/null 2>&1
chmod 0600 "$private_key"
openssl rand -hex 32 > "$api_key"
chmod 0600 "$api_key"
kube -n saf-test create secret tls fixture-qdrant-transport-tls \
  --cert="$cert" --key="$private_key" -o name >/dev/null
kube -n saf-test create secret generic fixture-qdrant-transport-key \
  --from-file=api-key="$api_key" -o name >/dev/null
create_immutable_configmap fixture-qdrant-transport-trust \
  --from-file=ca.crt="$cert"
cp "$(dirname "$0")/transport_fixture.py" "$phase_dir/transport_fixture.py"
cat > "$phase_dir/config.yaml" <<'EOF_CONFIGMAP'
telemetry_disabled: true
service:
  host: 0.0.0.0
  http_port: 6333
  grpc_port: null
  enable_tls: true
  jwt_rbac: false
  enable_cors: false
tls:
  cert: /tls/tls.crt
  key: /tls/tls.key
storage:
  storage_path: /qdrant/storage
  snapshots_path: /qdrant/snapshots
EOF_CONFIGMAP
create_immutable_configmap fixture-qdrant-transport-config \
  --from-file=config.yaml="$phase_dir/config.yaml"

qdrant_pod="$phase_dir/qdrant-pod.yaml"
cat > "$qdrant_pod" <<EOF_QDRANT
apiVersion: v1
kind: Pod
metadata:
  name: $QDRANT
  namespace: saf-test
  labels:
    app: $QDRANT
spec:
  restartPolicy: Always
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: qdrant
      image: $QDRANT_LOCAL
      imagePullPolicy: Never
      command:
        - /bin/sh
        - -ec
        - export QDRANT__SERVICE__API_KEY="\$(cat /run/key/api-key)"; exec /qdrant/qdrant --config-path /etc/qdrant/config.yaml
      ports:
        - name: https
          containerPort: 6333
      readinessProbe:
        tcpSocket:
          port: 6333
        periodSeconds: 2
        failureThreshold: 60
      volumeMounts:
        - name: config
          mountPath: /etc/qdrant
          readOnly: true
        - name: tls
          mountPath: /tls
          readOnly: true
        - name: key
          mountPath: /run/key
          readOnly: true
        - name: data
          mountPath: /qdrant/storage
        - name: snapshots
          mountPath: /qdrant/snapshots
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
      resources:
        requests:
          cpu: 100m
          memory: 128Mi
        limits:
          cpu: "1"
          memory: 512Mi
  volumes:
    - name: config
      configMap:
        name: fixture-qdrant-transport-config
    - name: tls
      secret:
        secretName: fixture-qdrant-transport-tls
        defaultMode: 0440
    - name: key
      secret:
        secretName: fixture-qdrant-transport-key
        defaultMode: 0440
    - name: data
      persistentVolumeClaim:
        claimName: $PVC
    - name: snapshots
      emptyDir:
        medium: Memory
EOF_QDRANT
kube -n saf-test apply -f - >/dev/null <<EOF_SERVICE
apiVersion: v1
kind: Service
metadata:
  name: $SERVICE
  namespace: saf-test
spec:
  selector:
    app: $QDRANT
  ports:
    - name: https
      port: 6333
      targetPort: 6333
EOF_SERVICE
kube -n saf-test apply -f "$qdrant_pod" >/dev/null
if ! kube -n saf-test wait --for=condition=Ready "pod/$QDRANT" --timeout=90s; then
  kube -n saf-test get pod "$QDRANT" -o 'jsonpath={.status.containerStatuses[*].state}'
  die 'Qdrant fixture failed readiness'
fi
create_immutable_configmap fixture-qdrant-transport-code \
  --from-file=transport_fixture.py="$phase_dir/transport_fixture.py"
kube -n saf-test apply -f - >/dev/null <<EOF_CLIENT
apiVersion: v1
kind: Pod
metadata:
  name: fixture-qdrant-pv-client
  namespace: saf-test
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: client
      image: $python_local
      imagePullPolicy: Never
      command: ["sleep", "3600"]
      volumeMounts:
        - name: code
          mountPath: /fixture
          readOnly: true
        - name: trust
          mountPath: /trust
          readOnly: true
        - name: key
          mountPath: /identity
          readOnly: true
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
      resources:
        requests:
          cpu: 10m
          memory: 32Mi
        limits:
          cpu: 200m
          memory: 128Mi
  volumes:
    - name: code
      configMap:
        name: fixture-qdrant-transport-code
    - name: trust
      configMap:
        name: fixture-qdrant-transport-trust
    - name: key
      secret:
        secretName: fixture-qdrant-transport-key
        items:
          - key: api-key
            path: api-key
        defaultMode: 0440
EOF_CLIENT
kube -n saf-test wait --for=condition=Ready pod/fixture-qdrant-pv-client --timeout=120s
client_call() {
  kube -n saf-test exec pod/fixture-qdrant-pv-client -c client -- python /fixture/transport_fixture.py \
    "$1" "$SERVICE.saf-test.svc" "$COLLECTION"
}
if [[ "$phase" == write ]]; then
  init=$(client_call initialize)
  python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); assert d.get("write_and_read_ok") is True and d.get("tls_verified") is True and d.get("hostname_verified") is True' <<<"$init" || die 'Qdrant marker write/read failed over verified TLS'
  kube -n saf-test delete pod "$QDRANT" --wait=true >/dev/null
  kube -n saf-test apply -f "$qdrant_pod" >/dev/null
  if ! kube -n saf-test wait --for=condition=Ready "pod/$QDRANT" --timeout=90s; then
  kube -n saf-test get pod "$QDRANT" -o 'jsonpath={.status.containerStatuses[*].state}'
  die 'Qdrant fixture failed readiness'
fi
  recreated=$(client_call recover)
  python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); assert d.get("recovered") is True and d.get("marker") == "synthetic-cedar-v1"' <<<"$recreated" || die 'Qdrant Pod recreation did not read the exact marker'
  qdrant_pod_recreation=true
  qdrant_write_read=true
  post_reopen_exact_marker_read=null
else
  recovered=$(client_call recover)
  python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); assert d.get("recovered") is True and d.get("marker") == "synthetic-cedar-v1"' <<<"$recovered" || die 'fresh Qdrant cluster did not read the persisted exact marker'
  qdrant_pod_recreation=null
  qdrant_write_read=null
  post_reopen_exact_marker_read=true
fi

# Drop the disposable client namespace and every pod before deleting the cluster.
kube delete namespace saf-test --wait=true --timeout=90s >/dev/null
cleanup_cluster() {
  local status=$?
  trap - EXIT INT TERM HUP
  if kind get clusters | grep -Fxq "$cluster"; then
    kind delete cluster --name "$cluster" --kubeconfig "$kubeconfig" >/dev/null || status=1
  fi
  if kind get clusters | grep -Fxq "$cluster"; then status=1; fi
  if (( status == 0 )); then
    python3 - "$arm" "$phase" "$qdrant_write_read" "$qdrant_pod_recreation" "$post_reopen_exact_marker_read" <<'PY_RECEIPT'
import json,sys
arm,phase,write_read,pod_recreation,post_reopen=sys.argv[1:]
def flag(value):
    return None if value == "null" else value == "true"
checks={
 "kind_cluster_deleted": True,
 "pinned_qdrant_image_verified": True,
 "pinned_fixture_image_verified": True,
 "kubernetes_v1_36_1_verified": True,
 "kind_node_mount_matches_luks_host_path": True,
 "static_pv_path_matches_guest_luks_mount": True,
 "claim_and_pv_uid_match": True,
 "qdrant_tls_marker_write_read": flag(write_read),
 "qdrant_pod_recreation_exact_read": flag(pod_recreation),
 "post_reopen_exact_marker_read": flag(post_reopen),
}
print(json.dumps({"arm":arm,"phase":phase,"checks":checks},sort_keys=True))
PY_RECEIPT
  fi
  rm -rf -- "$phase_dir"
  exit "$status"
}
trap - EXIT
trap cleanup_cluster EXIT
