#!/usr/bin/env bash
# Scratch-only proposal. Run only inside a fresh, explicitly owned Linux VM.
set -Eeuo pipefail
umask 077

fail() { printf 'BLOCKED: %s\n' "$*" >&2; exit 2; }
[[ ${SAF_K8S_0303_007_NATIVE_GUEST:-} == I_OWN_THIS_DISPOSABLE_VM ]] \
  || fail 'explicit disposable guest opt-in is required'
[[ $(id -u) == 0 ]] || fail 'run as root inside the disposable guest'
[[ -r /etc/os-release ]] || fail 'guest OS identity is unavailable'
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == debian && ${VERSION_ID:-} == 13 ]] || fail 'candidate is scoped to Debian 13 ARM64 guest'
[[ $(dpkg --print-architecture) == arm64 ]] || fail 'candidate is scoped to ARM64'
command -v systemd-detect-virt >/dev/null && systemd-detect-virt --vm >/dev/null \
  || fail 'must run inside a VM'
command -v findmnt >/dev/null || fail 'findmnt is required for the no-share check'
[[ -z $(findmnt -rn -t virtiofs,9p 2>/dev/null || true) ]] || fail 'host-shared mounts are prohibited'

for tool in apparmor_parser sha256sum python3 timeout ss findmnt; do
  command -v "$tool" >/dev/null || fail "required guest tool missing: $tool"
done
APPARMOR_PROFILES=/sys/kernel/security/apparmor/profiles
[[ -r /sys/module/apparmor/parameters/enabled ]] \
  && [[ $(cat /sys/module/apparmor/parameters/enabled) == Y ]] \
  || fail 'guest kernel does not report AppArmor enabled'
mountpoint -q /sys/kernel/security || fail 'securityfs is not mounted'
[[ -r /sys/kernel/security/lsm ]] || fail 'active LSM list is unavailable'
case ",$(cat /sys/kernel/security/lsm)," in *,apparmor,*) ;; *) fail 'AppArmor is not active in the guest LSM list' ;; esac
[[ -r $APPARMOR_PROFILES ]] || fail 'AppArmor profile inventory is unavailable'

# Stage the official ARM64 release binary through the guest's authenticated
# file-transfer channel. This script never downloads or executes a mutable URL.
K3S_BIN=${SAF_K3S_BINARY:-$PWD/k3s-arm64}
[[ -f $K3S_BIN && -x $K3S_BIN ]] || fail 'stage executable k3s-arm64 in this directory or set SAF_K3S_BINARY'
K3S_SHA256=49dcecdb4f64f5e92bdc52d204d407fb39729e492f09074488125ee58b6f2895
[[ $(sha256sum "$K3S_BIN" | awk '{print $1}') == "$K3S_SHA256" ]] \
  || fail 'K3s binary digest does not match the official pinned release asset'
K3S_VERSION=$("$K3S_BIN" --version)
[[ $(awk 'NR==1 {print $2,$3}' <<<"$K3S_VERSION") == 'version v1.36.6+k3s1' ]] \
  || fail 'unexpected K3s version'

BUSYBOX_IMAGE=docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
PROFILE_NAME="saf_0303_007_$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
SUFFIX=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
NAMESPACE="saf-aa-${SUFFIX}"
PROFILE_FILE="/run/${PROFILE_NAME}.apparmor"
EVIDENCE="$PWD/SAF-K8S-0303-007-native-${SUFFIX}.json"
[[ ! -e $EVIDENCE ]] || fail 'refusing to overwrite existing evidence'
[[ ! -e /etc/rancher/k3s ]] || fail 'existing K3s configuration detected'
if ss -ltn '( sport = :6443 )' | tail -n +2 | grep -q .; then
  fail 'TCP 6443 is already occupied'
fi
if grep -Eq "^${PROFILE_NAME} \(" "$APPARMOR_PROFILES"; then
  fail 'random profile name unexpectedly exists'
fi
WORK=$(mktemp -d /var/tmp/saf-0303-007-native.XXXXXXXX)
# The extracted runtime and snapshots require pathname traversal for
# the non-root workload. Logs, configuration and kubeconfig retain mode 0600.
chmod 0711 "$WORK"
export K3S_DATA_DIR="$WORK/data"
KUBECONFIG_FILE="$WORK/kubeconfig"
SCRIPT_SHA256=$(sha256sum "$0" | awk '{print $1}')

server_pid=''
profile_loaded=0
namespace_created=0
ready=false
baseline_ok=false
profiled_ok=false
cleanup_ok=false
server_version=''
kubelet_version=''
profile_sha256=''
cleanup() {
  local run_status=$? cleanup_status=0
  trap - EXIT INT TERM HUP
  set +e
  if [[ -n $KUBECONFIG_FILE && -s $KUBECONFIG_FILE && -n $server_pid ]]; then
    if (( namespace_created )); then
      if (( run_status != 0 )); then
        journalctl -k --no-pager -n 250 | grep -E "$PROFILE_NAME|apparmor=\"DENIED\"" |
          tail -n 14 >&2
        "$K3S_BIN" kubectl --kubeconfig "$KUBECONFIG_FILE" --namespace "$NAMESPACE" \
          --request-timeout=8s get pods -o json | python3 -c '
import json,sys
for p in json.load(sys.stdin).get("items",[]):
 s=p.get("status",{})
 print(p["metadata"]["name"],s.get("phase"),[
  {"waiting":c.get("state",{}).get("waiting",{}).get("reason"),
   "terminated":c.get("state",{}).get("terminated",{}).get("reason"),
   "exit_code":c.get("state",{}).get("terminated",{}).get("exitCode")}
   for c in s.get("containerStatuses",[])])' >&2
        "$K3S_BIN" kubectl --kubeconfig "$KUBECONFIG_FILE" --namespace "$NAMESPACE" \
          --request-timeout=8s get events -o json | python3 -c '
import json,sys
for event in json.load(sys.stdin).get("items",[]):
 if event.get("type")=="Warning":
  print(event.get("reason"),event.get("message","")[:280])' >&2
      fi
      "$K3S_BIN" kubectl --kubeconfig "$KUBECONFIG_FILE" delete namespace "$NAMESPACE" \
        --wait=true --timeout=45s >/dev/null 2>&1 || cleanup_status=1
    fi
  fi
  if [[ -n $server_pid ]]; then
    kill -TERM "$server_pid" 2>/dev/null
    for _ in $(seq 1 30); do
      kill -0 "$server_pid" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$server_pid" 2>/dev/null; then
      kill -KILL "$server_pid" 2>/dev/null
      cleanup_status=1
    fi
    wait "$server_pid" 2>/dev/null
    server_pid=''
  fi
  if (( profile_loaded )); then
    apparmor_parser -R "$PROFILE_FILE" >/dev/null 2>&1 || cleanup_status=1
    if grep -Eq "^${PROFILE_NAME} \(" "$APPARMOR_PROFILES"; then cleanup_status=1; fi
  fi
  rm -f -- "$PROFILE_FILE"
  if findmnt -rn -o TARGET | awk -v prefix="$WORK/" 'index($0,prefix)==1 {seen=1} END {exit !seen}'; then
    cleanup_status=1
  else
    rm -rf -- "$WORK" || cleanup_status=1
  fi
  if (( cleanup_status == 0 )); then cleanup_ok=true; else cleanup_ok=false; fi
  python3 - "$EVIDENCE" "$NAMESPACE" "$PROFILE_NAME" "$profile_sha256" \
      "$K3S_SHA256" "$K3S_VERSION" "$BUSYBOX_IMAGE" "$SCRIPT_SHA256" \
      "$server_version" "$kubelet_version" "$ready" \
      "$baseline_ok" "$profiled_ok" "$cleanup_ok" "$(uname -r)" \
      "$(systemd-detect-virt)" "$(dpkg-query -W -f='${Version}' apparmor 2>/dev/null || true)" \
      "$(apparmor_parser --version 2>&1 | head -n 1)" \
      "$(cat /sys/kernel/security/lsm)" <<'PY'
import json,sys
(path,namespace,profile,profile_sha,k3s_sha,k3s_version,image,script_sha,server,kubelet,ready,baseline,profiled,clean,
 kernel,vm_type,apparmor_package,parser_version,lsm)=sys.argv[1:]
obj={"control":"SAF-K8S-0303-007","candidate":"native-AppArmor direct-guest supplement",
 "scope":"one disposable Debian 13 ARM64 Linux guest; one native K3s node; synthetic read-only markers",
 "namespace":namespace,"profile_name":profile,"profile_sha256":profile_sha,
 "k3s_version":k3s_version,"k3s_arm64_sha256":k3s_sha,
 "busybox_image":image,"candidate_script_sha256":script_sha,
 "kubernetes_server_version":server,
 "guest_kernel_release":kernel,"guest_vm_type":vm_type,"active_lsm_list":lsm,
 "apparmor_package_version":apparmor_package,"apparmor_parser_version":parser_version,
 "kubelet_version":kubelet,"api_ready":ready=="true",
 "baseline_allowed_and_denied_marker_reads":baseline=="true",
 "profiled_allowed_read_denied_read_and_enforce_identity":profiled=="true",
 "owned_k3s_and_namespace_cleanup_complete":clean=="true"}
with open(path,"x",encoding="utf-8") as stream:
 json.dump(obj,stream,sort_keys=True,indent=2)
 stream.write("\n")
PY
  if (( run_status != 0 )); then exit "$run_status"; fi
  exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

cat >"$PROFILE_FILE" <<PROFILE
profile ${PROFILE_NAME} flags=(attach_disconnected) {
  /bin/busybox mr,
  /bin/busybox ix,
  /{lib,lib64}/** mr,
  /usr/lib/** mr,
  /etc/ld.so.cache r,
  /dev/console rw,
  /dev/null rw,
  /proc/*/attr/current r,
  /proc/*/attr/apparmor/current r,
  /fixture/allowed r,
  audit deny /fixture/denied r,
}
PROFILE
profile_sha256=$(sha256sum "$PROFILE_FILE" | awk '{print $1}')
apparmor_parser -r -T "$PROFILE_FILE"
profile_loaded=1
grep -Fq "${PROFILE_NAME} (enforce)" "$APPARMOR_PROFILES" \
  || fail 'exact fixture profile did not load in enforce mode'

# This runs K3s as a child process inside this guest. It does not use Docker,
# Kind, a system service, or an existing cluster. All state is under WORK.
(umask 022; exec "$K3S_BIN" server --data-dir "$WORK/data" \
  --write-kubeconfig "$KUBECONFIG_FILE" --write-kubeconfig-mode 0600 \
  --bind-address 127.0.0.1 \
  --disable traefik --disable servicelb --disable metrics-server \
 ) >"$WORK/k3s.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 120); do
  if [[ -s $KUBECONFIG_FILE ]] && "$K3S_BIN" kubectl --kubeconfig "$KUBECONFIG_FILE" \
      get --raw=/readyz >/dev/null 2>&1; then ready=true; break; fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    fail 'owned K3s process exited before API readiness; inspect only the disposable guest locally'
  fi
  sleep 1
done
[[ $ready == true ]] || fail 'owned K3s API did not become ready within 120 seconds'
listeners=$(ss -Hltn '( sport = :6443 )' | awk '{print $4}')
if ! python3 - "$listeners" <<'PY_LISTEN'
import ipaddress,sys
seen = sys.argv[1].splitlines()
if not seen:
    raise SystemExit(1)
for entry in seen:
    address, port = entry.rsplit(":",1)
    try:
        value = ipaddress.ip_address(address.strip("[]").split("%",1)[0])
    except ValueError:
        raise SystemExit(1)
    mapped = getattr(value,"ipv4_mapped",None)
    if port != "6443" or not (value.is_loopback or bool(mapped and mapped.is_loopback)):
        raise SystemExit(1)
PY_LISTEN
then
  printf 'Observed TCP 6443 listener fields: %q\n' "$listeners" >&2
  fail 'K3s API listener is not restricted to guest loopback'
fi
kubectl() { "$K3S_BIN" kubectl --kubeconfig "$KUBECONFIG_FILE" --request-timeout=20s "$@"; }
server_version=$(kubectl version -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["serverVersion"]["gitVersion"])')
[[ $server_version == v1.36.6+k3s1 ]] || fail 'unexpected Kubernetes server version'
node_count=0
for _ in $(seq 1 60); do
  node_count=$(kubectl get nodes -o json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["items"]))')
  [[ $node_count == 0 ]] || break
  sleep 1
done
[[ $node_count == 1 ]] || fail 'expected one direct guest node'
kubectl wait --for=condition=Ready node --all --timeout=90s >/dev/null
node_name=$(kubectl get nodes -o=jsonpath='{.items[0].metadata.name}')
kubelet_version=$(kubectl get node "$node_name" -o=jsonpath='{.status.nodeInfo.kubeletVersion}')
[[ $kubelet_version == v1.36.6+k3s1 ]] || fail 'unexpected guest kubelet version'
[[ $(kubectl get node "$node_name" -o=jsonpath='{.status.nodeInfo.kernelVersion}') == "$(uname -r)" ]] \
  || fail 'Kubernetes node kernel does not match the executing guest kernel'

# Pull only the repository fixture's immutable BusyBox ARM64 digest into this
# direct guest's embedded containerd; no workload or image build is involved.
"$K3S_BIN" ctr --namespace k8s.io images pull --platform linux/arm64 "$BUSYBOX_IMAGE" \
  >"$WORK/image-pull.log" 2>&1 || fail 'pinned fixture image pull failed'

kubectl create namespace "$NAMESPACE" >/dev/null
namespace_created=1
kubectl label namespace "$NAMESPACE" pod-security.kubernetes.io/enforce=restricted >/dev/null
python3 - "$NAMESPACE" "$PROFILE_NAME" "$BUSYBOX_IMAGE" >"$WORK/objects.jsonl" <<'PY'
import json,sys
ns,profile,image=sys.argv[1:]
cm={"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"markers","namespace":ns},
 "immutable":True,"data":{"allowed":"fixed harmless allowed marker","denied":"fixed harmless denied marker"}}
script=r'''set -eu
if [ "$MODE" = baseline ]; then
  test "$(/bin/busybox cat /fixture/allowed)" = 'fixed harmless allowed marker'
  test "$(/bin/busybox cat /fixture/denied)" = 'fixed harmless denied marker'
  printf 'BASELINE_ALLOWED_READ=true\nBASELINE_DENIED_READ=true\n'
else
  test "$(/bin/busybox cat /fixture/allowed)" = 'fixed harmless allowed marker'
  if /bin/busybox cat /fixture/denied >/dev/null 2>&1; then exit 42; fi
  current=$(/bin/busybox cat /proc/self/attr/current)
  test "$current" = "$PROFILE_NAME (enforce)"
  printf 'PROFILE_ALLOWED_READ=true\nPROFILE_DENIED_READ=true\nPROFILE_IDENTITY=true\n'
fi'''
for name,mode in (("baseline","baseline"),("enforced","enforced")):
 c={"name":"probe","image":image,"imagePullPolicy":"IfNotPresent",
  "command":["/bin/busybox","sh","-ec",script],
  "env":[{"name":"MODE","value":mode},{"name":"PROFILE_NAME","value":profile}],
  "securityContext":{"runAsNonRoot":True,"runAsUser":65534,"allowPrivilegeEscalation":False,
    "readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]},
    "seccompProfile":{"type":"RuntimeDefault"}},
  "resources":{"requests":{"cpu":"5m","memory":"16Mi"},"limits":{"cpu":"100m","memory":"64Mi"}},
  "volumeMounts":[{"name":"markers","mountPath":"/fixture/"+item,"subPath":item,"readOnly":True}
                  for item in ("allowed","denied")]}
 if mode=="enforced":
  c["securityContext"]["appArmorProfile"]={"type":"Localhost","localhostProfile":profile}
 pod={"apiVersion":"v1","kind":"Pod","metadata":{"name":name,"namespace":ns},
  "spec":{"restartPolicy":"Never","automountServiceAccountToken":False,
   "securityContext":{"runAsNonRoot":True,"runAsUser":65534,"seccompProfile":{"type":"RuntimeDefault"}},
   "containers":[c],"volumes":[{"name":"markers","configMap":{"name":"markers"}}]}}
 print(json.dumps(cm if name=="baseline" else pod,separators=(",",":")))
 if name=="baseline": print(json.dumps(pod,separators=(",",":")))
PY
# The Python generator emits ConfigMap, baseline Pod and enforced Pod. Apply each
# record separately so a failure cannot create an unintended object set.
python3 - "$WORK/objects.jsonl" <<'PY' | while IFS= read -r obj; do kubectl create -f - <<<"$obj" >/dev/null; done
import sys
for line in open(sys.argv[1],encoding="utf-8"):
 print(line.rstrip("\n"))
PY
wait_for_success() {
  local pod=$1 phase
  for _ in $(seq 1 90); do
    phase=$(kubectl get pod "$pod" --namespace "$NAMESPACE" -o=jsonpath='{.status.phase}')
    case "$phase" in
      Succeeded) return 0 ;;
      Failed) fail "comparison Pod failed before its success receipt: $pod" ;;
    esac
    sleep 1
  done
  fail "comparison Pod did not complete: $pod"
}
wait_for_success baseline
baseline_log=$(kubectl logs pod/baseline --namespace "$NAMESPACE")
grep -Fxq 'BASELINE_ALLOWED_READ=true' <<<"$baseline_log" || fail 'baseline allowed read failed'
grep -Fxq 'BASELINE_DENIED_READ=true' <<<"$baseline_log" || fail 'baseline comparison read failed'
baseline_ok=true
wait_for_success enforced
profiled_log=$(kubectl logs pod/enforced --namespace "$NAMESPACE")
for expected in PROFILE_ALLOWED_READ=true PROFILE_DENIED_READ=true PROFILE_IDENTITY=true; do
  grep -Fxq "$expected" <<<"$profiled_log" || fail "native profile observation missing: $expected"
done
actual_profile=$(kubectl get pod enforced --namespace "$NAMESPACE" -o=jsonpath='{.spec.containers[0].securityContext.appArmorProfile.localhostProfile}')
[[ $actual_profile == "$PROFILE_NAME" ]] || fail 'API object does not retain the exact Localhost profile binding'
profiled_ok=true
printf 'NATIVE_APPARMOR_BASELINE_AND_ENFORCED_READS=true\n'
