#!/usr/bin/env bash
set -euo pipefail
test "$(hostname)" = lima-mounttest
if findmnt -rn -t virtiofs,9p | grep -q .; then exit 41; fi
cd /tmp/saf-cri-candidate
kubectl() { sudo -n /usr/bin/kubectl --kubeconfig /etc/kubernetes/admin.conf "$@"; }
saf_namespace=saf-release-mount-options
kubectl create namespace "$saf_namespace"
saf_cleanup() {
  if kubectl delete namespace "$saf_namespace" --wait=true --timeout=90s; then
    printf '%s\n' 'Fixture namespace cleanup confirmed'
  else
    return 46
  fi
}
trap saf_cleanup EXIT
kubectl label namespace "$saf_namespace" pod-security.kubernetes.io/enforce=restricted
kubectl -n "$saf_namespace" create -f bind-options-pod.yaml
kubectl -n "$saf_namespace" wait --for=jsonpath='{.status.phase}'=Succeeded pod/bind-options --timeout=150s || true
kubectl -n "$saf_namespace" get pod bind-options -o json |
python3 -c '
import json, sys
pod = json.load(sys.stdin)
flags = {c["name"]: c["volumeMounts"][0].get("bindMountOptions", []) for c in pod["spec"]["containers"]}
status = pod["status"]
results = {c["name"]: c["state"].get("terminated", c["state"]) for c in status.get("containerStatuses", [])}
print(json.dumps({"phase":status["phase"], "retainedMountOptions":flags, "termination":results}, indent=2))
assert status["phase"] == "Succeeded", status.get("reason", "workload had not succeeded")
assert set(flags["guarded"]) == {"noexec", "nodev", "nosuid"} and flags["reference"] == []
for arm, other, code in (("guarded","reference","126"),("reference","guarded","0")):
    result = results[arm]
    observed = dict(line.split("=",1) for line in result["message"].splitlines())
    assert result["exitCode"] == 0 and observed["result"] == "ok"
    assert observed["shared_read"] == other and observed["exec_exit"] == code
    effective = set(observed["mount"].split(","))
    if arm == "guarded":
        assert {"noexec","nodev","nosuid"} <= effective and "permission denied" in observed["exec_output"].lower()
    else:
        assert "noexec" not in effective and observed["exec_output"] == "SAF_MOUNT_EXECUTED"
'
saf_cleanup
trap - EXIT
