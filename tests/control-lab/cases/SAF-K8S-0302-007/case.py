"""Check an exact group and synthetic-storage admission boundary."""
import json
from pathlib import Path
import re
import time

from fixtures import container, pod, ready

HERE = Path(__file__).parent
NAMESPACE = "saf-test"
APPROVED_CLAIM = "saf-0302-007-private"
COMPARISON_CLAIM = "saf-0302-007-comparison-own"
COMPARISON_POD = "saf-0302-007-group-comparison"
COMPARISON_LABEL = "saf-k8s.example/fixture-comparison"
COMPARISON_PATH = "/var/local/saf-0302-007-owned-comparison"
MARKER = "benign marker for SAF-K8S-0302-007"
LOCAL_PATH = "/var/local/saf-0302-007-fixture"
DENIALS = (
    "Pod groups must match an approved fixture identity",
    "Only the named workload storage and protected ConfigMap volumes are allowed",
    "Containers may mount only /fixture-data writable and /protected-data read-only",
)
SCOPE = (
    "Synthetic admission and real nonprivileged Linux process group and storage checks. "
    "Two local PVC mounting identities compare owned file permissions on a deliberately shared writable test claim. "
    "The selected comparison Pod uses supplemental groups without fsGroup to avoid changing shared ownership."
)


def workload(name, *, fs_group=2000, supplemental_groups=None,
             writable_path="/fixture-data", host_path=False, claim=None):
    security = {
        "runAsNonRoot": True,
        "runAsUser": 10001,
        "runAsGroup": 10001,
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    mounts = [
        {"name": "benign-data", "mountPath": writable_path},
        {"name": "protected-data", "mountPath": "/protected-data", "readOnly": True},
    ]
    regular = container("probe", command=["sh", "-c", "sleep 3600"],
                        securityContext=security, volumeMounts=mounts)
    peer = container("peer", command=["sh", "-c", "sleep 3600"],
                     securityContext=security, volumeMounts=mounts)
    volumes = [
        {"name": "benign-data", "emptyDir": {}},
        {"name": "protected-data", "configMap": {"name": "saf-0302-007-protected"}},
    ]
    if host_path:
        # API-server dry-run only. This path is never mounted or looked up on a node.
        volumes[0] = {"name": "benign-data", "hostPath": {
            "path": "/saf-k8s-synthetic-hostpath-probe", "type": "Directory"}}
    if claim:
        volumes[0] = {"name": "benign-data", "persistentVolumeClaim": {"claimName": claim}}
    security_context = {"fsGroup": fs_group, "supplementalGroupsPolicy": "Strict"}
    security_context["supplementalGroups"] = [3000] if supplemental_groups is None else supplemental_groups
    obj = pod(name, [regular, peer], volumes=volumes, securityContext=security_context,
              automountServiceAccountToken=False)
    obj["metadata"]["namespace"] = NAMESPACE
    return obj


def server_dry_run(lab, obj):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(obj), allow_failure=True)


def denied(result, message):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and message in result.stderr)


def observe_identity_and_storage(lab, name):
    script = r'''set -eu
uid=$(id -u)
groups=$(id -G)
fixture_gid=$(stat -c %g /fixture-data)
test "$uid" = 10001
case " $groups " in *" 2000 "*) ;; *) exit 20;; esac
case " $groups " in *" 3000 "*) ;; *) exit 21;; esac
test "$fixture_gid" = 2000
printf '%s\n' 'benign marker for SAF-K8S-0302-007' > /fixture-data/allowed.txt
test "$(cat /fixture-data/allowed.txt)" = 'benign marker for SAF-K8S-0302-007'
test "$(cat /protected-data/sentinel.txt)" = 'synthetic protected fixture'
if touch /protected-data/forbidden-write.txt 2>/dev/null; then exit 22; fi
test ! -e /protected-data/forbidden-write.txt
printf 'uid=%s groups=%s fixture_gid=%s writable=ok protected_write=denied sentinel=unchanged\n' \
  "$uid" "$(printf '%s' "$groups" | tr ' ' ',')" "$fixture_gid"
'''
    return lab.kubectl("exec", name, "-c", "probe", "--",
                       "sh", "-c", script).stdout.strip()


def provision_private_volume(lab, name=APPROVED_CLAIM, path=LOCAL_PATH, group=0):
    node = f"{lab.cluster}-control-plane"
    lab.command("docker", "exec", node, "sh", "-ceu",
                'mkdir -m 0770 -p "$1"; chown "0:$2" "$1"', "fixture-local-volume", path, str(group))
    pv = {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": name},
          "spec": {"storageClassName": "", "capacity": {"storage": "16Mi"},
                   "accessModes": ["ReadWriteOnce"], "persistentVolumeReclaimPolicy": "Retain",
                   "claimRef": {"namespace": NAMESPACE, "name": name},
                   "local": {"path": path}, "nodeAffinity": {"required": {"nodeSelectorTerms": [
                       {"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In",
                                              "values": [node]}]}]}}}}
    pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
           "metadata": {"name": name, "namespace": NAMESPACE},
           "spec": {"storageClassName": "", "volumeName": name,
                    "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "16Mi"}}}}
    for resource in (pv, pvc):
        lab.create(resource)
    lab.kubectl("wait", f"pvc/{name}", "--for=jsonpath={.status.phase}=Bound",
                "--timeout=30s", timeout=40)


def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s.example/group-storage-fixture=enforced", "--overwrite")
    lab.kubectl("create", "configmap", "saf-0302-007-protected",
                "--from-literal=sentinel.txt=synthetic protected fixture")

    probes = [
        ("out-of-set fsGroup", workload("saf-0302-007-bad-fsgroup", fs_group=0), DENIALS[0]),
        ("out-of-set supplementalGroups", workload(
            "saf-0302-007-bad-supplemental", supplemental_groups=[3000, 4000]), DENIALS[0]),
        ("forbidden mount path", workload(
            "saf-0302-007-bad-mount", writable_path="/etc"), DENIALS[2]),
        ("host-backed volume source", workload(
            "saf-0302-007-hostpath", host_path=True), DENIALS[1]),
        ("unapproved PVC reference", workload(
            "saf-0302-007-bad-pvc", supplemental_groups=[3000], claim="unapproved-data"), DENIALS[1]),
    ]
    for label, obj, _ in probes:
        result = server_dry_run(lab, obj)
        lab.check("red", f"API accepts inert {label} probe before policy",
                  result.returncode == 0,
                  result.stderr.strip() or "server dry-run accepted; no Pod persisted")

    compliant = workload("saf-0302-007-groups", supplemental_groups=[3000])
    before = server_dry_run(lab, compliant)
    lab.check("red", "API accepts exact approved group and mount values before policy",
              before.returncode == 0, before.stderr.strip() or "server dry-run accepted")

    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        first = server_dry_run(lab, probes[0][1])
        if denied(first, DENIALS[0]) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "Policy rejects unsafe fsGroup with its exact reason",
              denied(first, DENIALS[0]), first.stderr.strip())

    for label, obj, message in probes[1:]:
        result = server_dry_run(lab, obj)
        lab.check("green", f"Policy rejects {label} with its exact reason",
                  denied(result, message), result.stderr.strip())

    provision_private_volume(lab)
    persistent = workload("saf-0302-007-persistent", supplemental_groups=[3000], claim=APPROVED_CLAIM)
    for fixture in (compliant, persistent):
        name = fixture["metadata"]["name"]
        allowed = server_dry_run(lab, fixture)
        lab.check("positive", f"Policy admits the approved groups and named mounts for {name}",
                  allowed.returncode == 0, allowed.stderr.strip() or "server dry-run admitted")
        lab.create(fixture)
        ready(lab, name)
        observed = observe_identity_and_storage(lab, name)
        shared_read = lab.kubectl("exec", name, "-c", "peer", "--",
                                  "cat", "/fixture-data/allowed.txt").stdout.strip()
        groups_match = re.search(r"\bgroups=([^ ]+)", observed)
        groups = set(groups_match.group(1).split(",")) if groups_match else set()
        lab.check("positive", f"Exact nonroot groups and scoped shared writes for {name}",
                  "uid=10001" in observed and groups == {"10001", "2000", "3000"}
                  and "fixture_gid=2000" in observed and "writable=ok" in observed
                  and "protected_write=denied" in observed and "sentinel=unchanged" in observed
                  and shared_read == "benign marker for SAF-K8S-0302-007",
                  f"{observed} peer_shared_read={shared_read!r}")

    compare_groups(lab)


def compare_groups(lab):
    provision_private_volume(lab, COMPARISON_CLAIM, COMPARISON_PATH, 4000)
    comparative = workload(COMPARISON_POD, claim=COMPARISON_CLAIM)
    comparative["metadata"]["labels"] = {COMPARISON_LABEL: "approved"}
    spec = comparative["spec"]
    spec["securityContext"] = {"supplementalGroups": [4000], "supplementalGroupsPolicy": "Strict"}
    spec["volumes"].append({"name": "comparison-data", "persistentVolumeClaim": {"claimName": APPROVED_CLAIM}})
    comparison_mount = {"name": "comparison-data", "mountPath": "/comparison-data", "readOnly": False}
    for unit in spec["containers"]:
        unit["securityContext"].update({"runAsUser": 10002, "runAsGroup": 10002})
        unit["volumeMounts"] = [*unit["volumeMounts"], comparison_mount.copy()]
    unexpected = json.loads(json.dumps(comparative))
    unexpected["metadata"]["name"] = "saf-0302-007-other-comparison"
    denied_scope = denied(server_dry_run(lab, unexpected), DENIALS[0])
    permitted = server_dry_run(lab, comparative).returncode == 0
    lab.check("green", "Only the exact benign comparison fixture may mount the test comparison claim",
              denied_scope and permitted, {"unapproved_identity_denied": denied_scope, "exact_comparison_admitted": permitted})
    lab.create(comparative)
    ready(lab, COMPARISON_POD)

    script = r"""set -eu
groups=$(id -G)
printf 'uid=%s groups=%s own_gid=%s compared_gid=%s compared_mount_flags=%s\n' "$(id -u)" "$(printf '%s' "$groups" | tr ' ' ',')" \
  "$(stat -c %g /fixture-data)" "$(stat -c %g /comparison-data)" \
  "$(awk '$5 == "/comparison-data" {print $6}' /proc/self/mountinfo)"
printf '%s\n' 'owned comparison storage' >/fixture-data/comparison-self.txt
test "$(cat /fixture-data/comparison-self.txt)" = 'owned comparison storage'
printf '%s\n' 'own_write=ok'
if error=$( (printf '%s\n' 'comparison should not write' > /comparison-data/allowed.txt) 2>&1 ); then
    printf '%s\n' 'cross_write=unexpected'
else
    printf 'cross_write_error=%s\n' "$error"
fi
"""
    observed = lab.kubectl("exec", COMPARISON_POD, "-c", "probe", "--", "sh", "-c", script).stdout.strip()
    first, own, failure = observed.splitlines()
    identity = dict(part.split("=", 1) for part in first.split())
    wrong_group = set(identity["groups"].split(",")) == {"10002", "4000"}
    self_wrote = own == "own_write=ok" and identity["own_gid"] == "4000"
    mounted_rw = "rw" in identity["compared_mount_flags"].split(",")
    denied_write = failure.startswith("cross_write_error=") and "Permission denied" in failure
    original = lab.kubectl("exec", "saf-0302-007-persistent", "-c", "peer", "--", "cat",
                           "/fixture-data/allowed.txt").stdout.strip()
    unchanged = original == MARKER
    lab.check("positive", "A live different-group identity writes its own volume but cannot change the writable comparison marker",
              identity["uid"] == "10002" and wrong_group and self_wrote and denied_write
              and identity["compared_gid"] == "2000" and mounted_rw and unchanged,
              {"verified_group_boundary": wrong_group, "own_write": self_wrote,
               "other_write_denied": denied_write, "comparison_mount_writable": mounted_rw,
               "original_marker_unchanged": unchanged})
    (lab.evidence / "volume-group-observations.json").write_text(json.dumps({
        "comparison_identity": identity, "observation": observed, "source_original_marker": original,
        "comparison_mount_read_only": comparison_mount["readOnly"],
        "comparison_fs_group_present": "fsGroup" in spec["securityContext"],
        "exact_scope_admission": permitted, "another_identity_denied": denied_scope,
    }, indent=2) + "\n")
