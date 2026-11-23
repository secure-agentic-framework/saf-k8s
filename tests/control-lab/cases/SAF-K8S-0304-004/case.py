"""SAF-K8S-0304-004: restricted PSA and scoped ephemeral-container RBAC."""
from copy import deepcopy
import json
import time

BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)

SCOPE = (
    "Fresh harness-owned Kind cluster; namespace saf-test; native Pod Security "
    "Admission restricted v1.36; RBAC for one case-owned pod's ephemeralcontainers subresource."
)

NAMESPACE = "saf-test"
POD = "ephemeral-target"
APPROVED = "system:serviceaccount:saf-test:debugger"
UNAUTHORIZED = "system:serviceaccount:saf-test:unapproved"


def _raw_update(lab, identity, pod_obj, *, dry_run=False):
    path = f"/api/v1/namespaces/{NAMESPACE}/pods/{POD}/ephemeralcontainers"
    if dry_run:
        path += "?dryRun=All"
    return lab.kubectl("--as", identity, "replace", "--raw", path, "-f", "-",
                       payload=json.dumps(pod_obj), allow_failure=True)


def _get_pod(lab):
    return json.loads(lab.kubectl("get", "pod", POD, "-o", "json").stdout)


def _safe_ephemeral(name="debug-marker"):
    return {
        "name": name,
        "image": BUSYBOX_IMAGE,
        "command": ["sh", "-ec", "test $(id -u) = 65534; grep -Eq '^Seccomp:[[:space:]]+2$' /proc/self/status; echo saf-ephemeral-ok"],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }


def _pod(name=POD, *, bad=False):
    security = ({"runAsNonRoot": False, "runAsUser": 0,
                 "seccompProfile": {"type": "RuntimeDefault"}}
                if bad else {"runAsNonRoot": True, "runAsUser": 65534,
                             "seccompProfile": {"type": "RuntimeDefault"}})
    container_security = ({"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                           **security})
    container = {"name": "app", "image": BUSYBOX_IMAGE,
                 "command": ["sh", "-c", "sleep 3600"],
                 "securityContext": container_security}
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "labels": {"case": "saf-k8s-0304-004"}},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False, "containers": [container],
                 "initContainers": [{"name": "init", "image": BUSYBOX_IMAGE,
                                     "command": ["sh", "-c", "true"],
                                     "securityContext": container_security}]},
    }


def run(lab):
    # The identical noncompliant ordinary Pod is admitted by dry run before
    # namespace policy is enabled, proving the request reached the API server.
    red = lab.create(_pod("red-probe", bad=True), dry_run=True, allow_failure=True)
    lab.check("red", "insecure ordinary Pod is admitted before restricted PSA",
              red.returncode == 0, {"server_dry_run_accepted": red.returncode == 0})

    lab.kubectl("label", "namespace", NAMESPACE,
                "pod-security.kubernetes.io/enforce=restricted",
                "pod-security.kubernetes.io/enforce-version=v1.36", "--overwrite")
    rejected = lab.create(_pod("green-probe", bad=True), dry_run=True, allow_failure=True)
    reason = rejected.stderr.strip() or rejected.stdout.strip()
    lab.check("green", "restricted PSA rejects the same insecure ordinary Pod",
              rejected.returncode != 0 and "violates PodSecurity" in reason
              and "restricted:v1.36" in reason, {"reason_is_restricted_psa": "restricted:v1.36" in reason})

    # A compliant target containing an init container is owned by this case.
    lab.create(_pod(), dry_run=False)
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{POD}", "--timeout=95s", timeout=105)
    before = _get_pod(lab)
    init_names = [c["name"] for c in before["spec"].get("initContainers", [])]
    lab.check("positive", "init container remains in its own immutable field",
              init_names == ["init"] and not before["spec"].get("ephemeralContainers"),
              json.dumps({"initContainers": init_names,
                          "ephemeralContainers": before["spec"].get("ephemeralContainers", [])}))

    # Scope the write permission to only this pod and only the subresource.
    lab.kubectl("create", "serviceaccount", "debugger")
    lab.kubectl("create", "serviceaccount", "unapproved")
    lab.kubectl("create", "role", "ephemeral-debugger", "--verb=update",
                "--resource=pods/ephemeralcontainers", f"--resource-name={POD}")
    lab.kubectl("create", "rolebinding", "ephemeral-debugger",
                "--role=ephemeral-debugger", "--serviceaccount=saf-test:debugger")

    compliant = deepcopy(before)
    compliant["spec"]["ephemeralContainers"] = [_safe_ephemeral()]
    unauthorized = _raw_update(lab, UNAUTHORIZED, compliant, dry_run=True)
    denial = unauthorized.stderr
    blocked = unauthorized.returncode != 0 and "Forbidden" in denial and "cannot update" in denial
    lab.check("green", "Unauthorized identity cannot update the ephemeralcontainers subresource",
              blocked and "ephemeralcontainers" in denial,
              {"denied_by_rbac": blocked, "target_subresource": "ephemeralcontainers"})

    # Both negative content probes are dry runs of the inert marker.
    invalid = deepcopy(compliant)
    invalid["spec"]["ephemeralContainers"][0]["securityContext"]["runAsNonRoot"] = False
    invalid_result = _raw_update(lab, APPROVED, invalid, dry_run=True)
    invalid_reason = invalid_result.stderr
    restricted = ("violates PodSecurity" in invalid_reason
                  and "restricted:v1.36" in invalid_reason
                  and "runAsNonRoot" in invalid_reason)
    lab.check("green", "Restricted PSA rejects the authorized identity's noncompliant ephemeral update",
              invalid_result.returncode != 0 and restricted,
              {"denied_by_psa": restricted, "violation": "runAsNonRoot"})

    duplicate = deepcopy(compliant)
    duplicate["spec"]["ephemeralContainers"][0]["name"] = "init"
    duplicate_result = _raw_update(lab, APPROVED, duplicate, dry_run=True)
    duplicate_denied = (duplicate_result.returncode != 0 and
                        "duplicate" in duplicate_result.stderr.lower())
    lab.check("positive", "The ephemeral subresource rejects an existing init container name",
              duplicate_denied, {"duplicate_init_name_rejected": duplicate_denied})

    ordinary = lab.kubectl("patch", "pod", POD, "--type=merge", "--dry-run=server", "-p",
                           json.dumps({"spec": {"ephemeralContainers": [_safe_ephemeral()]}}),
                           allow_failure=True)
    unmodified = not _get_pod(lab)["spec"].get("ephemeralContainers")
    ordinary_denied = ordinary.returncode != 0 and "ephemeral" in ordinary.stderr.lower()
    lab.check("positive", "The ordinary Pod update route refuses ephemeral additions",
              ordinary_denied and unmodified,
              {"ordinary_update_denied": ordinary_denied, "target_unmodified": unmodified})

    accepted = _raw_update(lab, APPROVED, compliant)
    lab.check("positive", "Authorized compliant ephemeral update succeeds",
              accepted.returncode == 0, {"subresource_update_accepted": accepted.returncode == 0})

    after = _get_pod(lab)
    receipt = {"uid_before": before["metadata"]["uid"],
               "uid_after": after["metadata"]["uid"],
               "node_before": before.get("spec", {}).get("nodeName"),
               "node_after": after.get("spec", {}).get("nodeName"),
               "ephemeral_names": [c["name"] for c in after["spec"].get("ephemeralContainers", [])],
               "init_names": [c["name"] for c in after["spec"].get("initContainers", [])]}
    stable = (receipt["uid_before"] == receipt["uid_after"] and receipt["node_before"]
              and receipt["node_before"] == receipt["node_after"]
              and receipt["ephemeral_names"] == ["debug-marker"]
              and receipt["init_names"] == ["init"])
    lab.check("positive", "permitted marker preserves scheduled pod identity and init field",
              stable, {"pod_identity_and_node_preserved": bool(stable),
                       "ephemeral_names": receipt["ephemeral_names"], "init_names": receipt["init_names"]})

    deadline = time.monotonic() + 45
    finished = False
    while time.monotonic() < deadline:
        statuses = _get_pod(lab).get("status", {}).get("ephemeralContainerStatuses", [])
        if any(s["name"] == "debug-marker" and s.get("state", {}).get("terminated", {}).get("exitCode") == 0 for s in statuses):
            finished = True
            break
        time.sleep(1)
    result = lab.kubectl("logs", POD, "-c", "debug-marker", allow_failure=True)
    lab.check("positive", "The permitted ephemeral marker actually runs non-root with a seccomp filter",
              finished and result.returncode == 0 and result.stdout.strip() == "saf-ephemeral-ok",
              {"marker_exit_zero": finished, "non_root_filtered_process_observed": result.stdout.strip() == "saf-ephemeral-ok"})
    (lab.evidence / "ephemeral-boundary.raw.json").write_text(json.dumps(receipt, indent=2) + "\n")
