"""Verify evidence and a UID-bound response against one case-owned inert Pod."""

import hashlib
import json
import time

SCOPE = "A fixture-only response to one bare Pod with separately retained evidence and scoped authorization."
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
SUBJECT = "response-fixture-subject"
WITNESS = "response-fixture-witness"
RECOVERY = "response-fixture-recovery"
SLOT = "saf.example/response-slot"
IDENTITY = "system:serviceaccount:saf-test:fixture-responder"
PUBLIC_MARKER = "saf-owned-response-fixture"


def pod(lab, name):
    resources = {"requests": {"cpu": "5m", "memory": "4Mi"}, "limits": {"cpu": "100m", "memory": "32Mi"}}
    if name in (SUBJECT, RECOVERY):
        resources["requests"][SLOT] = "1"
        resources["limits"][SLOT] = "1"
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"saf.example/response": "owned-fixture"}},
                "spec": {"restartPolicy": "Never", "terminationGracePeriodSeconds": 1,
                         "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{"name": "fixture", "image": IMAGE,
                                         "command": ["/bin/sh", "-c", f"echo {PUBLIC_MARKER}; exec sleep 180"],
                                         "resources": resources,
                                         "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                             "capabilities": {"drop": ["ALL"]}}}]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=55s", timeout=65)
    return read_pod(lab, name)


def read_pod(lab, name):
    text = lab.kubectl("get", "pod", name, "-o", "json", "--ignore-not-found").stdout
    return json.loads(text) if text.strip() else None


def grant(lab):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "fixture-responder"},
                "automountServiceAccountToken": False})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "fixture-response"},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "resourceNames": [SUBJECT], "verbs": ["delete"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "fixture-response"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "fixture-response"},
                "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": "fixture-responder"}]})


def subject_delete(lab, uid, *, dry=False):
    options = {"gracePeriodSeconds": 1, "preconditions": {"uid": uid}}
    if dry:
        options["dryRun"] = ["All"]
    return lab.kubectl("--as", IDENTITY, "delete", "--raw", f"/api/v1/namespaces/saf-test/pods/{SUBJECT}",
                       "-f", "-", payload=json.dumps(options), allow_failure=True)


def approved(approval, evidence, evidence_digest):
    return approval == {"fixture_only": True, "approved_uid": evidence["uid"], "evidence_sha256": evidence_digest}


def run(lab):
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if len(nodes) != 1 or not nodes[0]["metadata"]["name"].startswith(lab.cluster + "-"):
        lab.block("The response fixture requires a fresh owned Kind node")
    node = nodes[0]["metadata"]["name"]
    patch = json.dumps([{"op": "add", "path": "/status/capacity/" + SLOT.replace("/", "~1"), "value": "1"}])
    lab.kubectl("patch", "node", node, "--subresource=status", "--type=json", "-p", patch)
    for _ in range(65):
        snapshot = json.loads(lab.kubectl("get", "node", node, "-o", "json").stdout)
        if snapshot["status"]["allocatable"].get(SLOT) == "1":
            break
        time.sleep(1)
    else:
        lab.block("The fixture slot did not become allocatable")
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    previous = pod(lab, SUBJECT)
    old_uid = previous["metadata"]["uid"]
    lab.kubectl("delete", "pod", SUBJECT, "--wait=true", "--timeout=35s", timeout=45)
    current = pod(lab, SUBJECT)
    witness = pod(lab, WITNESS)
    uid = current["metadata"]["uid"]
    replaces = uid != old_uid and current["metadata"]["name"] == previous["metadata"]["name"]
    lab.check("red", "Name-only selection points to a different live fixture generation",
              replaces, {"same_fixture_name_and_distinct_uid": replaces})
    grant(lab)
    marker = lab.kubectl("logs", SUBJECT).stdout.strip()
    valid_fixture = (marker == PUBLIC_MARKER and current["metadata"]["labels"].get("saf.example/response") == "owned-fixture"
                     and not current["metadata"].get("ownerReferences"))
    if not valid_fixture:
        lab.block("The scoped fixture marker or scope could not be established")
    evidence = {"namespace": "saf-test", "name": SUBJECT, "uid": uid, "marker": marker,
                "container_image": current["spec"]["containers"][0]["image"], "case_owned_bare_pod": True}
    raw = json.dumps(evidence, sort_keys=True)
    fingerprint = hashlib.sha256(raw.encode()).hexdigest()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "response-evidence"},
                "immutable": True, "data": {"snapshot.json": raw, "sha256": fingerprint}})
    authorization = {"fixture_only": True, "approved_uid": uid, "evidence_sha256": fingerprint}
    stale_approval = {**authorization, "approved_uid": old_uid}
    no_record = not approved(None, evidence, fingerprint)
    outdated = not approved(stale_approval, evidence, fingerprint)
    stale = subject_delete(lab, old_uid, dry=True)
    stale_refused = stale.returncode != 0 and "precondition" in stale.stderr.lower() and "uid" in stale.stderr.lower()
    unchanged = read_pod(lab, SUBJECT)["metadata"]["uid"] == uid
    denied_other = lab.kubectl("--as", IDENTITY, "auth", "can-i", "delete", f"pod/{WITNESS}", allow_failure=True)
    out_of_scope = denied_other.returncode != 0 and denied_other.stdout.strip().split(" ", 1)[0] == "no"
    lab.check("green", "Approval and API preconditions reject a stale generation and exclude the witness from authorization",
              no_record and outdated and stale_refused and unchanged and out_of_scope,
              {"missing_and_stale_approval_denied": no_record and outdated, "uid_conflict_observed": stale_refused,
               "approved_uid_still_present": unchanged, "witness_excluded_by_rbac": out_of_scope})
    retained = json.loads(lab.kubectl("get", "configmap", "response-evidence", "-o", "json").stdout)
    intact = (retained["immutable"] and hashlib.sha256(retained["data"]["snapshot.json"].encode()).hexdigest()
              == retained["data"]["sha256"] == fingerprint)
    if not intact or not approved(authorization, evidence, fingerprint):
        lab.block("Fixture approval does not match the retained evidence")
    response = subject_delete(lab, uid)
    if response.returncode != 0:
        lab.block("The scoped fixture action returned an error; inspect the local command log")
    expires = time.monotonic() + 40
    while time.monotonic() < expires and read_pod(lab, SUBJECT) is not None:
        time.sleep(1)
    stopped = read_pod(lab, SUBJECT) is None
    survivor = read_pod(lab, WITNESS)
    ready = (survivor and survivor["metadata"]["uid"] == witness["metadata"]["uid"]
             and any(row["type"] == "Ready" and row["status"] == "True" for row in survivor["status"]["conditions"]))
    if not stopped:
        lab.block("The exact fixture did not stop within its response window")
    recovery = pod(lab, RECOVERY)
    consumed = recovery["spec"]["containers"][0]["resources"]["requests"].get(SLOT)
    reclaimed = recovery["spec"]["nodeName"] == current["spec"]["nodeName"] == node and consumed == "1"
    preserved = json.loads(lab.kubectl("get", "configmap", "response-evidence", "-o", "json").stdout)
    evidence_survived = preserved["data"] == retained["data"]
    lab.check("positive", "The exact approved fixture stops after evidence capture and the witness remains Ready",
              stopped and ready and evidence_survived and reclaimed,
              {"subject_gone": stopped, "same_witness_ready": bool(ready), "evidence_preserved": evidence_survived, "slot_reused": reclaimed})
    (lab.evidence / "response-observations.json").write_text(json.dumps({
        "marker_evidence": evidence, "approved_fixture_action": authorization, "previous_uid": old_uid,
        "protected_witness_uid": witness["metadata"]["uid"], "previous_uid_conflict": stale_refused,
        "subject_gone": stopped, "same_witness_ready": bool(ready), "evidence_preserved": evidence_survived, "slot_reused": reclaimed,
    }, indent=2) + "\n")
