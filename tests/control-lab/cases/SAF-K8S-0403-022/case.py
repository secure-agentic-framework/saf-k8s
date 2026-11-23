"""Revoke only credentials for observed terminal workload identities."""

import base64
import json
from pathlib import Path
import runpy
import time
from types import SimpleNamespace

from fixtures import container

HERE = Path(__file__).resolve().parent
vault = SimpleNamespace(**runpy.run_path(str(HERE / "vault_fixture.py")))
NS = "saf-test"
COMPLETE = "fixture-cleanup-complete"
FAILED = "fixture-cleanup-failed"
ACCOUNT = "fixture-cleanup-workload"
POLICY = "fixture-cleanup-credential"
HISTORY = "fixture-cleanup-terminal-history"
KEY = "fixture-cleanup-marker"
PATH = "transit/encrypt/" + KEY
VALUE = base64.b64encode(b"public cleanup canary").decode()
SCOPE = (
    "Reconcile real Vault credentials against immutable Kubernetes Job lifecycle evidence. "
    "Verify failed and successful jobs, same-name replacement survival, unresolved identities, "
    "provider refusal, revocation, and Pod-bound Kubernetes token invalidation. Other issuers and "
    "production lifecycle service levels need separate evidence."
)


def create_job(lab, name, shell):
    unit = container("job", command=["sh", "-c", shell])
    opened = lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                         "spec": {"backoffLimit": 0, "template": {"spec": {
                             "containers": [unit], "restartPolicy": "Never", "serviceAccountName": ACCOUNT,
                             "automountServiceAccountToken": False,
                         }}}})
    return opened["metadata"]["uid"]


def bind_pod(lab, job_uid):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        objects = json.loads(lab.kubectl("get", "pods", "-o", "json").stdout)["items"]
        owned = [row for row in objects if any(ref["uid"] == job_uid for ref in row["metadata"].get("ownerReferences", []))]
        if len(owned) == 1:
            return owned[0]["metadata"]["name"]
        time.sleep(.5)
    lab.block("No unique Pod belongs to the owned Job UID")


def issue(lab, administrator, uid):
    created = vault.required(lab, "auth/token/create", token=administrator,
                             body={"policies": [POLICY], "token_type": "service", "ttl": "10m",
                                   "no_default_policy": True, "meta": {"owner_uid": uid}})["auth"]
    return (created["accessor"], created["client_token"])


def value_status(lab, pair):
    return vault.request(lab, PATH, token=pair[1], body={"plaintext": VALUE})[0]


def authorized(lab, material):
    body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
            "spec": {"token": material.strip(), "audiences": [vault.AUDIENCE]}}
    response = vault.private(lab, "create", "-f", "-", "-o", "json", payload=json.dumps(body))
    if not response:
        lab.block("The owned Pod-bound token review was unavailable")
    return json.loads(response)["status"].get("authenticated") is True


def terminal(lab, name, recorded_uid, condition):
    lab.kubectl("wait", "--for=condition=" + condition, "job/" + name, "--timeout=75s", timeout=85)
    job = json.loads(lab.kubectl("get", "job/" + name, "-o", "json").stdout)
    matched = (job["metadata"]["uid"] == recorded_uid
               and any(row["type"] == condition and row["status"] == "True" for row in job["status"]["conditions"]))
    if not matched:
        lab.block("Terminal state did not belong to the expected immutable workload")
    return {"namespace": NS, "name": name, "uid": recorded_uid, "terminal": condition}


def eligible(lab, root, key, history):
    info = vault.required(lab, "auth/token/lookup-accessor", token=root, body={"accessor": key[0]})["data"]
    reference = (info["meta"] or {}).get("owner_uid")
    return history.get(reference)


def revoke(lab, actor, key):
    return vault.request(lab, "auth/token/revoke-accessor", token=actor, body={"accessor": key[0]})[0]


def run(lab):
    root = vault.start(lab)
    vault.required(lab, "transit/keys/" + KEY, token=root, body={"type": "aes256-gcm96"})
    vault.permissions(lab, root, POLICY, {PATH: ["update"]})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT},
                "automountServiceAccountToken": False})
    old_uid = create_job(lab, COMPLETE, "sleep 12; exit 0")
    failed_uid = create_job(lab, FAILED, "sleep 12; exit 42")
    pod_name = bind_pod(lab, old_uid)
    observed_token = vault.private(lab, "create", "token", ACCOUNT, "--bound-object-kind=Pod",
                                   "--bound-object-name=" + pod_name, "--duration=10m", "--audience=" + vault.AUDIENCE)
    if not observed_token:
        lab.block("Could not obtain the owned projected-token equivalent for the fixture Pod")
    old, failed = issue(lab, root, old_uid), issue(lab, root, failed_uid)
    terminal_history = {old_uid: terminal(lab, COMPLETE, old_uid, "Complete"),
                        failed_uid: terminal(lab, FAILED, failed_uid, "Failed")}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": HISTORY}, "immutable": True,
                "data": {"terminal": json.dumps(terminal_history, sort_keys=True)}})
    still_valid_before = authorized(lab, observed_token)
    provider_still_valid = value_status(lab, old) == value_status(lab, failed) == 200
    lab.check("red", "Job completion and failure leave owned provider credentials active, and the retained Pod token still authenticates",
              provider_still_valid and still_valid_before,
              {"terminal_provider_tokens_still_active": provider_still_valid, "completed_retained_pod_token_active": still_valid_before})

    lab.kubectl("delete", "job/" + COMPLETE, "--cascade=foreground", "--wait=true")
    new_uid = create_job(lab, COMPLETE, "sleep 300")
    newer = issue(lab, root, new_uid)
    uncertain = issue(lab, root, "unresolved-fixture-uid")
    saved = json.loads(lab.kubectl("get", "configmap/" + HISTORY, "-o", "jsonpath={.data.terminal}").stdout)
    records = {"completed": old, "failed": failed, "replacement": newer, "unresolved": uncertain}
    qualifying = {name for name, credential in records.items() if eligible(lab, root, credential, saved)}
    refused = revoke(lab, newer[1], old) == 403 and value_status(lab, old) == 200
    lab.check("green", "Reconciliation identifies only terminal UIDs and keeps a denied revocation unresolved",
              new_uid != old_uid and qualifying == {"completed", "failed"} and refused,
              {"terminal_candidates": sorted(qualifying), "same_name_replacement_distinct": new_uid != old_uid,
               "denied_provider_action_left_active": refused})

    settled = {name: revoke(lab, root, records[name]) for name in sorted(qualifying)}
    allowed = {name: value_status(lab, credential) for name, credential in records.items()}
    deadline = time.monotonic() + 25
    pod_removed = False
    while time.monotonic() < deadline:
        pod_removed = not authorized(lab, observed_token)
        if pod_removed:
            break
        time.sleep(1)
    finished = (all(code == 204 for code in settled.values())
                and not any(value_status(lab, records[name]) == 200 for name in qualifying)
                and allowed == {"completed": 403, "failed": 403, "replacement": 200, "unresolved": 200})
    lab.check("positive", "The actual authority denies both retired credentials while preserving replacement and unresolved credentials",
              finished and pod_removed, {"provider_decisions_after_reconciliation": allowed,
                                        "bound_token_denied_after_pod_deletion": pod_removed})
    (lab.evidence / "credential-reconciliation-observations.json").write_text(json.dumps({
        "terminal_provider_credentials_initially_active": provider_still_valid, "terminal_pod_token_initially_active": still_valid_before,
        "terminal_uid_match_only": sorted(qualifying), "denied_provider_revoke_unresolved": refused,
        "provider_decisions_after_revoke": allowed, "replacement_uid_is_distinct": new_uid != old_uid,
        "bound_token_retired_on_pod_deletion": pod_removed,
    }, indent=2) + "\n")
