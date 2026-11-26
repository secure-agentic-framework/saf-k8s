"""Exercise cross-cluster registry pair authorization and real membership repair."""
import importlib.util
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
NS = "saf-test"
CODE = "fixture-federation-code"
APPROVAL = "fixture-approved-membership"
APPROVAL_NEXT = "fixture-approved-membership-v2"
APPROVAL_POINTER = "fixture-approved-membership-current"
MEMBERSHIP = "fixture-federation-membership"
MANAGER = "fixture-federation-manager"
OBSERVER = "fixture-federation-observer"
APPROVAL_AUTHORITY = "fixture-federation-approval-authority"
RECONCILE_CRONJOB = "fixture-federation-reconcile"
SOURCE_REGISTRY = "fixture-federation-source"
APPROVED_REGISTRY = "fixture-federation-approved"
UNAPPROVED_REGISTRY = "fixture-federation-unapproved"
REPOSITORY = "fixtures/saf-federation"
TAG = "fixture-v1"
REGISTRY = ("docker.io/library/registry:3.0.0@sha256:"
            "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e")
RBAC = "rbac.authorization.k8s.io/v1"
SCOPE = (
    "A pinned CNCF Distribution registry in the supervisor cluster is the source; two separately "
    "addressed pinned Distribution registries in the disposable owned-peer Kind cluster are the "
    "only candidate destinations. The exact source-to-unapproved-destination pair and one fixed "
    "tag are first copied without governance, then removed and refused by the governed path. The "
    "approved destination path is also exercised. Membership is a real ConfigMap managed by a "
    "least-privilege service account; a separate observer independently checks that resource "
    "and each registry manifest. Reconciliation is capped at four API read/repair passes. The "
    "scratch extension selects one new immutable approval snapshot, observes one native CronJob "
    "reconciliation invocation, and verifies refusal of the formerly approved pair; this is not "
    "evidence of sustained schedule reliability or production endpoint identity."
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Required adjacent fixture helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def registry_pod(name):
    unit = container("registry", image=REGISTRY, imagePullPolicy="IfNotPresent", ports=[{"containerPort": 5000}],
                     env=[{"name": "REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY", "value": "/tmp/registry"}])
    del unit["command"]
    unit["readinessProbe"] = {"httpGet": {"port": 5000, "path": "/v2/"}, "periodSeconds": 1}
    definition = pod(name, [unit], automountServiceAccountToken=False, terminationGracePeriodSeconds=2)
    definition["metadata"]["labels"] = {"app": name}
    return definition


def registry(lab, name, peer=None):
    definition = registry_pod(name)
    spec = {"selector": {"app": name}, "ports": [{"port": 5000, "targetPort": 5000}]}
    if peer is None:
        lab.create(definition)
        create(lab, "Service", name, spec=spec)
        ready(lab, name)
        return
    spec["type"] = "NodePort"
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name}, "spec": spec}
    peer("create", "-f", "-", payload=json.dumps(definition))
    result = peer("create", "-f", "-", "-o", "json", payload=json.dumps(service))
    peer("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=90s", timeout=100)
    return json.loads(result.stdout)["spec"]["ports"][0]["nodePort"]


def runner(lab, image, actor, env):
    unit = container("fixture", image=image, imagePullPolicy="Never", command=["sleep", "360"],
                     volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True}], env=env)
    lab.create(pod(actor, [unit], serviceAccountName=actor,
                   volumes=[{"name": "code", "configMap": {"name": CODE}}]))
    ready(lab, actor)


def accounts(lab):
    for account in (MANAGER, OBSERVER, APPROVAL_AUTHORITY):
        create(lab, "ServiceAccount", account)
        permissions = []
        if account in (MANAGER, OBSERVER):
            permissions.append({"apiGroups": [""], "resources": ["configmaps"],
                                "resourceNames": [APPROVAL, APPROVAL_NEXT, APPROVAL_POINTER, MEMBERSHIP],
                                "verbs": ["get"]})
        if account == MANAGER:
            permissions.append({"apiGroups": [""], "resources": ["configmaps"],
                                "resourceNames": [MEMBERSHIP], "verbs": ["patch"]})
        if account == APPROVAL_AUTHORITY:
            permissions.extend([
                {"apiGroups": [""], "resources": ["configmaps"],
                 "resourceNames": [APPROVAL_POINTER], "verbs": ["get", "patch"]},
            ])
        create(lab, "Role", account, RBAC, rules=permissions)
        create(lab, "RoleBinding", account, RBAC,
               roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": account},
               subjects=[{"kind": "ServiceAccount", "name": account, "namespace": NS}])


def scheduled_reconciliation(lab, image, env):
    command = ["python", "/fixture/federation_fixture.py", "call", "reconcile"]
    worker = container("reconcile", image=image, imagePullPolicy="Never", command=command,
                       env=env,
                       volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True}],
                       securityContext={"allowPrivilegeEscalation": False,
                                        "capabilities": {"drop": ["ALL"]},
                                        "runAsNonRoot": True, "runAsUser": 65534,
                                        "seccompProfile": {"type": "RuntimeDefault"}})
    cron = {"apiVersion": "batch/v1", "kind": "CronJob",
            "metadata": {"name": RECONCILE_CRONJOB},
            "spec": {"schedule": "* * * * *", "concurrencyPolicy": "Forbid",
                     "startingDeadlineSeconds": 60, "successfulJobsHistoryLimit": 1,
                     "failedJobsHistoryLimit": 1,
                     "jobTemplate": {"spec": {"backoffLimit": 0, "activeDeadlineSeconds": 45,
                         "template": {"spec": {"serviceAccountName": MANAGER,
                             "restartPolicy": "Never", "automountServiceAccountToken": True,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                  "fsGroup": 65534},
                             "containers": [worker],
                             "volumes": [{"name": "code", "configMap": {"name": CODE,
                                                                             "defaultMode": 292}}]}}}}}}
    created_cron = lab.create(cron)
    cron_uid = created_cron["metadata"]["uid"]
    schedule_configured = created_cron.get("spec", {}).get("schedule") == "* * * * *"
    job_name = None
    try:
        deadline = time.monotonic() + 110
        while time.monotonic() < deadline:
            listing = json.loads(lab.kubectl("get", "jobs", "-o", "json", timeout=15).stdout)
            owned = [
                job for job in listing.get("items", [])
                if job["metadata"].get("annotations", {}).get("batch.kubernetes.io/cronjob-scheduled-timestamp")
                and any(owner.get("kind") == "CronJob" and owner.get("uid") == cron_uid
                        and owner.get("controller") is True
                        for owner in job["metadata"].get("ownerReferences", []))
            ]
            completed = next((job for job in owned if job.get("status", {}).get("succeeded") == 1), None)
            failed = next((job for job in owned if job.get("status", {}).get("failed", 0) > 0), None)
            if completed:
                job_name = completed["metadata"]["name"]
                output = lab.kubectl("logs", f"job/{job_name}", timeout=15).stdout.strip()
                return {"schedule_configured": schedule_configured,
                        "scheduled": bool(completed["status"].get("startTime")),
                        "completed": True, "result": json.loads(output)}
            if failed:
                job_name = failed["metadata"]["name"]
                output = lab.kubectl("logs", f"job/{job_name}", timeout=15, allow_failure=True).stdout.strip()
                return {"schedule_configured": schedule_configured,
                        "scheduled": bool(failed["status"].get("startTime")),
                        "completed": False, "result": output[:160]}
            time.sleep(1)
        return {"schedule_configured": schedule_configured, "scheduled": False,
                "completed": False, "result": "schedule-window-expired"}
    finally:
        lab.kubectl("delete", "cronjob", RECONCILE_CRONJOB, "--wait=true", "--timeout=20s",
                    timeout=25, allow_failure=True)
        if job_name:
            lab.kubectl("delete", "job", job_name, "--wait=true", "--timeout=20s",
                        timeout=25, allow_failure=True)


def run(lab):
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_federation_runtime")
    bridge = load(HERE.parent / "SAF-K8S-0910-020" / "owned_peer.py", "saf_owned_peer")
    fixture = load(HERE / "federation_fixture.py", "saf_federation_program")
    digest = fixture.MANIFEST_DIGEST
    image = runtime.load_runtime(lab)
    with bridge.owned_peer(lab, image) as (peer, peer_ip):
        create(lab, "ConfigMap", CODE, immutable=True,
               data={"federation_fixture.py": (HERE / "federation_fixture.py").read_text()})
        accounts(lab)
        registry(lab, SOURCE_REGISTRY)
        approved_port = registry(lab, APPROVED_REGISTRY, peer)
        rejected_port = registry(lab, UNAPPROVED_REGISTRY, peer)
        endpoints = fixture.endpoint_map(peer_ip, approved_port, rejected_port)
        allowed = [endpoints["source"], endpoints["destination_approved"]]
        create(lab, "ConfigMap", APPROVAL, immutable=True, data={"approved.json": json.dumps(allowed)})
        create(lab, "ConfigMap", APPROVAL_NEXT, immutable=True,
               data={"approved.json": json.dumps([endpoints["source"]])})
        create(lab, "ConfigMap", APPROVAL_POINTER,
               data={"current.json": json.dumps(APPROVAL)})
        create(lab, "ConfigMap", MEMBERSHIP, data={"active.json": json.dumps(allowed)})
        env = [{"name": name, "value": str(value)} for name, value in
               (("PEER_IP", peer_ip), ("APPROVED_PORT", approved_port), ("UNAPPROVED_PORT", rejected_port))]
        for actor in (MANAGER, OBSERVER, APPROVAL_AUTHORITY):
            runner(lab, image, actor, env)

        def invoke(actor, operation):
            result = lab.kubectl("exec", actor, "--", "python", "/fixture/federation_fixture.py",
                                 "call", operation, timeout=40)
            return json.loads(result.stdout)

        # The helper receives only fixed operation names; endpoint URLs and repository/tag are constants.
        if invoke(OBSERVER, "wait-ready") != {"ready": True}:
            lab.block("The three owned registry endpoints never became ready")
        seed = invoke(MANAGER, "seed")
        source_observation = invoke(OBSERVER, "observe-source")
        if seed.get("digest") != digest or source_observation.get("digest") != digest:
            lab.block("Could not seed and independently observe the fixed source manifest")

        baseline = invoke(MANAGER, "baseline-copy")
        baseline_state = invoke(OBSERVER, "observe-unapproved")
        lab.check("red", "Without governance the exact ordered pair writes the fixture digest",
                  baseline.get("decision") == "baseline-written" and
                  baseline_state.get("digest") == digest,
                  {"decision": baseline, "destination": baseline_state})

        peer("delete", "pod", UNAPPROVED_REGISTRY, "--wait=true", "--timeout=38s", timeout=45)
        peer("create", "-f", "-", payload=json.dumps(registry_pod(UNAPPROVED_REGISTRY)))
        peer("wait", "--for=condition=Ready", f"pod/{UNAPPROVED_REGISTRY}", "--timeout=75s", timeout=85)
        if invoke(OBSERVER, "wait-ready") != {"ready": True}:
            lab.block("The unapproved fixture registry did not return on its original Service")
        clear_state = invoke(OBSERVER, "observe-unapproved")
        cleared = invoke(OBSERVER, "observe-unapproved-empty")
        refusal = invoke(MANAGER, "governed-copy-unapproved")
        refused_state = invoke(OBSERVER, "observe-unapproved")
        refused_content = invoke(OBSERVER, "observe-unapproved-empty")
        approved = invoke(MANAGER, "governed-copy-approved")
        approved_state = invoke(OBSERVER, "observe-approved")
        lab.check("green", "Governance refuses the same pair after reset and the approved pair succeeds",
                  cleared.get("all_fixture_content_absent") is True and clear_state.get("digest") is None and
                  refusal.get("decision") == "denied-endpoint-pair" and
                  refused_state.get("digest") is None
                  and refused_content.get("all_fixture_content_absent") is True and
                  approved.get("decision") == "allowed" and approved_state.get("digest") == digest,
                  {"baseline_clear": cleared, "clear_observation": clear_state,
                   "refusal": refusal, "refused_destination": refused_state,
                   "refused_content": refused_content,
                   "approved": approved, "approved_destination": approved_state})

        observer_write = invoke(OBSERVER, "observer-write-denied")
        manager_approval_write = invoke(MANAGER, "manager-approval-write-denied")
        drift = invoke(MANAGER, "inject-drift")
        before = invoke(OBSERVER, "observe-membership")
        reconciliation = invoke(MANAGER, "reconcile")
        after = invoke(OBSERVER, "observe-membership")
        final_approved = invoke(OBSERVER, "observe-approved")
        lab.check("green", "RBAC separates membership observation and bounded repair changes the real ConfigMap",
                  observer_write.get("http_status") == 403 and
                  manager_approval_write.get("http_status") == 403 and
                  "destination_unapproved" in before.get("active", []) and
                  reconciliation.get("passes", 99) <= 4 and reconciliation.get("changed") is True and
                  "destination_unapproved" not in after.get("active", []) and
                  after.get("active") == ["destination_approved", "source"] and
                  final_approved.get("digest") == digest,
                  {"observer_write": observer_write, "manager_approval_write": manager_approval_write,
                   "drift_injection": drift,
                   "before": before, "reconciliation": reconciliation,
                   "after": after, "approved_state": final_approved})

        active_copy = invoke(MANAGER, "governed-copy-approved")
        independently_read = invoke(OBSERVER, "observe-approved")
        lab.check("positive", "The repaired membership still allows replication of the exact approved image",
                  active_copy == {"decision": "allowed", "digest": digest}
                  and independently_read == {"digest": digest, "status": 200},
                  {"copy": active_copy, "registry_state": independently_read})

        peer("delete", "pod", APPROVED_REGISTRY, "--wait=true", "--timeout=38s", timeout=45)
        peer("create", "-f", "-", payload=json.dumps(registry_pod(APPROVED_REGISTRY)))
        peer("wait", "--for=condition=Ready", f"pod/{APPROVED_REGISTRY}",
             "--timeout=75s", timeout=85)
        if invoke(OBSERVER, "wait-ready") != {"ready": True}:
            lab.block("The replaced approved registry did not recover its private route")
        reset_state = invoke(OBSERVER, "observe-approved")
        reset_empty = invoke(OBSERVER, "observe-approved-empty")
        before_revoke = invoke(OBSERVER, "observe-approval-revisions")
        denied_revision = invoke(MANAGER, "manager-revision-write-denied")
        authorized_revision = invoke(APPROVAL_AUTHORITY, "advance-approval-revision")
        revisions = invoke(OBSERVER, "observe-approval-revisions")
        scheduled = scheduled_reconciliation(lab, image, env)
        after_reconcile = invoke(OBSERVER, "observe-membership")
        revoked_copy = invoke(MANAGER, "governed-copy-approved")
        revoked_destination = invoke(OBSERVER, "observe-approved")
        revoked_empty = invoke(OBSERVER, "observe-approved-empty")
        source_unchanged = invoke(OBSERVER, "observe-source")
        revocation = {
            "formerly_approved_destination_was_empty": (
                reset_state.get("digest") is None and reset_empty.get("all_fixture_content_absent") is True),
            "manager_cannot_advance_approval_pointer": denied_revision.get("http_status") == 403,
            "separate_approval_authority_advanced_version": authorized_revision == {
                "http_status": 200, "revision": APPROVAL_NEXT},
            "immutable_revision_and_pre_reconcile_state_observed": (
                before_revoke.get("current", {}).get("approval_revision") == APPROVAL
                and before_revoke.get("current", {}).get("approved") == ["destination_approved", "source"]
                and before_revoke.get("current", {}).get("active") == ["destination_approved", "source"]
                and revisions.get("current", {}).get("approval_revision") == APPROVAL_NEXT
                and revisions.get("v1") == ["destination_approved", "source"]
                and revisions.get("v2") == ["source"]
                and revisions.get("current", {}).get("active") == ["destination_approved", "source"]),
            "scheduled_reconciler_removed_revoked_endpoint": (
                scheduled.get("schedule_configured") is True
                and scheduled.get("scheduled") is True and scheduled.get("completed") is True
                and scheduled.get("result", {}).get("changed") is True
                and scheduled.get("result", {}).get("passes", 99) <= 4
                and scheduled.get("result", {}).get("active") == ["source"]
                and after_reconcile.get("approval_revision") == APPROVAL_NEXT
                and after_reconcile.get("approved") == ["source"]
                and after_reconcile.get("active") == ["source"]),
            "revoked_pair_refused_without_new_destination_content": (
                revoked_copy.get("decision") == "denied-endpoint-pair"
                and revoked_destination.get("digest") is None
                and revoked_empty.get("all_fixture_content_absent") is True),
            "source_registry_content_remains_exact": source_unchanged.get("digest") == digest,
        }
        lab.check("revocation", "A versioned approval revocation is reconciled on schedule and blocks new replication",
                  all(revocation.values()),
                  {"reset_state": reset_state, "reset_empty": reset_empty,
                   "before_revoke": before_revoke,
                   "manager_pointer_write": denied_revision,
                   "authorized_revision": authorized_revision, "revisions": revisions,
                   "scheduled_reconciliation": scheduled, "after_reconcile": after_reconcile,
                   "revoked_copy": revoked_copy, "revoked_destination": revoked_destination,
                   "revoked_empty": revoked_empty, "source_unchanged": source_unchanged,
                   "checks": revocation})

        # Drop ephemeral bridge addresses and Kubernetes object metadata from the stable record.
        evidence = {
            "scope": SCOPE,
            "digest": digest,
            "repository": REPOSITORY,
            "tag": TAG,
            "ordered_pairs": {"baseline_and_refusal": ["source", "destination_unapproved"],
                              "approved": ["source", "destination_approved"]},
            "baseline": {"decision": baseline.get("decision"), "observed_digest": baseline_state.get("digest")},
            "governed_refusal": {"decision": refusal.get("decision"),
                                 "cleared_before_refusal": clear_state.get("digest") is None,
                                 "observed_digest": refused_state.get("digest"),
                                 "all_fixture_content_absent": refused_content.get("all_fixture_content_absent")},
            "approved": {"decision": approved.get("decision"), "observed_digest": approved_state.get("digest")},
            "rbac": {"observer_write_status": observer_write.get("http_status"),
                     "manager_approval_write_status": manager_approval_write.get("http_status")},
            "reconciliation": {"injected": drift.get("injected"),
                                "before_active": before.get("active"),
                                "passes": reconciliation.get("passes"),
                                "changed": reconciliation.get("changed"),
                                "after_active": after.get("active")},
            "revocation": {"current_approval_revision": revisions.get("current", {}).get("approval_revision"),
                           "old_snapshot_unchanged": revisions.get("v1") == ["destination_approved", "source"],
                           "new_snapshot": revisions.get("v2"),
                           "manager_pointer_write_status": denied_revision.get("http_status"),
                           "approval_authority_status": authorized_revision.get("http_status"),
                           "scheduled_reconcile": scheduled.get("scheduled") is True,
                           "reconciled_active": after_reconcile.get("active"),
                           "revoked_copy_decision": revoked_copy.get("decision"),
                           "destination_fixture_content_absent": revoked_empty.get("all_fixture_content_absent")},
        }
        (lab.evidence / "registry-federation-observations.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n")
