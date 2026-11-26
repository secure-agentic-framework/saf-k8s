"""Schedule revocation of the single credential selected by the audited case."""
import json
from pathlib import Path
import time

NS = "saf-test"
NAME = "saf-0402-002-scheduled"
CODE = NAME + "-code"
DECISION = NAME + "-decision"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)


def resource(lab, api, kind, name, **fields):
    return lab.create({
        "apiVersion": api, "kind": kind,
        "metadata": {"name": name, "namespace": NS}, **fields,
    })


def job_template():
    return {
        "metadata": {"labels": {"saf-test/fixture": NAME}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 40, "template": {"spec": {
            "serviceAccountName": NAME, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "revocation", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "/case/revoke.py"],
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "150m", "memory": "96Mi"}},
                "volumeMounts": [{"name": "code", "mountPath": "/case", "readOnly": True},
                                 {"name": "decision", "mountPath": "/decision", "readOnly": True}],
            }],
            "volumes": [{"name": "code", "configMap": {"name": CODE}},
                        {"name": "decision", "configMap": {"name": DECISION}}],
        }}},
    }


def jobs_for(lab, uid):
    jobs = json.loads(lab.kubectl("get", "jobs", "-l", f"saf-test/fixture={NAME}", "-o", "json").stdout)
    return [job for job in jobs["items"] if any(
        owner.get("kind") == "CronJob" and owner.get("uid") == uid
        for owner in job["metadata"].get("ownerReferences", [])
    )]


def presence(lab, target):
    return lab.kubectl("get", "secret", target, "--ignore-not-found", "-o", "name").stdout.strip()


def revoke_approved_credential(lab, approval_id, target, unrelated, audit_events):
    v1, rbac = "v1", "rbac.authorization.k8s.io/v1"
    if target != "saf-0402-002-unused-legacy":
        lab.block("The CronJob accepts only the exact case-owned credential")
    resource(lab, v1, "ServiceAccount", NAME)
    resource(lab, rbac, "Role", NAME, rules=[{
        "apiGroups": [""], "resources": ["secrets"], "resourceNames": [target], "verbs": ["delete"],
    }])
    resource(lab, rbac, "RoleBinding", NAME,
             subjects=[{"kind": "ServiceAccount", "name": NAME, "namespace": NS}],
             roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": NAME})
    resource(lab, v1, "ConfigMap", CODE, immutable=True,
             data={"revoke.py": Path(__file__).with_name("revoke.py").read_text()})
    resource(lab, v1, "ConfigMap", DECISION, immutable=True, data={
        "review.json": json.dumps({"decision": "approved", "approval_id": approval_id,
                                   "credential": target}, sort_keys=True),
    })
    cron = resource(lab, "batch/v1", "CronJob", NAME, spec={
        "schedule": "* * * * *", "timeZone": "Etc/UTC", "suspend": True,
        "concurrencyPolicy": "Forbid", "startingDeadlineSeconds": 30,
        "jobTemplate": job_template(),
    })
    uid = cron["metadata"]["uid"]
    stayed_while_suspended = (
        cron["spec"]["suspend"] is True and jobs_for(lab, uid) == []
        and presence(lab, target) == f"secret/{target}"
        and presence(lab, unrelated) == f"secret/{unrelated}"
    )
    lab.kubectl("patch", "cronjob", NAME, "--type=merge", "-p", '{"spec":{"suspend":false}}')
    deadline = time.monotonic() + 85
    owned = jobs_for(lab, uid)
    while not owned and time.monotonic() < deadline:
        time.sleep(1)
        owned = jobs_for(lab, uid)
    if len(owned) != 1:
        lab.block("The native CronJob did not create exactly one scheduled credential job")
    job = owned[0]
    job_name = job["metadata"]["name"]
    lab.kubectl("wait", "--for=condition=Complete", f"job/{job_name}", "--timeout=45s", timeout=55)
    lab.kubectl("patch", "cronjob", NAME, "--type=merge", "-p", '{"spec":{"suspend":true}}')
    job_account = job["spec"]["template"]["spec"]["serviceAccountName"]
    observation = json.loads(lab.kubectl("logs", f"job/{job_name}").stdout.strip())
    principal = f"system:serviceaccount:{NS}:{NAME}"
    deleted_by_job = any(
        event.get("stage") == "ResponseComplete" and event.get("verb") == "delete"
        and event.get("user", {}).get("username") == principal
        and event.get("objectRef", {}).get("resource") == "secrets"
        and event.get("objectRef", {}).get("name") == target
        and event.get("responseStatus", {}).get("code") in (200, 202)
        for event in audit_events(lab)
    )
    evidence = {
        "suspended_schedule_keeps_both_credentials": stayed_while_suspended,
        "scheduled_job_identity_and_owner_match": job_account == NAME,
        "bound_worker_observed_success": observation == {"approved_credential_deleted": True},
        "authorized_deletion_observed_in_native_audit": deleted_by_job,
        "selected_credential_absent": not presence(lab, target),
        "unrelated_credential_present": presence(lab, unrelated) == f"secret/{unrelated}",
    }
    lab.check("automation", "The scheduled scoped Job revokes the exact approved legacy Secret",
              all(evidence.values()), evidence)
