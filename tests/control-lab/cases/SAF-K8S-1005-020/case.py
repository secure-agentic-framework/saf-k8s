"""Run a synthetic ownership, escalation, and handoff coordination Job."""
import json
from pathlib import Path
import re

from fixtures import BUSYBOX_IMAGE


HERE = Path(__file__).parent
NAMESPACE = "saf-test"
JOB_NAME = "synthetic-coordination-review"
SCOPE = (
    "One offline, one-shot Job classifies synthetic vulnerability-coordination records for "
    "missing owners, missing escalation routes, unacknowledged handoffs, open work, and "
    "approved closure. The Job reads only a mounted fixture and makes no provider, upstream, "
    "external-contact, or Kubernetes API calls. This verifies the fixture evaluator and Job "
    "execution in disposable Kind v1.36.1; it does not establish organizational ownership, "
    "real acknowledgments, provider processes, contact behavior, or production coverage."
)


def run(lab):
    records = (HERE / "fixtures" / "coordination-records.tsv").read_text(encoding="utf-8")
    validator = (HERE / "validator.sh").read_text(encoding="utf-8")
    config = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "synthetic-coordination-fixtures", "namespace": NAMESPACE},
        "immutable": True,
        "data": {"coordination-records.tsv": records, "validator.sh": validator},
    }
    lab.create(config)

    lab.create({
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "synthetic-coordination-deny-all", "namespace": NAMESPACE},
        "spec": {"podSelector": {"matchLabels": {"app": JOB_NAME}},
                 "policyTypes": ["Egress"]},
    })

    job = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": JOB_NAME, "namespace": NAMESPACE,
                     "labels": {"app": JOB_NAME}},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 60,
            "ttlSecondsAfterFinished": 300,
            "template": {
                "metadata": {"labels": {"app": JOB_NAME}},
                "spec": {
                    "serviceAccountName": "default",
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "restartPolicy": "Never",
                    "containers": [{
                        "name": "coordination-review", "image": BUSYBOX_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["/bin/sh", "/app/validator.sh", "/fixtures/coordination-records.tsv"],
                        "resources": {
                            "requests": {"cpu": "10m", "memory": "16Mi"},
                            "limits": {"cpu": "100m", "memory": "32Mi"},
                        },
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "volumeMounts": [
                            {"name": "app", "mountPath": "/app", "readOnly": True},
                            {"name": "fixtures", "mountPath": "/fixtures", "readOnly": True},
                        ],
                    }],
                    "volumes": [
                        {"name": "app", "configMap": {
                            "name": "synthetic-coordination-fixtures",
                            "items": [{"key": "validator.sh", "path": "validator.sh"}],
                        }},
                        {"name": "fixtures", "configMap": {
                            "name": "synthetic-coordination-fixtures",
                            "items": [{"key": "coordination-records.tsv", "path": "coordination-records.tsv"}],
                        }},
                    ],
                },
            },
        },
    }
    lab.create(job)
    waited = lab.kubectl("wait", f"job/{JOB_NAME}", "--for=condition=complete", "--timeout=90s",
                         timeout=100, allow_failure=True)
    complete = waited.returncode == 0
    lab.check("positive", "The bounded synthetic coordination Job completes successfully",
              complete, {"job_complete": complete, "wait_output": waited.stdout.strip(),
                         "wait_error": waited.stderr.strip()})

    job_status = json.loads(lab.kubectl("get", "job", JOB_NAME, "-o", "json").stdout)
    pod_list = json.loads(lab.kubectl("get", "pods", "-l", f"app={JOB_NAME}", "-o", "json").stdout)
    logs = lab.kubectl("logs", f"job/{JOB_NAME}").stdout
    observed = {"bypass": {}, "enforced": {}}
    for line in logs.splitlines():
        match = re.fullmatch(r"OBSERVATION\|(bypass|enforced)\|([a-z-]+)\|([a-z_]+)", line)
        if not match:
            lab.block("The synthetic Job returned an unrecognized observation")
        mode, name, state = match.groups()
        if name in observed[mode]:
            lab.block("The synthetic Job returned a duplicate observation")
        observed[mode][name] = state
    pods = pod_list["items"]
    if len(pods) != 1:
        lab.block("Expected exactly one Job Pod for the synthetic review")
    pod = pods[0]
    owner_references = pod["metadata"].get("ownerReferences", [])
    owned_job = any(ref["kind"] == "Job" and ref["uid"] == job_status["metadata"]["uid"]
                    and ref.get("controller", False) for ref in owner_references)
    pod_spec = pod.get("spec", {})
    service_account_token_disabled = pod_spec.get("automountServiceAccountToken") is False
    no_api_token_volume = not any(
        volume.get("projected", {}).get("sources")
        and any("serviceAccountToken" in source for source in volume["projected"]["sources"])
        for volume in pod_spec.get("volumes", [])
    )
    independent_evidence = {
        "job_succeeded": job_status.get("status", {}).get("succeeded") == 1,
        "pod_succeeded": pod.get("status", {}).get("phase") == "Succeeded",
        "service_account_token_disabled": service_account_token_disabled,
        "no_projected_api_token": no_api_token_volume,
        "observed_classifications": observed,
    }

    bypass = observed["bypass"]
    enforced = observed["enforced"]
    withheld = {
        "missing-owner": "missing_owner",
        "missing-escalation": "missing_escalation",
        "unacknowledged-handoff": "unacknowledged_handoff",
    }
    lab.check("red", "Without the coordination checks all three incomplete requests would close",
              all(bypass.get(name) == "approved_closure" for name in withheld), bypass)
    lab.check("green", "The same requests are withheld for their distinct coordination gaps",
              {name: enforced.get(name) for name in withheld} == withheld, enforced)
    expected = {**withheld, "ready-open": "open", "approved-closure": "approved_closure"}
    lab.check("positive", "Acknowledged work can remain open and complete approved work can close",
              enforced == expected
              and independent_evidence["job_succeeded"] and independent_evidence["pod_succeeded"]
              and owned_job and service_account_token_disabled and no_api_token_volume,
              {**independent_evidence, "pod_owned_by_job": owned_job})
    (lab.evidence / "coordination-observations.raw.json").write_text(
        json.dumps({**independent_evidence, "pod_owned_by_job": owned_job,
                    "job_uid": job_status["metadata"]["uid"], "pod_uid": pod["metadata"]["uid"]},
                   indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
