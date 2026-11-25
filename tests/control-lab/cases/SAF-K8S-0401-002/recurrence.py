"""Bounded CronJob recurrence check for SAF-K8S-0401-002's named GET gap."""
from datetime import datetime, timezone
import json
import time

NAMESPACE = "saf-0401-002"
CASE_LABEL = "saf-k8s.example/control-case"
CASE_VALUE = "SAF-K8S-0401-002"
CRON = "saf-0401-002-recurrence"
SA = "saf-0401-002-audited-reader"
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"

WORKER = r'''import datetime, json, os, ssl, urllib.request

HOST = os.environ["KUBERNETES_SERVICE_HOST"]
PORT = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
BASE = "https://%s:%s" % (HOST, PORT)
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
TOKEN = open(TOKEN_PATH, encoding="utf-8").read().strip()
CTX = ssl.create_default_context(cafile=CA_PATH)

# These are fixed, harmless authorization questions. No target object is read or changed.
def review(name):
    body = {
      "apiVersion": "authorization.k8s.io/v1",
      "kind": "SelfSubjectAccessReview",
      "spec": {"resourceAttributes": {
        "namespace": "saf-0401-002", "verb": "get", "group": "",
        "resource": "configmaps", "name": name
      }}
    }
    req = urllib.request.Request(
      BASE + "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
      data=json.dumps(body, separators=(",", ":")).encode(),
      headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
      method="POST")
    # urlopen errors (including HTTP errors), TLS failures, timeouts and bad JSON
    # propagate as Job failures. Only a valid HTTP response with boolean
    # status.allowed=false is interpreted as a denial.
    with urllib.request.urlopen(req, context=CTX, timeout=8) as response:
        if response.status != 201:
            raise RuntimeError("unexpected SelfSubjectAccessReview HTTP status %d" % response.status)
        result = json.loads(response.read())
    status = result.get("status")
    if not isinstance(status, dict):
        raise RuntimeError("SelfSubjectAccessReview response has no status object")
    if status.get("evaluationError"):
        raise RuntimeError("authorization evaluation error: " + str(status["evaluationError"]))
    allowed = status.get("allowed")
    if type(allowed) is not bool:
        raise RuntimeError("SelfSubjectAccessReview response lacks boolean status.allowed")
    return {"allowed": allowed, "reason": status.get("reason", "")}

required = review("saf-0401-002-required-config")
unneeded = review("saf-0401-002-unneeded-config")
if required["allowed"] and unneeded["allowed"]:
    disposition = "open: unneeded named GET is currently allowed; remove the case-owned binding"
elif required["allowed"] and not unneeded["allowed"]:
    disposition = "remediated: required named GET remains allowed and unneeded named GET is denied"
else:
    disposition = "regression: required named GET is denied"
print(json.dumps({
  "control": "SAF-K8S-0401-002",
  "owner": "saf-k8s-control-lab",
  "due": "each scheduled run",
  "disposition": disposition,
  "evidence": {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "job_name": os.environ.get("JOB_NAME", "unknown")},
  "requests": {
    "get_configmap_saf-0401-002-required-config": required,
    "get_configmap_saf-0401-002-unneeded-config": unneeded
  }
}, sort_keys=True, separators=(",", ":")), flush=True)
'''


def _cluster_objects(run_id):
    labels = {CASE_LABEL: CASE_VALUE, "saf-k8s.example/recurrence-run": run_id}
    return [
        # SelfSubjectAccessReview is cluster-scoped, so the grant and binding
        # must be ClusterRole/ClusterRoleBinding. No ConfigMap permission is granted.
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
         "metadata": {"name": run_id, "labels": labels}, "rules": [
             {"apiGroups": ["authorization.k8s.io"], "resources": ["selfsubjectaccessreviews"], "verbs": ["create"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
         "metadata": {"name": run_id, "labels": labels},
         "subjects": [{"kind": "ServiceAccount", "name": SA, "namespace": NAMESPACE}],
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": run_id}},
    ]


def _cronjob(run_id):
    labels = {CASE_LABEL: CASE_VALUE, "saf-k8s.example/recurrence-run": run_id}
    return {
        "apiVersion": "batch/v1", "kind": "CronJob",
        "metadata": {"name": CRON, "namespace": NAMESPACE, "labels": labels},
        "spec": {
            "schedule": "* * * * *",
            "concurrencyPolicy": "Forbid",
            "startingDeadlineSeconds": 50,
            "successfulJobsHistoryLimit": 3,
            "failedJobsHistoryLimit": 1,
            "jobTemplate": {
                "metadata": {"labels": labels},
                "spec": {
                    "backoffLimit": 0,
                    "activeDeadlineSeconds": 35,
                    "template": {
                        "metadata": {"labels": labels},
                        "spec": {
                            "serviceAccountName": SA,
                            "automountServiceAccountToken": True,
                            "restartPolicy": "Never",
                            "securityContext": {
                                "runAsNonRoot": True,
                                "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "containers": [{
                                "name": "fixed-authorization-review",
                                "image": PYTHON_IMAGE,
                                "imagePullPolicy": "IfNotPresent",
                                "command": ["python", "-c", WORKER],
                                "env": [{
                                    "name": "JOB_NAME",
                                    "valueFrom": {"fieldRef": {"fieldPath": "metadata.labels['batch.kubernetes.io/job-name']"}},
                                }],
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]},
                                },
                                "resources": {
                                    "requests": {"cpu": "10m", "memory": "32Mi"},
                                    "limits": {"cpu": "100m", "memory": "64Mi"},
                                },
                            }],
                        },
                    },
                },
            },
        },
    }


def _owned_jobs(lab, run_id, cron_uid):
    data = json.loads(lab.kubectl("-n", NAMESPACE, "get", "jobs", "-l",
        f"saf-k8s.example/recurrence-run={run_id}", "-o", "json", timeout=12).stdout)
    return [job for job in data.get("items", []) if any(
        ref.get("uid") == cron_uid and ref.get("kind") == "CronJob" and ref.get("controller")
        for ref in job.get("metadata", {}).get("ownerReferences", []))]


def _wait_job(lab, run_id, cron_uid, *, after_scheduled=None, timeout=85):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for job in _owned_jobs(lab, run_id, cron_uid):
            ann = job.get("metadata", {}).get("annotations", {})
            scheduled = ann.get("batch.kubernetes.io/cronjob-scheduled-timestamp")
            if job.get("status", {}).get("failed", 0):
                job_name = job["metadata"]["name"]
                lab.kubectl("-n", NAMESPACE, "get", "pods", "-l",
                            f"batch.kubernetes.io/job-name={job_name}", "-o", "wide",
                            timeout=15, allow_failure=True)
                lab.kubectl("-n", NAMESPACE, "describe", "job", job_name,
                            timeout=15, allow_failure=True)
                lab.kubectl("-n", NAMESPACE, "logs", "job/" + job_name,
                            timeout=12, allow_failure=True)
                failed = next((item.get("reason", "unknown") for item in job["status"].get("conditions", [])
                               if item.get("type") == "Failed"), "unknown")
                lab.block(f"Scheduled review Job failed ({failed}): {job_name}")
            if not scheduled and job.get("status", {}).get("succeeded", 0) == 1:
                raise RuntimeError("CronJob-owned Job lacks its scheduled-time annotation")
            if after_scheduled and (not scheduled or scheduled <= after_scheduled):
                continue
            if job.get("status", {}).get("succeeded", 0) == 1:
                pod_data = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pods", "-l",
                    f"batch.kubernetes.io/job-name={job['metadata']['name']}", "-o", "json").stdout)
                pods = pod_data.get("items", [])
                if len(pods) != 1:
                    raise RuntimeError("expected exactly one pod for scheduled review job")
                logs = lab.kubectl("-n", NAMESPACE, "logs", pods[0]["metadata"]["name"]).stdout
                rows = [line for line in logs.splitlines() if line.strip()]
                if len(rows) != 1:
                    raise RuntimeError("scheduled review did not emit exactly one JSON evidence line")
                observed = json.loads(rows[0])
                if observed.get("evidence", {}).get("observed_at") in (None, "", "unknown"):
                    raise RuntimeError("job lacks worker observation timestamp evidence")
                evidence = observed["evidence"]
                if evidence.get("job_name") != job["metadata"]["name"]:
                    lab.block("The observation did not identify its owning Job")
                observed_at = datetime.fromisoformat(evidence["observed_at"])
                scheduled_at = datetime.fromisoformat(scheduled.replace("Z", "+00:00"))
                if observed_at < scheduled_at:
                    lab.block("The Job observation precedes its scheduled time")
                return observed, scheduled
        time.sleep(1)
    lab.block(f"No matching CronJob Job completed within {timeout}s")


def prepare_worker_image(lab):
    """Ready the exact worker image separately from the real CronJob deadline."""
    name = CRON + "-image-check"
    worker = _cronjob(CRON)["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    container = worker["containers"][0]
    container["command"] = ["python", "-c", "print('fixture image ready')"]
    container.pop("env")
    worker["automountServiceAccountToken"] = False
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": name, "namespace": NAMESPACE}, "spec": worker}
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "name",
                payload=json.dumps(pod))
    try:
        prepared = lab.kubectl("-n", NAMESPACE, "wait", "--for=jsonpath={.status.phase}=Succeeded",
                               "pod/" + name, "--timeout=100s", timeout=110, allow_failure=True)
        if prepared.returncode:
            lab.kubectl("-n", NAMESPACE, "describe", "pod", name, timeout=15, allow_failure=True)
            lab.block("The exact digest-pinned audit worker image did not become usable before scheduling")
    finally:
        lab.kubectl("-n", NAMESPACE, "delete", "pod", name, "--ignore-not-found=true", timeout=20)


def run(lab):
    prepare_worker_image(lab)
    run_id = CRON
    for obj in _cluster_objects(run_id):
        lab.create(obj)

    # Inline Python keeps the job self-contained and relies on no shell, sidecar,
    # ConfigMap mount, or additional runtime permission.
    creation = lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "json",
                           payload=json.dumps(_cronjob(run_id)))
    cron = json.loads(creation.stdout)
    cron_uid = cron["metadata"]["uid"]

    first, first_scheduled = _wait_job(lab, run_id, cron_uid)
    first_requests = first.get("requests", {})
    gap_ok = (
        first_requests.get("get_configmap_saf-0401-002-required-config", {}).get("allowed") is True
        and first_requests.get("get_configmap_saf-0401-002-unneeded-config", {}).get("allowed") is True
        and first.get("disposition", "").startswith("open:")
    )
    lab.check("red", "A real scheduled CronJob records the current named-access gap with a valid API response",
              gap_ok, {
                  "schedule": "* * * * *",
                  "job_owner_verified": True,
                  "request_decisions": {key: value["allowed"] for key, value in first_requests.items()},
                  "finding": {key: first[key] for key in ("owner", "due", "disposition")},
              })

    # Reconcile only the intentionally excessive case RoleBinding, preserving the required binding.
    lab.kubectl("-n", NAMESPACE, "delete", "rolebinding", "saf-0401-002-unneeded-reader")
    second, second_scheduled = _wait_job(
        lab, run_id, cron_uid, after_scheduled=first_scheduled)
    second_requests = second.get("requests", {})
    confirmation_ok = (
        second_requests.get("get_configmap_saf-0401-002-required-config", {}).get("allowed") is True
        and second_requests.get("get_configmap_saf-0401-002-unneeded-config", {}).get("allowed") is False
        and second.get("disposition", "").startswith("remediated:")
    )
    lab.check("green", "A later scheduled CronJob confirms the change: required named GET allowed, unnecessary named GET denied",
              confirmation_ok, {"change": "deleted only case-owned saf-0401-002-unneeded-reader RoleBinding",
                               "distinct_later_schedule": second_scheduled > first_scheduled,
                               "job_owner_verified": True,
                               "request_decisions": {key: value["allowed"] for key, value in second_requests.items()},
                               "finding": {key: second[key] for key in ("owner", "due", "disposition")}})

    # Keep the surrounding canonical case's labeled RBAC inventory exact and
    # leave no active schedule behind in its disposable namespace.
    lab.kubectl("-n", NAMESPACE, "delete", "cronjob", CRON)
    lab.kubectl("delete", "clusterrolebinding", run_id)
    lab.kubectl("delete", "clusterrole", run_id)
