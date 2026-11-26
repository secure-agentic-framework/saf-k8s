"""Bounded namespace-wide count/jobs.batch admission witness.

Call run(lab) on an owned disposable Kubernetes cluster. This proves an
object-count ResourceQuota over Job objects in one namespace. Per-queue and
pending-only limits have separate evidence requirements.
"""

from __future__ import annotations

import json
import time


SUFFIX = "saf-0901-006-job-count"
NAMESPACE = SUFFIX
QUOTA = SUFFIX
COMPLETED = SUFFIX + "-completed"
HELD = SUFFIX + "-suspended"
REJECTED = SUFFIX + "-rejected"
REPLACEMENT = SUFFIX + "-replacement"
IMAGE = (
    "docker.io/library/busybox:1.37.0@"
    "sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
COUNT_KEY = "count/jobs.batch"


def _cmd(lab, *args, timeout=45, allow_failure=False, payload=None):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", f"--request-timeout={timeout - 5}s", *args,
        timeout=timeout, allow_failure=allow_failure, payload=payload,
    )


def _json(lab, *args):
    return json.loads(_cmd(lab, *args, "-o", "json").stdout)


def _job(name: str, *, suspended: bool) -> dict:
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {"saf-k8s.example/fixture": SUFFIX},
            "annotations": {"saf-k8s.example/purpose": "bounded-job-count-admission"},
        },
        "spec": {
            "suspend": suspended,
            "activeDeadlineSeconds": 75,
            "backoffLimit": 0,
            "template": {
                "metadata": {"labels": {"saf-k8s.example/fixture": SUFFIX}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "terminationGracePeriodSeconds": 1,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 65534,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [{
                        "name": "finite",
                        "image": IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["/bin/sh", "-c", "printf '%s\\n' saf-job-count-fixture"],
                        "resources": {"requests": {"cpu": "10m", "memory": "8Mi"}},
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]},
                        },
                    }],
                },
            },
        },
    }


def _usage(lab):
    quota = _json(lab, "-n", NAMESPACE, "get", "resourcequota", QUOTA)
    return quota, quota.get("status", {}).get("used", {}).get(COUNT_KEY)


def _wait_usage(lab, expected: str, seconds=30):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        quota, used = _usage(lab)
        last = {"quota": quota, "used": used}
        if used == expected:
            return quota
        time.sleep(0.5)
    lab.block(f"ResourceQuota usage did not reach {expected}; last={last!r}")


def _wait_job(lab, name, predicate, description, seconds=60):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = _json(lab, "-n", NAMESPACE, "get", "job", name)
        if predicate(last):
            return last
        time.sleep(0.5)
    lab.block(f"Timed out waiting for {description}; last={last!r}")


def _pods_owned_by_job(lab, job_uid):
    pods = _json(lab, "-n", NAMESPACE, "get", "pods").get("items", [])
    return [pod for pod in pods if any(
        owner.get("kind") == "Job" and owner.get("apiVersion") == "batch/v1"
        and owner.get("uid") == job_uid
        for owner in pod.get("metadata", {}).get("ownerReferences", []))]


def _complete(job):
    return any(row.get("type") == "Complete" and row.get("status") == "True"
               for row in job.get("status", {}).get("conditions", []))


def _create_job(lab, name, *, suspended, dry_run=False, allow_failure=False):
    flags = ["--dry-run=server"] if dry_run else []
    return _cmd(lab, "-n", NAMESPACE, "create", "-f", "-", "-o", "json", *flags,
                payload=json.dumps(_job(name, suspended=suspended), sort_keys=True),
                allow_failure=allow_failure)


def _job_is_absent(lab, name):
    result = _cmd(lab, "-n", NAMESPACE, "get", "job", name,
                  "--ignore-not-found", "-o", "json", allow_failure=True)
    return result.returncode == 0 and not result.stdout.strip()


def run(lab):
    raw = {"namespace": NAMESPACE, "quota_name": QUOTA, "count_key": COUNT_KEY, "stages": {}}

    def retain(stage, **observed):
        raw["stages"][stage] = observed
        (lab.evidence / "count-jobs-intake-raw.json").write_text(
            json.dumps(raw, indent=2, sort_keys=True) + "\n")

    _cmd(lab, "create", "namespace", NAMESPACE)
    _create_job(lab, COMPLETED, suspended=False)
    completed = _wait_job(lab, COMPLETED, _complete, "the finite Job to complete")
    completed_uid = completed["metadata"]["uid"]
    _create_job(lab, HELD, suspended=True)
    held = _json(lab, "-n", NAMESPACE, "get", "job", HELD)
    held_uid = held["metadata"]["uid"]
    held_pods = _pods_owned_by_job(lab, held_uid)
    before_jobs = _json(lab, "-n", NAMESPACE, "get", "jobs")["items"]
    no_quota = _json(lab, "-n", NAMESPACE, "get", "resourcequota")["items"] == []
    baseline = json.loads(_create_job(lab, REJECTED, suspended=True, dry_run=True).stdout)
    baseline_absent = _job_is_absent(lab, REJECTED)
    comparable = {row["metadata"]["uid"] for row in before_jobs} == {completed_uid, held_uid}
    retain("before_quota", jobs=before_jobs, held_owned_pods=held_pods,
           request=baseline, dry_run_object_absent=baseline_absent, no_quota=no_quota)
    lab.check("red", "With two stored Jobs and no count quota, the same third Job is admissible",
              no_quota and comparable and baseline_absent
              and baseline["metadata"]["name"] == REJECTED and baseline["spec"]["suspend"] is True,
              {"stored_jobs": len(before_jobs), "third_dry_run_allowed": True,
               "dry_run_object_absent": baseline_absent, "quota_absent": no_quota})

    _cmd(lab, "apply", "-f", "-", payload=json.dumps({
        "apiVersion": "v1", "kind": "ResourceQuota",
        "metadata": {"name": QUOTA, "namespace": NAMESPACE},
        "spec": {"hard": {COUNT_KEY: "2"}},
    }, sort_keys=True))
    quota = _wait_usage(lab, "2")
    quota_uid = quota["metadata"]["uid"]
    retain("quota_active", quota=quota, completed=completed, suspended=held)
    lab.check("positive", "The quota counts both the retained completed Job and the suspended Job",
              comparable and _complete(completed) and held.get("spec", {}).get("suspend") is True
              and held_pods == [] and quota["status"]["hard"].get(COUNT_KEY) == "2",
              {"hard_limit": "2", "used_count": "2", "completed_job_counted": True,
               "suspended_job_counted": True, "suspended_job_owned_pods": len(held_pods)})

    denied = _create_job(lab, REJECTED, suspended=True, allow_failure=True)
    denial = denied.stderr + denied.stdout
    exact_denial = all(fragment in denial for fragment in (
        "(Forbidden)", "exceeded quota: " + QUOTA, f"requested: {COUNT_KEY}=1",
        f"used: {COUNT_KEY}=2", f"limited: {COUNT_KEY}=2",
    ))
    denied_absent = _job_is_absent(lab, REJECTED)
    quota_after_denial = _wait_usage(lab, "2")
    retain("quota_denial", returncode=denied.returncode, message=denial,
           absent=denied_absent, quota=quota_after_denial)
    lab.check("green", "The exact Job-count quota refuses the third create and leaves no Job",
              denied.returncode != 0 and exact_denial and denied_absent
              and quota_after_denial["metadata"]["uid"] == quota_uid,
              {"forbidden_by_exact_quota": exact_denial, "rejected_job_absent": denied_absent,
               "used_count": "2"})

    # Raw kubectl DELETE reads these Kubernetes DeleteOptions bytes from stdin.
    uri = f"/apis/batch/v1/namespaces/{NAMESPACE}/jobs/{COMPLETED}"
    options = {"apiVersion": "v1", "kind": "DeleteOptions",
               "propagationPolicy": "Foreground", "preconditions": {"uid": completed_uid}}
    deleted = _cmd(lab, "delete", "--raw", uri, "-f", "-", payload=json.dumps(options))
    quota = _wait_usage(lab, "1")
    held_now = _json(lab, "-n", NAMESPACE, "get", "job", HELD)
    completed_absent = _job_is_absent(lab, COMPLETED)
    held_unchanged = held_now["metadata"]["uid"] == held_uid and held_now["spec"].get("suspend") is True
    retain("completed_job_retired", delete_options=options, response=json.loads(deleted.stdout),
           completed_absent=completed_absent, suspended_job=held_now, quota=quota)
    lab.check("positive", "Deleting the completed Job by UID frees one slot while the suspended Job remains",
              completed_absent and held_unchanged and quota["metadata"]["uid"] == quota_uid,
              {"completed_job_absent": completed_absent, "same_suspended_job_retained": held_unchanged,
               "used_count": "1"})

    _create_job(lab, REPLACEMENT, suspended=False)
    replacement = _wait_job(lab, REPLACEMENT, _complete, "the replacement Job to complete")
    quota = _wait_usage(lab, "2")
    final_jobs = _json(lab, "-n", NAMESPACE, "get", "jobs")["items"]
    exact_final_count = {row["metadata"]["uid"] for row in final_jobs} == {held_uid, replacement["metadata"]["uid"]}
    retain("replacement_admitted", replacement=replacement, quota=quota, exact_job_objects=final_jobs)
    lab.check("positive", "A replacement Job completes and fills the freed object-count slot",
              exact_final_count and _complete(replacement) and quota["metadata"]["uid"] == quota_uid,
              {"replacement_completed": True, "exact_two_job_objects": exact_final_count, "used_count": "2"})

    _cmd(lab, "delete", "namespace", NAMESPACE, "--wait=true", timeout=90)
    absent = _cmd(lab, "get", "namespace", NAMESPACE, "--ignore-not-found", "-o", "json",
                  allow_failure=True)
    cleaned = absent.returncode == 0 and not absent.stdout.strip()
    retain("cleanup", namespace_absent=cleaned)
    lab.check("positive", "The owned Job-count namespace is removed", cleaned,
              {"namespace_absent": cleaned})
