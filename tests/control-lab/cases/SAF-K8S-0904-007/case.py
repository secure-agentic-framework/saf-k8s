"""Owned, inert CronJob hardening case for SAF-K8S-0904-007.

Run only through the supervisor's disposable Kind harness. This file never
contacts production clusters or executes a data-processing workload.
"""
from datetime import datetime
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
SCOPE = (
    "One fresh Kind v1.36.1 cluster and harness namespace; native Kubernetes "
    "ValidatingAdmissionPolicy enforcement for three exact labeled fixture "
    "resource kinds (CronJob, Job, Pod); API-server authorization decisions "
    "for named fixture CronJob access by dedicated service accounts; one "
    "actual CronJob-owned Job and Pod running a harmless marker; and one "
    "inert Job observed to fail with DeadlineExceeded. This does not establish "
    "production data permissions, workload safety, change governance or "
    "monitoring, cluster-wide policy coverage, or resistance to privileged "
    "administrators."
)

CONTROL = "SAF-K8S-0904-007"
PREFIX = "saf-0904-007"
CRONJOB = f"{PREFIX}-scheduled"
POLICY_NAMES = {
    "cronjobs": f"{PREFIX}-cronjob-policy",
    "jobs": f"{PREFIX}-job-policy",
    "pods": f"{PREFIX}-pod-policy",
}


def read_yaml(name):
    return HERE / name


def run(lab):
    # Fixtures are all confined to the harness-created saf-test namespace.
    lab.apply(read_yaml("rbac.yaml"))
    lab.apply(read_yaml("admission.yaml"))

    probes = [
        ("cronjobs", "cronjob-invalid.json", "CronJob policy rejects an unguarded template"),
        ("jobs", "job-invalid.json", "Job policy rejects a missing active deadline"),
        ("pods", "pod-invalid.json", "Pod policy rejects a missing security context"),
    ]
    inputs = [(kind, json.loads(read_yaml(filename).read_text()), claim)
              for kind, filename, claim in probes]
    for kind, resource, _ in inputs:
        red = lab.create(resource, dry_run=True, allow_failure=True)
        if red.returncode or not red.stdout:
            lab.block(f"The {kind} baseline did not reach native admission.")
        lab.check("red", f"The owned {kind} fixture is admitted with its policy unbound",
                  red.returncode == 0, {"server_dry_run_admitted": True,
                                       "object": resource["metadata"]["name"]})

    lab.apply(read_yaml("admission-bindings.yaml"))
    for kind, resource, claim in inputs:
        expected = POLICY_NAMES[kind]
        deadline = time.monotonic() + 12
        while True:
            denied = lab.create(resource, dry_run=True, allow_failure=True)
            matched = denied.returncode != 0 and expected in denied.stderr
            if matched or denied.returncode or time.monotonic() >= deadline:
                break
            time.sleep(0.25)
        if denied.returncode and expected not in denied.stderr:
            lab.block(f"{kind} admission rejected the fixture for an unrelated reason: {denied.stderr}")
        lab.check("green", claim, matched,
                  {"denied": matched, "policy": expected, "object": resource["metadata"]["name"]})

    # Exercise the authorization layer as named service-account subjects.
    # `kubectl auth can-i` submits a SelfSubjectAccessReview to this API server.
    reviewer = f"system:serviceaccount:saf-test:{PREFIX}-reviewer"
    runner = f"system:serviceaccount:saf-test:{PREFIX}-runner"
    editor = f"system:serviceaccount:saf-test:{PREFIX}-editor"
    checks = [
        (reviewer, "get", CRONJOB, True),
        (reviewer, "get", f"{PREFIX}-other", False),
        (reviewer, "patch", CRONJOB, False),
        (editor, "patch", CRONJOB, True),
        (editor, "patch", f"{PREFIX}-other", False),
        (runner, "get", CRONJOB, False),
    ]
    authz = []
    for subject, verb, name, expected in checks:
        response = lab.kubectl("auth", "can-i", verb, f"cronjobs.batch/{name}",
                               f"--as={subject}",
                               allow_failure=True)
        if (response.returncode, response.stdout.strip()) not in {(0, "yes"), (1, "no")}:
            lab.block("API-server authorization review failed: " + response.stderr.strip())
        actual = response.stdout.strip() == "yes"
        authz.append({"subject": subject.rsplit(":", 1)[-1], "verb": verb,
                      "resource_name": name, "allowed": actual})
        lab.check("green" if not expected else "positive",
                  f"API server authorization for {subject.rsplit(':', 1)[-1]} {verb} "
                  f"CronJob {name} is {'allowed' if expected else 'denied'}",
                  actual is expected, authz[-1])

    # Create a valid CronJob under active native admission and require its
    # controller-generated Job and Pod to carry the expected ownership chain.
    cronjob = json.loads(read_yaml("cronjob-valid.json").read_text())
    created = lab.create(cronjob)
    owner_uid = created["metadata"]["uid"]
    deadline = time.monotonic() + 85
    owned_jobs = []
    while time.monotonic() < deadline:
        listing = json.loads(lab.kubectl("get", "jobs", "-o", "json").stdout)
        owned_jobs = [row for row in listing["items"] if any(
            ref.get("kind") == "CronJob" and ref.get("uid") == owner_uid
            and ref.get("name") == CRONJOB
            for ref in row["metadata"].get("ownerReferences", []))]
        if owned_jobs:
            break
        time.sleep(2)
    if not owned_jobs:
        lab.block("The owned one-minute CronJob did not produce a Job within 85 seconds")
    job = owned_jobs[0]
    job_name = job["metadata"]["name"]
    scheduled_at = job.get("metadata", {}).get("annotations", {}).get(
        "batch.kubernetes.io/cronjob-scheduled-timestamp")
    if not scheduled_at:
        lab.block("Scheduled Job lacks the Kubernetes scheduled-timestamp annotation")
    try:
        datetime.fromisoformat(scheduled_at.replace("Z", "+00:00"))
    except ValueError as error:
        lab.block(f"Scheduled Job timestamp is not RFC3339-like: {error}")
    suspended = json.loads(lab.kubectl("patch", "cronjob", CRONJOB, "--type=merge", "-p",
                                      '{"spec":{"suspend":true}}', "-o", "json", f"--as={editor}").stdout)
    if suspended.get("spec", {}).get("suspend") is not True:
        lab.block("Scoped editor did not submit the expected suspension")
    wait = lab.kubectl("wait", "--for=condition=Complete", f"job/{job_name}",
                       "--timeout=50s", timeout=55, allow_failure=True)
    if wait.returncode:
        lab.block("Scheduled inert Job did not complete: " + wait.stderr.strip())
    job = json.loads(lab.kubectl("get", f"job/{job_name}", "-o", "json").stdout)
    output = lab.kubectl("logs", f"job/{job_name}").stdout.strip()
    pods = json.loads(lab.kubectl(
        "get", "pods", "-l", f"batch.kubernetes.io/job-name={job_name}", "-o", "json").stdout)["items"]
    pod = pods[0] if len(pods) == 1 else {}
    pod_owner = bool(pod) and any(
        ref.get("kind") == "Job" and ref.get("uid") == job["metadata"]["uid"]
        for ref in pod.get("metadata", {}).get("ownerReferences", []))
    hardened_pod = bool(pod) and pod["spec"].get("serviceAccountName") == f"{PREFIX}-runner" \
        and pod["spec"].get("automountServiceAccountToken") is False \
        and all(c.get("securityContext", {}).get("readOnlyRootFilesystem") is True
                and c.get("securityContext", {}).get("runAsNonRoot") is True
                and c.get("securityContext", {}).get("allowPrivilegeEscalation") is False
                and "ALL" in c.get("securityContext", {}).get("capabilities", {}).get("drop", [])
                for c in pod["spec"].get("containers", []))
    job_hardened = job.get("spec", {}).get("activeDeadlineSeconds") == 25 \
        and job.get("spec", {}).get("backoffLimit") == 0
    lab.check("positive", "A real CronJob-owned Job and Pod complete the harmless scheduled operation",
              output == "scheduled-ok" and pod_owner and hardened_pod and job_hardened
              and job.get("status", {}).get("succeeded") == 1,
              {"job_owner_matches": True, "pod_owner_matches": pod_owner, "named_editor_suspension": True,
               "scheduled_timestamp_present": True, "job_active_deadline_seconds":
                   job.get("spec", {}).get("activeDeadlineSeconds"),
               "pod_hardening_observed": hardened_pod, "result": output})

    # A separate harmless sleeper proves Job-controller expiry, not just a
    # configured deadline field. Its Pod remains subject to the same policy.
    lab.apply(read_yaml("deadline-job.yaml"))
    name = f"{PREFIX}-deadline"
    sleeper_seen = False
    end = time.monotonic() + 10
    while time.monotonic() < end:
        owned = json.loads(lab.kubectl("get", "pods", "-l", f"batch.kubernetes.io/job-name={name}",
                                       "-o", "json").stdout)["items"]
        if (len(owned) == 1 and any("running" in c.get("state", {}) and c.get("name") == "inert-sleeper"
                                   for c in owned[0].get("status", {}).get("containerStatuses", []))):
            sleeper_seen = True
            break
        time.sleep(0.3)
    if not sleeper_seen:
        lab.block("The harmless sleeper did not start before reaching its configured deadline")
    expired = lab.kubectl("wait", "--for=condition=Failed", f"job/{name}",
                          "--timeout=50s", timeout=55, allow_failure=True)
    if expired.returncode:
        lab.block("Deadline fixture did not reach a terminal Failed condition: "
                  + expired.stderr.strip())
    result = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
    failure = next((condition for condition in result.get("status", {}).get("conditions", [])
                    if condition.get("type") == "Failed" and condition.get("status") == "True"), {})
    started = result.get("status", {}).get("startTime")
    transition = failure.get("lastTransitionTime")
    if not started or not transition:
        lab.block("Job did not report start and failed-transition timestamps")
    start = datetime.fromisoformat(started.replace("Z", "+00:00"))
    finish = datetime.fromisoformat(transition.replace("Z", "+00:00"))
    elapsed = (finish - start).total_seconds()
    deadline = result.get("spec", {}).get("activeDeadlineSeconds")
    elapsed_matched = 12 <= elapsed <= 36
    lab.check("green", "The Job controller terminates the already-running sleeper at its active deadline",
              sleeper_seen and failure.get("reason") == "DeadlineExceeded"
              and deadline == 12 and elapsed_matched,
              {"failure_reason": failure.get("reason"), "active_deadline_seconds": deadline,
               "running_observed": sleeper_seen, "elapsed_in_expected_window": elapsed_matched})
    (lab.evidence / "cronjob-hardening.raw.json").write_text(json.dumps(
        {"cronjob": suspended, "scheduled_job": job, "scheduled_pod": pod,
         "deadline_job": result, "deadline_elapsed_seconds": elapsed,
         "authorization": authz}, indent=2) + "\n")
