"""Exercise CronJob scheduling with a version-mapped, scoped upstream scanner."""
from datetime import datetime, timezone
import json
import time

NODE_IMAGE = "kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256"
SCANNER = "docker.io/aquasec/kube-bench:v0.16.0@sha256:75506f222d1eb6ce2a751a5533bdc0a3b54c898e2e49e7751d0ee22cfb862679"
PROFILE = "cis-1.12"
CHECK_IDS = {"2.2", "2.5"}
SCAN_NAME = "saf-cis-recurring"
LABEL = f"app={SCAN_NAME}"
SCOPE = (
    "Disposable self-managed Kind Kubernetes v1.34.8. Executes a real kube-bench "
    "v0.16.0 scan for two selected etcd checks under CIS 1.12 on two ordinary "
    "CronJob schedule ticks. Reads the disposable node process view with hostPID, "
    "without host filesystem mounts or Kubernetes credentials. Full benchmark and "
    "managed-service coverage, production cadence, and post-upgrade profile selection remain open."
)


def prepare_kind(lab, temporary):
    profile = temporary / "kind.yaml"
    profile.write_text("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n- role: control-plane\n")
    return profile


def scheduled_jobs(lab):
    return json.loads(lab.kubectl("get", "jobs", "-l", LABEL, "-o", "json").stdout)["items"]


def scanner_receipt(lab, job, cronjob_uid):
    metadata = job["metadata"]
    name = metadata["name"]
    lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=90s", timeout=100)
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"batch.kubernetes.io/job-name={name}",
                                   "-o", "json").stdout)["items"]
    pod, = pods
    status, = pod["status"]["containerStatuses"]
    stdout = lab.kubectl("logs", f"job/{name}").stdout
    # The pinned CLI may print a version-detection warning before its single JSON record.
    records = [json.loads(line) for line in stdout.splitlines() if line.startswith('{"Controls":')]
    record, = records
    control, = record["Controls"]
    checks = {str(row["test_number"]): row["status"] for group in control["tests"]
              for row in group["results"]}
    owner_matches = any(ref["uid"] == cronjob_uid and ref["kind"] == "CronJob"
                        and ref.get("controller") is True for ref in metadata["ownerReferences"])
    return {
        "job": name, "job_uid": metadata["uid"], "pod_uid": pod["metadata"]["uid"],
        "scheduled_at": metadata["annotations"]["batch.kubernetes.io/cronjob-scheduled-timestamp"],
        "owner_matches": owner_matches, "exit": status["state"]["terminated"]["exitCode"],
        "image": status["imageID"], "profile": control["version"],
        "target": control["node_type"], "checks": checks,
    }


def run(lab):
    version = json.loads(lab.kubectl("get", "--raw=/version").stdout)["gitVersion"]
    if version != "v1.34.8":
        lab.block(f"Expected the version-mapped v1.34.8 release, got {version}")
    cronjob = lab.create({
        "apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": SCAN_NAME},
        "spec": {"schedule": "* * * * *", "timeZone": "Etc/UTC", "suspend": True,
                 "concurrencyPolicy": "Forbid", "startingDeadlineSeconds": 35,
                 "successfulJobsHistoryLimit": 3, "failedJobsHistoryLimit": 2,
                 "jobTemplate": {"metadata": {"labels": {"app": SCAN_NAME}}, "spec": {
                     "backoffLimit": 0, "activeDeadlineSeconds": 90,
                     "template": {"spec": {"hostPID": True, "restartPolicy": "Never",
                         "automountServiceAccountToken": False, "containers": [{
                             "name": "scanner", "image": SCANNER,
                             "command": ["kube-bench", "run", "--benchmark", PROFILE,
                                         "--targets", "etcd", "--check", "2.2,2.5", "--json",
                                         "--noremediations"],
                             "securityContext": {"allowPrivilegeEscalation": False,
                                                 "readOnlyRootFilesystem": True,
                                                 "capabilities": {"drop": ["ALL"]}},
                             "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                           "limits": {"cpu": "250m", "memory": "96Mi"}},
                         }]}}}}}})
    # Keep it suspended across an eligible UTC schedule tick.
    deadline = time.monotonic() + (60 - time.time() % 60) + 14
    observed_jobs = []
    while time.monotonic() < deadline:
        observed_jobs = scheduled_jobs(lab)
        if observed_jobs:
            break
        time.sleep(2)
    lab.check("red", "Suspended scanner creates no Job across a UTC schedule tick",
              not observed_jobs, {"suspended": True, "jobs": len(observed_jobs)})

    lab.kubectl("patch", "cronjob", SCAN_NAME, "--type=merge",
                "-p", '{"spec":{"suspend":false}}')
    deadline = time.monotonic() + 165
    while time.monotonic() < deadline:
        jobs = scheduled_jobs(lab)
        if len(jobs) >= 2:
            break
        time.sleep(2)
    else:
        lab.block("Two controller-scheduled scan Jobs did not appear")

    # Freeze the schedule once both distinct controllers have launched.
    lab.kubectl("patch", "cronjob", SCAN_NAME, "--type=merge",
                "-p", '{"spec":{"suspend":true}}')
    receipts = [scanner_receipt(lab, job, cronjob["metadata"]["uid"]) for job in jobs]
    (lab.evidence / "scan-receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
    times = sorted(datetime.fromisoformat(row["scheduled_at"].replace("Z", "+00:00"))
                   for row in receipts)
    repeated = (len(receipts) == 2 and len({row["job_uid"] for row in receipts}) == 2
                and len({row["pod_uid"] for row in receipts}) == 2
                and all(row["owner_matches"] for row in receipts)
                and (times[1] - times[0]).total_seconds() == 60
                and all(value.utcoffset() == timezone.utc.utcoffset(value) for value in times))
    lab.check("green", "Two separate CronJob-owned Jobs ran on consecutive UTC schedule ticks",
              repeated, {"jobs": len(receipts), "minute_spacing": repeated, "version": version})
    expected = dict.fromkeys(CHECK_IDS, "PASS")
    clean = all(row["exit"] == 0 and row["profile"] == PROFILE and row["target"] == "etcd"
                and row["checks"] == expected and "sha256:" in row["image"] for row in receipts)
    lab.check("positive", "Both actual scanner runs evaluated the pinned etcd checks successfully",
              clean, {"profile": PROFILE, "target": "etcd", "selected_checks": sorted(CHECK_IDS),
                      "checks_passed_both_times": clean})
