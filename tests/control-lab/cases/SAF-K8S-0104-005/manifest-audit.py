"""Observe two version-matched scanner runs over one live manifest's metadata."""
import json
import time


PROFILE = "cis-1.12"
FILE = "/etc/kubernetes/manifests/kube-apiserver.yaml"
SCANNER = ("docker.io/aquasec/kube-bench:v0.16.0@sha256:"
           "75506f222d1eb6ce2a751a5533bdc0a3b54c898e2e49e7751d0ee22cfb862679")
CHECKS = {"1.1.1": "PASS", "1.1.2": "PASS"}
SCHEDULED = "fixture-manifest-metadata"


def spec(node):
    return {"backoffLimit": 0, "activeDeadlineSeconds": 60, "template": {"spec": {
        "nodeName": node, "restartPolicy": "Never", "automountServiceAccountToken": False,
        "containers": [{"name": "scanner", "image": SCANNER,
                        "command": ["kube-bench", "run", "--benchmark", PROFILE, "--targets", "master",
                                    "--check", "1.1.1,1.1.2", "--json", "--noremediations"],
                        "volumeMounts": [{"name": "manifest", "mountPath": FILE, "readOnly": True}],
                        "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]},
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                      "limits": {"cpu": "250m", "memory": "96Mi"}}}],
        "volumes": [{"name": "manifest", "hostPath": {"path": FILE, "type": "File"}}],
    }}}


def get(lab, *args):
    return json.loads(lab.kubectl("get", *args, "-o", "json").stdout)


def scan(lab, name, node):
    lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=65s", timeout=72)
    job = get(lab, "job", name)
    pod, = get(lab, "pods", "-l", f"batch.kubernetes.io/job-name={name}")["items"]
    reports = [json.loads(line) for line in lab.kubectl("logs", f"job/{name}").stdout.splitlines()
               if line.startswith('{"Controls":')]
    report, = reports
    section, = report["Controls"]
    checks = {row["test_number"]: row["status"] for group in section["tests"] for row in group["results"]}
    status, = pod["status"]["containerStatuses"]
    valid = (section["version"] == PROFILE and section["node_type"] == "master"
             and pod["spec"]["nodeName"] == node
             and status["state"]["terminated"]["exitCode"] == 0
             and status["imageID"] and checks == CHECKS)
    return job, pod, checks, bool(valid)


def run(lab):
    node = f"{lab.cluster}-control-plane"
    actual = json.loads(lab.kubectl("get", "--raw=/version").stdout)["gitVersion"]
    if actual != "v1.34.8":
        lab.block("Version-matched CIS 1.12 path requires the pinned Kubernetes v1.34.8 profile")
    lab.create({"apiVersion": "batch/v1", "kind": "Job",
                "metadata": {"name": "fixture-provisioning-manifest-metadata"}, "spec": spec(node)})
    before, pod1, first, verified = scan(lab, "fixture-provisioning-manifest-metadata", node)
    lab.check("positive", "The version-matched scanner checks live API server manifest mode and ownership",
              verified, {"kubernetes": actual, "benchmark": PROFILE, "selected_checks": first})

    owner = lab.create({"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": SCHEDULED},
                        "spec": {"schedule": "* * * * *", "timeZone": "Etc/UTC",
                                 "startingDeadlineSeconds": 30, "concurrencyPolicy": "Forbid",
                                 "jobTemplate": {"metadata": {"labels": {"app": SCHEDULED}}, "spec": spec(node)}}})
    deadline = time.monotonic() + 95
    planned = []
    while not planned and time.monotonic() < deadline:
        planned = get(lab, "jobs", "-l", f"app={SCHEDULED}")["items"]
        if not planned:
            time.sleep(1)
    if not planned:
        lab.block("No controller-owned recurring metadata scan was observed")
    followup, pod2, second, rescanned = scan(lab, planned[0]["metadata"]["name"], node)
    meta = followup["metadata"]
    owned = any(ref["uid"] == owner["metadata"]["uid"] and ref.get("controller")
                for ref in meta["ownerReferences"])
    scheduled = meta["annotations"].get("batch.kubernetes.io/cronjob-scheduled-timestamp")
    separate = meta["uid"] != before["metadata"]["uid"] and pod1["metadata"]["uid"] != pod2["metadata"]["uid"]
    lab.check("green", "A controller-scheduled scan repeats both checks on the same owned node",
              rescanned and owned and scheduled and separate,
              {"scheduled_timestamp_present": bool(scheduled), "owned_cronjob": owned,
               "independent_job_and_pod": separate, "selected_checks": second})
    (lab.evidence / "manifest-metadata-scans.raw.json").write_text(json.dumps({
        "profile": PROFILE, "server": actual, "initial_checks": first, "scheduled_checks": second,
        "initial_job": before["metadata"]["uid"], "scheduled_job": meta["uid"],
        "scheduled_timestamp": scheduled, "scanner_image_id": pod2["status"]["containerStatuses"][0]["imageID"],
        "manifest": FILE,
    }, indent=2) + "\n")
