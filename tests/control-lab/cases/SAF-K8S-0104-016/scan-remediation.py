"""Record a real, same-check file-mode correction in an owned Kind node."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path


PROFILE = "cis-1.12"
CHECK = "4.1.9"
CONFIG = "/var/lib/kubelet/config.yaml"
SCANNER = ("docker.io/aquasec/kube-bench:v0.16.0@sha256:"
           "75506f222d1eb6ce2a751a5533bdc0a3b54c898e2e49e7751d0ee22cfb862679")
TARGET_VERSION = "v1.34.8"
IDENTITY = ("node_uid", "server_version", "profile", "target", "check_id", "scanner_image")


def clock():
    return datetime.now(timezone.utc)


def get(lab, *args):
    return json.loads(lab.kubectl("get", *args, "-o", "json").stdout)


def metadata(lab, node):
    output = lab.command("docker", "exec", node, "stat", "-c", "%a %i %u %g %F", "--", CONFIG)
    mode, inode, uid, gid, kind = output.stdout.strip().split(" ", 4)
    if kind != "regular file" or uid != "0" or gid != "0":
        lab.block("Expected the regular root-owned kubelet file on the disposable node")
    return {"mode": mode, "inode": inode, "uid": uid, "gid": gid}


def scan(lab, target_node, job, server):
    label = {"app": "saf-cis-retest"}
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": job, "labels": label},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65,
                 "template": {"metadata": {"labels": label}, "spec": {
                     "nodeName": target_node["metadata"]["name"], "restartPolicy": "Never",
                     "automountServiceAccountToken": False,
                     "containers": [{
                         "name": "scanner", "image": SCANNER,
                         "command": ["kube-bench", "run", "--benchmark", PROFILE,
                                     "--targets", "node", "--check", CHECK, "--json", "--noremediations"],
                         "volumeMounts": [{"name": "kubelet-metadata", "mountPath": CONFIG, "readOnly": True}],
                         "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False,
                                             "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]},
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                       "limits": {"cpu": "250m", "memory": "96Mi"}},
                     }],
                     "volumes": [{"name": "kubelet-metadata",
                                  "hostPath": {"path": CONFIG, "type": "File"}}],
                 }}},
    })
    lab.kubectl("wait", "--for=condition=Complete", f"job/{job}", "--timeout=75s", timeout=80)
    job_object = get(lab, "job", job)
    pod, = get(lab, "pods", "-l", f"batch.kubernetes.io/job-name={job}")["items"]
    status, = pod["status"]["containerStatuses"]
    if (pod["spec"]["nodeName"] != target_node["metadata"]["name"]
            or not any(ref["uid"] == job_object["metadata"]["uid"] and ref.get("controller")
                       for ref in pod["metadata"]["ownerReferences"])
            or status["state"]["terminated"]["exitCode"] != 0):
        lab.block("Scanner receipt does not identify a successful scan Job on the selected node")
    output = lab.kubectl("logs", f"job/{job}").stdout
    report, = [json.loads(line) for line in output.splitlines() if line.startswith('{"Controls":')]
    section, = report["Controls"]
    result, = [row for group in section["tests"] for row in group["results"]]
    if section["version"] != PROFILE or section["node_type"] != "node" or result["test_number"] != CHECK:
        lab.block("Scanner output omitted or changed the exact assessed recommendation")
    return {
        "node_uid": target_node["metadata"]["uid"], "server_version": server,
        "profile": section["version"], "target": section["node_type"],
        "check_id": result["test_number"], "result": result["status"],
        "scanner_image": status["imageID"], "job_uid": job_object["metadata"]["uid"],
        "pod_uid": pod["metadata"]["uid"], "completed_at": job_object["status"]["completionTime"],
    }


def permits_closure(failed, retest):
    return (
        failed["result"] == "FAIL" and retest["result"] == "PASS"
        and failed["job_uid"] != retest["job_uid"]
        and all(failed[key] == retest[key] for key in IDENTITY)
    )


def run(lab):
    node = f"{lab.cluster}-control-plane"
    server = json.loads(lab.kubectl("get", "--raw=/version").stdout)["gitVersion"]
    if server != TARGET_VERSION:
        lab.block("Expected the version-mapped Kubernetes release for the CIS 1.12 scan")

    listed = get(lab, "node", node)
    initial = metadata(lab, node)
    if not (int(initial["mode"], 8) & ~0o600):
        lab.block("The stock owned kubelet file already satisfies the selected permission check")
    baseline = scan(lab, listed, "fixture-cis-baseline", server)
    lab.check("red", "The pinned scanner reports the exact stock kubelet mode finding",
              baseline["result"] == "FAIL",
              {"profile": baseline["profile"], "check_id": CHECK, "result": baseline["result"]})
    if baseline["result"] != "FAIL":
        lab.block("The approved fixture change needs an actual failed recommendation")

    # The fixture only tightens metadata of the owned file. It never reads its contents.
    assigned = clock()
    due = assigned + timedelta(minutes=5)
    lab.command("docker", "exec", node, "chmod", "0600", "--", CONFIG)
    after = metadata(lab, node)
    same_file = (after["mode"] == "600"
                 and all(after[key] == initial[key] for key in ("inode", "uid", "gid")))

    final_node = get(lab, "node", node)
    retest = scan(lab, final_node, "fixture-cis-retest", server)
    wrong_check = {**retest, "check_id": "4.1.10"}
    wrong_target = {**retest, "node_uid": "other-owned-fixture"}
    denies_unrelated_pass = not permits_closure(baseline, wrong_check) and not permits_closure(baseline, wrong_target)
    lab.check("red", "A passing result for a different recommendation or node cannot close the finding",
              denies_unrelated_pass, {"unrelated_check_and_node_rejected": denies_unrelated_pass})
    real_closure = same_file and permits_closure(baseline, retest)
    lab.check("green", "The exact failed check passes on the same file after the authorized mode change",
              real_closure, {"file_identity_preserved": same_file, "same_check_now_passes": real_closure,
                             "profile": retest["profile"], "check_id": CHECK})
    closed = clock()
    addressed_on_time = real_closure and closed <= due
    node_ready = any(c["type"] == "Ready" and c["status"] == "True" for c in final_node["status"]["conditions"])
    lab.check("positive", "Attributed same-scope receipts support timely closure and the node stays Ready",
              addressed_on_time and node_ready,
              {"timely_closure": addressed_on_time, "node_ready": node_ready})
    record = {
        "source": "actual scoped kube-bench assessment", "fixture_approval_ref": "SAF-CIS-FIXTURE-016",
        "fixture_priority": "P2", "fixture_risk_basis": "broad access to Kubernetes component configuration",
        "fixture_owner": "fixture-platform-owner", "fixture_reviewer": "fixture-assessment-review",
        "assigned_at": assigned.isoformat(), "due_at": due.isoformat(), "closed_at": closed.isoformat(),
        "configuration_revision": 2, "status": "remediated" if addressed_on_time else "unverified",
        "baseline": baseline, "retest": retest, "before_metadata": initial, "after_metadata": after,
    }
    (Path(lab.evidence) / "same-check-remediation.raw.json").write_text(json.dumps(record, indent=2) + "\n")
