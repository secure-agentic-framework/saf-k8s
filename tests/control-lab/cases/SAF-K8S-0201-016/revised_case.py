"""Replay receiver retention and sample per-node audit delivery on a schedule."""
import json
from pathlib import Path
from runpy import run_path
import time


ROOT = Path(__file__).resolve().parent
BASE = run_path(str(ROOT / "case.py"))
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
SCOPE = (
    "Owned v1.36.1 Kind and a mount-free Linux Audit guest. Forward one attributable native "
    "marker over mTLS, persist the sender queue during 503, resume from the same volume "
    "through Pod replacement, and verify exact central retrieval and deduplication. "
    "The distinct scheduled two-node canary checks coverage of the fixture."
)
APP = "audit-coverage"
SOURCE = "audit-node-canary"
SCHEDULE_ANNOTATION = "batch.kubernetes.io/cronjob-scheduled-timestamp"


def prepare_kind(lab, temporary):
    path = temporary / "audit-kind.yaml"
    path.write_text("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n"
                    "- role: control-plane\n- role: worker\n")
    path.chmod(0o600)
    return path


def template(mode, *, endpoint_env, source=False):
    specification = BASE["_pod_security"]()
    mounts = [{"name": "app", "mountPath": "/app", "readOnly": True}]
    volumes = [{"name": "app", "configMap": {"name": APP}}]
    if source:
        mounts.append({"name": "state", "mountPath": "/state"})
        volumes.append({"name": "state", "emptyDir": {}})
    container = BASE["_container"]("coverage", ["python", "/app/coverage.py", mode], mounts)
    container["env"] = endpoint_env
    if source:
        container["readinessProbe"] = {"exec": {"command": ["test", "-f", "/state/accepted"]},
                                       "periodSeconds": 1}
        specification["tolerations"] = [{"key": "node-role.kubernetes.io/control-plane",
                                         "operator": "Exists", "effect": "NoSchedule"}]
    else:
        specification["restartPolicy"] = "Never"
    specification["containers"] = [container]
    specification["volumes"] = volumes
    return {"metadata": {"labels": {"app": SOURCE if source else APP}}, "spec": specification}


def schedule(lab, nodes):
    return lab.create({
        "apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": APP},
        "spec": {"schedule": "* * * * *", "timeZone": "Etc/UTC", "concurrencyPolicy": "Forbid",
                 "startingDeadlineSeconds": 30, "successfulJobsHistoryLimit": 4, "failedJobsHistoryLimit": 4,
                 "jobTemplate": {"metadata": {"labels": {"app": APP}},
                                 "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 40,
                                          "template": template("sample", endpoint_env=[
                                              {"name": "EXPECTED_NODES", "value": json.dumps(nodes)}
                                          ])}}},
    })["metadata"]["uid"]


def scheduled_observation(lab, owner_uid, after=""):
    deadline = time.monotonic() + 110
    while time.monotonic() < deadline:
        jobs = json.loads(lab.kubectl("get", "jobs", "-l", f"app={APP}", "-o", "json").stdout)["items"]
        for job in sorted(jobs, key=lambda item: item["metadata"]["creationTimestamp"]):
            meta = job["metadata"]
            when = meta.get("annotations", {}).get(SCHEDULE_ANNOTATION)
            owner = any(ref["uid"] == owner_uid and ref["kind"] == "CronJob" and ref.get("controller")
                        for ref in meta.get("ownerReferences", []))
            if not when or not owner:
                lab.block("the coverage Job is missing the expected scheduled owner")
            if when <= after:
                continue
            conditions = job.get("status", {}).get("conditions", [])
            states = {item["type"] for item in conditions if item["status"] == "True"}
            if states & {"Complete", "Failed"}:
                logs = lab.kubectl("logs", "job/" + meta["name"]).stdout.strip()
                return when, "Complete" in states, json.loads(logs)
        time.sleep(2)
    lab.block("the scheduled audit coverage observation did not complete")


def install_source(lab):
    lab.create({
        "apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": {"name": SOURCE},
        "spec": {"selector": {"matchLabels": {"app": SOURCE}},
                 "template": template("forward", source=True, endpoint_env=[
                     {"name": "SOURCE_NODE", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}}
                 ])},
    })
    lab.kubectl("rollout", "status", f"daemonset/{SOURCE}", "--timeout=90s", timeout=100)


def run(lab):
    nodes = sorted(item["metadata"]["name"] for item in
                   json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"])
    lab.check("positive", "The recapture check has independent control-plane and worker nodes",
              len(nodes) == 2, {"fixture_nodes": len(nodes)})
    BASE["run"](lab)
    run_path(str(ROOT / "native_transport.py"))["run"](lab, BASE)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": APP},
                "data": {"coverage.py": (ROOT / "coverage.py").read_text()}})
    owner = schedule(lab, nodes)
    first, succeeded, observed = scheduled_observation(lab, owner)
    missing = {"node_count": 2, "received_count": 0, "missing_count": 2, "unexpected_count": 0}
    lab.check("red", "The scheduled sink check reports both missing node markers before canary deployment",
              not succeeded and observed == missing, observed)

    install_source(lab)
    # Let any Job already scheduled during rollout settle. Start observing future slots.
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    next_slot, succeeded, observed = scheduled_observation(lab, owner, cutoff)
    complete = {"node_count": 2, "received_count": 2, "missing_count": 0, "unexpected_count": 0}
    lab.check("green", "A scheduled sink check finds one acknowledged marker for each node",
              succeeded and observed == complete, observed)
    later, succeeded, observed = scheduled_observation(lab, owner, next_slot)
    recurring = first < next_slot < later
    lab.check("positive", "A later CronJob execution retrieves both retained node markers",
              succeeded and recurring and observed == complete,
              {**observed, "new_scheduled_slot": recurring})
