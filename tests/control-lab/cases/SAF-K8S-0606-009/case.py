"""Run a governed development tool as a real, restricted Kubernetes Job."""

import hashlib
import json
import time

SCOPE = "A lab-only example of toolchain integrity and execution for SSDF v1.1 PO.3.2."
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
APPROVED = "printf '%s\\n' approved-public-tool-v1\n"
CHANGED = "printf '%s\\n' different-public-tool-v2\n"
EXPECTED = hashlib.sha256(APPROVED.encode()).hexdigest()
CHECKED_RUN = r'''
printf '%s  %s\n' "$TOOL_SHA256" /input/tool.sh | sha256sum -c - >/dev/null || {
  printf '%s\n' unapproved-tool-digest
  exit 12
}
exec /bin/sh /input/tool.sh
'''


def run_tool(lab, name, content, guard):
    config = lab.create({
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
        "immutable": True, "data": {"tool.sh": content},
    })
    job = lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65,
                 "template": {"spec": {
                     "automountServiceAccountToken": False, "restartPolicy": "Never",
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "volumes": [{"name": "tool", "configMap": {"name": name}}],
                     "containers": [{"name": "tool", "image": IMAGE,
                                     "command": ["/bin/sh", "-c", guard],
                                     "env": [{"name": "TOOL_SHA256", "value": EXPECTED}],
                                     "resources": {"requests": {"cpu": "5m", "memory": "4Mi"},
                                                   "limits": {"cpu": "100m", "memory": "32Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "volumeMounts": [{"name": "tool", "mountPath": "/input",
                                                       "readOnly": True}]}],
                 }}},
    })
    expires = time.monotonic() + 85
    while time.monotonic() < expires:
        current = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        terminal = {condition["type"] for condition in current["status"].get("conditions", [])
                    if condition["status"] == "True"} & {"Complete", "Failed"}
        if terminal:
            break
        time.sleep(1)
    else:
        lab.block(f"Fixture Job {name} did not reach a terminal state")
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"batch.kubernetes.io/job-name={name}",
                                  "-o", "json").stdout)["items"]
    if len(pods) != 1 or not any(ref["uid"] == job["metadata"]["uid"]
                                 for ref in pods[0]["metadata"].get("ownerReferences", [])):
        lab.block(f"Unable to identify the single owned Pod for {name}")
    pod = pods[0]
    container = pod["status"].get("containerStatuses", [])
    terminated = container[0]["state"].get("terminated") if len(container) == 1 else None
    if not terminated:
        lab.block(f"Fixture Job {name} has no verified container exit status")
    return {"state": sorted(terminal), "exit": terminated["exitCode"],
            "marker": lab.kubectl("logs", pod["metadata"]["name"]).stdout.strip(),
            "immutable_input": config["immutable"],
            "token_mount_disabled": pod["spec"]["automountServiceAccountToken"] is False
            and all("serviceAccountToken" not in source for volume in pod["spec"].get("volumes", [])
                    for source in volume.get("projected", {}).get("sources", []))}


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    comparison = run_tool(lab, "ssdf-tool-comparison", CHANGED, "exec /bin/sh /input/tool.sh")
    lab.check("red", "An unchecked Job executes the different public tool bytes",
              comparison["state"] == ["Complete"] and comparison["exit"] == 0
              and comparison["marker"] == "different-public-tool-v2", comparison)
    denied = run_tool(lab, "ssdf-tool-changed", CHANGED, CHECKED_RUN)
    lab.check("green", "The governed Job refuses to execute those same bytes",
              denied["state"] == ["Failed"] and denied["exit"] == 12
              and denied["marker"].splitlines()[-1:] == ["unapproved-tool-digest"]
              and "different-public-tool-v2" not in denied["marker"].splitlines(), denied)
    approved = run_tool(lab, "ssdf-tool-approved", APPROVED, CHECKED_RUN)
    lab.check("positive", "The governed Job runs the approved tool with immutable input and no default token",
              approved["state"] == ["Complete"] and approved["exit"] == 0
              and approved["marker"] == "approved-public-tool-v1"
              and approved["immutable_input"] and approved["token_mount_disabled"], approved)
    report = {"ssdf": "NIST SP 800-218 v1.1", "selected_task": "PO.3.2", "approved_sha256": EXPECTED,
              "unchecked": comparison, "rejected": denied, "approved": approved}
    (lab.evidence / "toolchain-observations.json").write_text(json.dumps(report, indent=2) + "\n")
