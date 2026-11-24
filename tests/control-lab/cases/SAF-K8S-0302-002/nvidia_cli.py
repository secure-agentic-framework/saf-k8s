"""Verify NVIDIA device-plugin option parsing without registering a plugin."""

import json
import re
import time


IMAGE = (
    "nvcr.io/nvidia/k8s-device-plugin:v0.20.2@sha256:"
    "7673383d44a84bece724d9ca8feeadf4eee69cd46475fdff614cbbca6732d463"
)
CASES = {
    "unknown": ["--cdi-enabled", "--help"],
    "documented": ["--device-list-strategy=cdi-annotations", "--help"],
}


def submit(lab, key, arguments):
    name = "saf-nvidia-cdi-" + key
    lab.create({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 120,
            "template": {
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": "parser",
                        "image": IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["nvidia-device-plugin"],
                        "args": arguments,
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                    }],
                },
            },
        },
    })
    return name


def read_result(lab, name):
    deadline = time.monotonic() + 132
    while time.monotonic() < deadline:
        raw = lab.kubectl("get", "job", name, "-o", "json").stdout
        terminal = next((item["type"] for item in json.loads(raw)["status"].get("conditions", [])
                         if item["status"] == "True" and item["type"] in ("Complete", "Failed")), None)
        if terminal:
            break
        time.sleep(1)
    else:
        lab.block(f"NVIDIA CLI Job did not finish: {name}")

    label = "batch.kubernetes.io/job-name=" + name
    pods = json.loads(lab.kubectl("get", "pod", "-l", label, "-o", "json").stdout)["items"]
    if len(pods) != 1:
        lab.block(f"Expected exactly one vendor CLI Pod for {name}")
    pod = pods[0]
    statuses = pod.get("status", {}).get("containerStatuses", [])
    if len(statuses) != 1 or not statuses[0].get("state", {}).get("terminated"):
        lab.block(f"Vendor CLI never terminated for {name}")
    status = statuses[0]
    if not status.get("imageID"):
        lab.block(f"Vendor CLI Pod has no runtime image ID for {name}")
    logs = lab.kubectl("logs", "pod/" + pod["metadata"]["name"]).stdout
    return {"job_terminal": terminal, "exit_code": status["state"]["terminated"]["exitCode"],
            "image_id": status["imageID"], "log": logs}


def run(lab):
    names = {key: submit(lab, key, args) for key, args in CASES.items()}
    rows = {key: read_result(lab, name) for key, name in names.items()}
    old, new = rows["unknown"], rows["documented"]
    reject_reason = re.search(r"flag provided but not defined:\s+-+cdi-enabled(?:\s|$)", old["log"]) is not None
    handled = {
        "unknown_flag_exit": old["exit_code"],
        "unknown_flag_named": reject_reason,
        "old_job_failed": old["job_terminal"] == "Failed",
        "documented_flag_exit": new["exit_code"],
        "documented_strategy_in_help": "--device-list-strategy" in new["log"] and "cdi-annotations" in new["log"],
        "help_job_completed": new["job_terminal"] == "Complete",
    }
    lab.check("red", "The exact NVIDIA plugin rejects the previous undocumented CDI flag",
              handled["unknown_flag_exit"] == 1 and reject_reason and handled["old_job_failed"],
              {key: handled[key] for key in ("unknown_flag_exit", "unknown_flag_named", "old_job_failed")})
    lab.check("positive", "The pinned NVIDIA plugin parses the documented CDI strategy in help mode",
              handled["documented_flag_exit"] == 0 and handled["documented_strategy_in_help"]
              and handled["help_job_completed"],
              {key: handled[key] for key in ("documented_flag_exit", "documented_strategy_in_help",
                                              "help_job_completed")})
    (lab.evidence / "nvidia-cdi-observations.json").write_text(
        json.dumps({"requested_pinned_image": IMAGE, "results": rows}, indent=2) + "\n")
