"""Measure Chrony clock offset, preferred and alternate selection, loss and recovery in a restricted Job with clock adjustment disabled."""

import csv
from datetime import datetime, timezone
import hashlib
import re
import json
from pathlib import Path

SCOPE = "Measure Chrony clock offset, preferred and alternate selection, loss and recovery in a restricted Job with clock adjustment disabled."
HERE = Path(__file__).resolve().parent
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
TOOLS = "saf-lab-clock-fixture:source-" + SOURCE[:24]
LABEL = "org.saf.fixture.clock-source"
NAME = "fixture-chrony-reference"


PHASES = ("preferred", "alternate", "unavailable", "recovered")
SOURCE_BY_PHASE = dict(zip(PHASES, ("127.0.0.1", "127.0.0.2", None, "127.0.0.1")))
NOMINAL_LIMIT_SECONDS = 0.100
TIGHT_LIMIT_SECONDS = 0.020
MAX_SAMPLE_AGE_SECONDS = 5
OFFSET = re.compile(r"^System time\s*:\s*(\d+\.\d+) seconds (fast|slow) of NTP time$")


def observe(logs):
    observations = {}
    lines = logs.splitlines()
    for phase in PHASES:
        timestamps = [line.removeprefix(f"sample {phase} ") for line in lines
                      if line.startswith(f"sample {phase} ")]
        timestamp, = timestamps
        sampled_at = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        source_lines = [line.removeprefix(f"sources {phase} ") for line in lines
                        if line.startswith(f"sources {phase} ")]
        tracking = [line.removeprefix(f"tracking {phase} ") for line in lines
                    if line.startswith(f"tracking {phase} ")]
        selected = [row for row in csv.reader(source_lines) if row[1] == "*"]
        if len(selected) > 1 or not source_lines:
            raise ValueError(f"Invalid Chrony source report for {phase}")
        match, = [match for line in tracking if (match := OFFSET.fullmatch(line))]
        amount, direction = match.groups()
        offset = float(amount) * (1 if direction == "fast" else -1)
        # Chrony 4.6 sources CSV reports LastRx as field 7, after Reach.
        sample_age = int(selected[0][6]) if selected else None
        fresh = sample_age is not None and 0 <= sample_age <= MAX_SAMPLE_AGE_SECONDS
        observations[phase] = {
            "sampled_at": sampled_at.isoformat(),
            "selected": selected[0][2] if selected else None,
            "last_sample_age_seconds": sample_age,
            "ref_matches_selected": bool(selected) and any(
                line.startswith("Reference ID") and line.endswith(f" ({selected[0][2]})") for line in tracking),
            "system_offset_seconds": offset,
            "nominal_profile_ok": fresh and abs(offset) <= NOMINAL_LIMIT_SECONDS,
            "tight_profile_ok": fresh and abs(offset) <= TIGHT_LIMIT_SECONDS,
            "raw_sources": source_lines,
            "raw_tracking": tracking,
        }
    return observations


def image(lab):
    checked = lab.command("docker", "image", "inspect", TOOLS, allow_failure=True)
    if checked.returncode:
        lab.command("docker", "build", "-q", "-t", TOOLS, "--label", f"{LABEL}={SOURCE}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
        checked = lab.command("docker", "image", "inspect", TOOLS)
    record, = json.loads(checked.stdout)
    if record["Config"]["Labels"].get(LABEL) != SOURCE:
        lab.block("The local guest fixture image does not match the tested build recipe")
    return record["Id"]


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    expected_image = image(lab)
    lab.command("kind", "load", "docker-image", TOOLS, "--name", lab.cluster, timeout=210)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"boot.sh": (HERE / "clock-check.sh").read_text()}})
    unit = {"name": "guest", "image": TOOLS, "imagePullPolicy": "Never",
            "command": ["sh", "/test/boot.sh"],
            "volumeMounts": [{"name": "fixture", "mountPath": "/test", "readOnly": True},
                             {"name": "temporary", "mountPath": "/tmp"}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "25m", "memory": "24Mi"},
                          "limits": {"cpu": "150m", "memory": "96Mi"}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME},
                "spec": {"backoffLimit": 0, "template": {"spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [unit], "volumes": [
                        {"name": "fixture", "configMap": {"name": NAME}}, {"name": "temporary", "emptyDir": {}}],
                }}}})
    completion = lab.kubectl("wait", "--for=condition=Complete", "job/" + NAME,
                             "--timeout=135s", timeout=145, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    if completion.returncode or logs.returncode:
        lab.block("The Chrony reference fixture did not complete; inspect its owned Job result")
    try:
        observations = observe(logs.stdout)
    except (ValueError, IndexError) as error:
        lab.block(f"Could not read live Chrony tracking and source evidence: {error}")
    failed = observations["unavailable"]
    lab.check("red", "Loss of both owned sources makes the reference unavailable and fails the profile check",
              failed["selected"] is None and not failed["nominal_profile_ok"],
              {"selected": failed["selected"], "profile_ok": failed["nominal_profile_ok"]})
    for phase in ("preferred", "alternate", "recovered"):
        sample = observations[phase]
        lab.check("green" if phase == "alternate" else "positive",
                  f"Chrony selects the expected {phase} source with a fresh measurement in the nominal band",
                  sample["selected"] == SOURCE_BY_PHASE[phase] and sample["nominal_profile_ok"]
                  and sample["ref_matches_selected"],
                  {"phase": phase, "expected_source_selected": sample["selected"] == SOURCE_BY_PHASE[phase],
                   "nominal_profile_ok": sample["nominal_profile_ok"]})
    observed = observations["preferred"]
    magnitude = abs(observed["system_offset_seconds"])
    lab.check("counterfactual", "The same fresh measured offset passes the nominal policy and exceeds a tighter bound",
              0.025 <= magnitude <= 0.075 and observed["nominal_profile_ok"] and not observed["tight_profile_ok"],
              {"fixture_offset_within_expected_band": 0.025 <= magnitude <= 0.075,
               "nominal_profile_ok": observed["nominal_profile_ok"], "tight_profile_ok": observed["tight_profile_ok"]})
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    worker, = rows
    status, = worker["status"]["containerStatuses"]
    (lab.evidence / "clock-source-observations.json").write_text(json.dumps({
        "build_image": expected_image, "running_image": status["imageID"],
        "nominal_limit_seconds": NOMINAL_LIMIT_SECONDS,
        "tight_limit_seconds": TIGHT_LIMIT_SECONDS,
        "maximum_source_sample_age_seconds": MAX_SAMPLE_AGE_SECONDS,
        "observations": observations,
    }, indent=2) + "\n")
