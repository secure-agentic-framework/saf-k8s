"""Observe actual AppArmor complain and enforcing modes and their operation-specific evidence."""

import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAME = "fixture-apparmor-observation"
BUILD_LABEL = "org.saf.fixture.apparmor-build"
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes() + b"\0" +
                       (HERE / "seccomp-proof.c").read_bytes()).hexdigest()
IMAGE = "saf-lab-apparmor:source-" + SOURCE[:24]
SCOPE = (
    "Compare AppArmor complain, enforcing and profile-removal behavior in a private Linux "
    "guest. In the same guest, correlate a harmless syscall under the reviewed seccomp LOG "
    "filter with its kernel audit event, compare enforcing behavior and test fresh-process recovery."
)


def profile_job():
    security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}}
    guest = {
        "name": "guest", "image": IMAGE, "imagePullPolicy": "Never",
        "command": ["sh", "/fixture/boot.sh", "/fixture/profile"],
        "securityContext": security,
        "resources": {"requests": {"cpu": "200m", "memory": "160Mi"},
                      "limits": {"cpu": "1500m", "memory": "768Mi"}},
        "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                         {"name": "scratch", "mountPath": "/tmp"}],
    }
    return {
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90, "template": {"spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [guest],
            "volumes": [{"name": "fixture", "configMap": {"name": NAME}},
                        {"name": "scratch", "emptyDir": {}}],
        }}},
    }


def run(lab):
    profile = (HERE / "profile.apparmor").read_text()
    digest = hashlib.sha256(profile.encode()).hexdigest()
    if lab.command("docker", "image", "inspect", IMAGE, allow_failure=True).returncode:
        lab.command("docker", "build", "-q", "-t", IMAGE, "--label", f"{BUILD_LABEL}={SOURCE}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
    image, = json.loads(lab.command("docker", "image", "inspect", IMAGE).stdout)
    if image["Config"].get("Labels", {}).get(BUILD_LABEL) != SOURCE:
        lab.block("The guest fixture image does not match the pinned build recipe")
    lab.command("kind", "load", "docker-image", IMAGE, "--name", lab.cluster, timeout=220)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"profile": profile,
                                            "boot.sh": (HERE / "apparmor-complain.sh").read_text()}})
    lab.create(profile_job())
    completion = lab.kubectl("wait", "--for=condition=Complete", "job/" + NAME,
                             "--timeout=98s", timeout=108, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    if completion.returncode or logs.returncode or len(rows) != 1:
        lab.block("The AppArmor mode fixture did not complete; inspect the owned Job evidence")
    guest_pod, = rows
    status, = guest_pod["status"]["containerStatuses"]
    lines = logs.stdout.splitlines()
    messages = set(lines)
    input_matched = f"SAF-AA-AUDIT-INPUT: {digest}" in messages
    baseline = "SAF-AA-AUDIT: both owned comparison reads are initially available" in messages
    observed = "SAF-AA-AUDIT: complain allows the implicit would-be denial and records the expected event" in messages
    enforced = "SAF-AA-AUDIT: enforcing denies both while the approved read continues" in messages
    restored = "SAF-AA-AUDIT: removing the fixture policy restores both controls" in messages
    seccomp_input = next((line.split(": ", 1)[1] for line in lines
                          if line.startswith("SAF-SC-FILTER-SHA256: ")), None)
    seccomp_expected = hashlib.sha256((HERE / "seccomp-proof.c").read_bytes()).hexdigest()
    seccomp_observed = "SAF-SC-OBSERVE: getpid returned successfully under LOG action" in messages
    seccomp_enforced = "SAF-SC-ENFORCE: getpid denied with EPERM; ordinary output succeeded" in messages
    seccomp_recovery = "SAF-SC-RECOVERY: fresh unrestricted process completed getpid and output" in messages
    event_rows = [line for line in lines if line.startswith("SAF-SC-AUDIT-EVENT: ")]
    observer_pids = [match[1] for line in lines
                     if (match := re.fullmatch(r"SAF-SC-TASK: mode=observe pid=([0-9]+) syscall=getpid", line))]
    expected_event = len(event_rows) == len(observer_pids) == 1 and bool(re.search(
        rf"\btype=1326\b.*\bpid={observer_pids[0]}\b.*\barch=c00000b7\s+syscall=172\b.*\bcode=0x7ffc0000$",
        event_rows[0]))
    ordinary_reached = lines.count("SAF-SC-ORDINARY: getuid succeeded under the selected filter") == 2
    explicit = [line.removeprefix("SAF-AA-AUDIT-EXPLICIT: ") for line in messages
                if line.startswith("SAF-AA-AUDIT-EXPLICIT: ")]
    lab.check("red", "The two owned test reads are initially available and complain mode logs the implicit would-be denial",
              baseline and observed and input_matched, {"baseline_reads": baseline, "expected_complain_event": observed,
                                                       "profile_input_matched": input_matched})
    lab.check("green", "Enforcing mode denies both fixture reads while the approved read remains available",
              enforced, {"enforcing_canaries_correct": enforced})
    lab.check("positive", "The exact compiler and kernel produce a recorded explicit-rule decision and removing policy restores both reads",
              len(explicit) == 1 and restored, {"explicit_rule_in_complain": explicit, "rollback_restored": restored})
    lab.check("red", "The reviewed seccomp LOG filter permits the harmless probe and produces a correlated kernel audit event",
              seccomp_input == seccomp_expected and seccomp_observed and expected_event,
              {"reviewed_filter_sha256_matches": seccomp_input == seccomp_expected,
               "expected_observation": seccomp_observed, "correlated_audit_event_count": len(event_rows)})
    lab.check("green", "The same seccomp policy matrix denies the probe in enforcing mode, permits ordinary output, and recovers in a fresh process",
              seccomp_enforced and ordinary_reached and seccomp_recovery,
              {"enforcing_allow_deny": seccomp_enforced, "ordinary_allowed_in_both_modes": ordinary_reached,
               "fresh_process_recovery": seccomp_recovery})
    (lab.evidence / "mac-audit-observations.json").write_text(json.dumps({
        "profile_sha256": digest, "guest_image": image["Id"], "running_guest_image": status["imageID"],
        "complain_implicit_would_be_denial_event": observed, "complain_explicit_rule_decision": explicit[0],
        "enforcing_allow_deny_matrix": enforced, "rollback_restored": restored,
        "seccomp_filter_sha256": seccomp_input, "seccomp_observation_probe_succeeded": seccomp_observed,
        "seccomp_correlated_audit_event": event_rows[0] if expected_event else None,
        "seccomp_enforcing_allow_deny": seccomp_enforced, "seccomp_fresh_process_recovery": seccomp_recovery,
    }, indent=2) + "\n")
