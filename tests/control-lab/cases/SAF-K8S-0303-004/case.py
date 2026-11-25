"""Verify limited AppArmor runtime recording and independently approved rule generation."""

import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAME = "fixture-apparmor-recording"
BUILD_LABEL = "org.saf.fixture.apparmor-build"
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes() + b"\0" +
                       (HERE / "seccomp-probe.c").read_bytes()).hexdigest()
IMAGE = "saf-lab-apparmor:source-" + SOURCE[:24]
SCOPE = (
    "Record selected AppArmor file opens and seccomp syscall notifications in a disconnected "
    "Linux guest in one restricted Kind Job. Compare the first capture and a newly exercised "
    "recovery path, intersect observations with each exact approval list, enforce the generated "
    "policies and check recovery. A separate SELinux guest derives named file rules "
    "from attributable AVC records, enforces the exact rule sets and verifies removal."
)


def profile_job(name=NAME, image=IMAGE, command=None):
    security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}}
    guest = {
        "name": "guest", "image": image, "imagePullPolicy": "Never",
        "command": command or ["sh", "/fixture/boot.sh", "/fixture/recorder", "/fixture/approved"],
        "securityContext": security,
        "resources": {"requests": {"cpu": "200m", "memory": "160Mi"},
                      "limits": {"cpu": "1500m", "memory": "768Mi"}},
        "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                         {"name": "scratch", "mountPath": "/tmp"}],
    }
    return {
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90, "template": {"spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [guest],
            "volumes": [{"name": "fixture", "configMap": {"name": name}},
                        {"name": "scratch", "emptyDir": {}}],
        }}},
    }


def run(lab):
    recorder = (HERE / "recorder.apparmor").read_text()
    approved = (HERE / "approved-paths.txt").read_text()
    digests = [hashlib.sha256(text.encode()).hexdigest() for text in (recorder, approved)]
    if lab.command("docker", "image", "inspect", IMAGE, allow_failure=True).returncode:
        lab.command("docker", "build", "-q", "-t", IMAGE, "--label", f"{BUILD_LABEL}={SOURCE}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
    image, = json.loads(lab.command("docker", "image", "inspect", IMAGE).stdout)
    if image["Config"].get("Labels", {}).get(BUILD_LABEL) != SOURCE:
        lab.block("The guest fixture image does not match the pinned build recipe")
    lab.command("kind", "load", "docker-image", IMAGE, "--name", lab.cluster, timeout=220)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"recorder": recorder, "approved": approved,
                                            "boot.sh": (HERE / "apparmor-recording.sh").read_text(),
                                            "seccomp-recording.sh": (HERE / "seccomp-recording.sh").read_text(),
                                            "seccomp-approved.txt": (HERE / "seccomp-approved.txt").read_text()}})
    lab.create(profile_job())
    completion = lab.kubectl("wait", "--for=condition=Complete", "job/" + NAME,
                             "--timeout=98s", timeout=108, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    if completion.returncode or logs.returncode or len(rows) != 1:
        lab.block("The AppArmor mode fixture did not complete; inspect the owned Job evidence")
    guest_pod, = rows
    status, = guest_pod["status"]["containerStatuses"]
    messages = set(logs.stdout.splitlines())
    matched = f"SAF-RECORD-INPUT: {' '.join(digests)}" in messages
    incomplete = "SAF-RECORD: first capture observes incidental use and misses a required recovery operation" in messages
    enforced = "SAF-RECORD: the reviewed generated policy preserves approved operations and excludes the observed incidental one" in messages
    removed = "SAF-RECORD: the generated fixture policy is removed" in messages
    names = ("seccomp-probe.c", "seccomp-approved.txt")
    seccomp_inputs = [hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names]
    seccomp_input_ok = f"SAF-SECCOMP-INPUTS: {' '.join(seccomp_inputs)}" in messages
    policy_digests = [hashlib.sha256(value).hexdigest() for value in (b"getpid\n", b"getpid\ngetuid\n")]
    generated_syscall_policy_ok = f"SAF-SECCOMP-POLICIES: {' '.join(policy_digests)}" in messages
    seccomp_observed = "SAF-SECCOMP: first capture observed getpid and incidental getppid; approval retained getpid only" in messages
    seccomp_initial = "SAF-SECCOMP: initial policy allowed getpid and denied getppid and unobserved recovery getuid" in messages
    seccomp_recovery = "SAF-SECCOMP: exercised recovery added approved getuid; final policy allowed getpid and getuid and denied incidental getppid" in messages
    seccomp_rollback = "SAF-SECCOMP: rollback discarded the filtered process and verified a fresh unfiltered fixture process" in messages
    rows = [line.split()[1:] for line in messages if line.startswith("SAF-RECORD-PROFILES: ")]
    generated = rows[0] if len(rows) == 1 else []
    distinct = len(generated) == 2 and len(set(generated)) == 2
    lab.check("red", "A limited actual recording observes incidental activity and omits recovery",
              matched and incomplete, {"matched_definitions": matched, "limited_capture_misses_recovery": incomplete})
    lab.check("green", "Representative recording plus exact approval generates a different enforcing policy with the intended boundary",
              distinct and enforced, {"generated_profiles": generated, "enforced_matrix": enforced})
    lab.check("positive", "Removing the generated profile restores the missing-profile comparison",
              removed, {"generated_profile_removed": removed})
    lab.check("green", "The seccomp collector observes only the synthetic syscall probes and excludes unapproved incidental use",
              seccomp_observed and seccomp_input_ok,
              {"observed_syscalls_and_approval_intersection": seccomp_observed,
               "exact_seccomp_inputs": seccomp_input_ok})
    lab.check("green", "The initial seccomp policy enforces the expected allow and deny results",
              seccomp_initial, {"initial_allowed_denied_matrix": seccomp_initial})
    lab.check("green", "A newly exercised approved recovery syscall enters the final enforced policy",
              seccomp_recovery and generated_syscall_policy_ok,
              {"recovery_and_final_allowed_denied_matrix": seccomp_recovery,
               "generated_policy_digests": policy_digests})
    lab.check("positive", "Discarding the filtered process provides the documented seccomp rollback path",
              seccomp_rollback, {"fresh_process_rollback": seccomp_rollback})
    (lab.evidence / "mac-recording-observations.json").write_text(json.dumps({
        "recorder_sha256": digests[0], "approved_paths_sha256": digests[1], "guest_image": image["Id"],
        "running_guest_image": status["imageID"], "generated_profile_digests": generated,
        "limited_capture_incomplete": incomplete, "enforcing_matrix": enforced, "generated_profile_removed": removed,
        "seccomp_inputs": dict(zip(names, seccomp_inputs)),
        "seccomp_policy_digests": policy_digests,
        "seccomp_collector_observed_and_intersected": seccomp_observed,
        "seccomp_initial_enforcement_matrix": seccomp_initial,
        "seccomp_recovery_and_final_enforcement_matrix": seccomp_recovery,
        "seccomp_fresh_process_rollback": seccomp_rollback,
    }, indent=2) + "\n")


    verify_selinux(lab)


def verify_selinux(lab):
    name = "fixture-selinux-recording"
    recipe = HERE / "Dockerfile.selinux"
    digest = hashlib.sha256(recipe.read_bytes()).hexdigest()
    build_label = "org.saf.fixture.selinux-build"
    image = "saf-lab-selinux:source-" + digest[:24]
    if lab.command("docker", "image", "inspect", image, allow_failure=True).returncode:
        lab.command("docker", "build", "-q", "-t", image, "--label", f"{build_label}={digest}",
                    "-f", str(recipe), str(HERE), timeout=420)
    metadata, = json.loads(lab.command("docker", "image", "inspect", image).stdout)
    if metadata["Config"].get("Labels", {}).get(build_label) != digest:
        lab.block("The SELinux fixture image does not match its pinned build recipe")
    lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=220)
    inputs = ("selinux-base.cil", "selinux-approved.txt")
    data = {filename: (HERE / filename).read_text() for filename in inputs}
    data["boot.sh"] = (HERE / "selinux-recording.sh").read_text()
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "immutable": True, "data": data})
    job = profile_job(name, image, ["sh", "/fixture/boot.sh"])
    job["spec"]["activeDeadlineSeconds"] = 335
    lab.create(job)
    completion = lab.kubectl("wait", "--for=condition=Complete", "job/" + name, "--timeout=337s",
                             timeout=345, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + name, allow_failure=True)
    if completion.returncode or logs.returncode:
        lab.block("The isolated SELinux recording Job did not complete; inspect the guest log")

    lines = logs.stdout.splitlines()
    input_digests = [hashlib.sha256(data[filename].encode()).hexdigest() for filename in inputs]
    inputs_match = f"SAF-SELINUX-RECORD-INPUT: {' '.join(input_digests)}" in lines
    rule_prefix = "(allow container_t saf_record_{}_t (file (open read)))\n"
    approved = [rule_prefix.format(candidate) for candidate in ("startup", "recovery")]
    expected_rules = [hashlib.sha256(value.encode()).hexdigest() for value in (approved[0], "".join(approved))]
    rules_match = f"SAF-SELINUX-RECORD-PROFILES: {' '.join(expected_rules)}" in lines
    evidence = {}
    for mode in (0, 1):
        evidence[mode] = [line for line in lines if line.startswith(f"SAF-SELINUX-RECORDED-AVC-{mode}: ")]
    parsed = {mode: [match.groups() for line in rows if (match := re.search(
        r"pid=(\d+) .*name=\"(startup|recovery|incidental)\".*scontext=system_u:system_r:container_t:s0:c10,c20 "
        rf"tcontext=system_u:object_r:saf_record_\2_t:s0:c10,c20 tclass=file permissive={mode}(?:\s|$)",
        line))] for mode, rows in evidence.items()}
    phase_subjects = {pid for rows in parsed.values() for pid, _ in rows}
    attributable_modes = len(phase_subjects) == 1 and all(
        {target for _, target in parsed[mode]} == {"startup", "recovery", "incidental"} for mode in (0, 1))
    initial = "SAF-SELINUX-RECORD: the initial enforcing profile excludes incidental and unobserved recovery reads" in lines
    final = "SAF-SELINUX-RECORD: the derived enforcing profile keeps both approved reads and denies the incidental read" in lines
    rollback = "SAF-SELINUX-RECORD: restoring the saved policy restores the previous enforcement decisions" in lines
    lab.check("red", "Recorded SELinux startup and incidental access miss an approved recovery operation",
              inputs_match and initial and attributable_modes,
              {"immutable_inputs_matched": inputs_match, "initial_recovery_denied": initial,
               "avc_contexts_attributable_in_both_modes": attributable_modes})
    lab.check("green", "The reviewed SELinux rule sets enforce the generated approved access with no incidental read",
              final and rules_match, {"final_allow_deny_matrix": final, "exact_generated_rules": expected_rules})
    lab.check("positive", "Restoring the saved SELinux policy restores the baseline denies",
              rollback, {"baseline_restored": rollback})
    (lab.evidence / "selinux-recording-observations.json").write_text(json.dumps({
        "guest_image": metadata["Id"], "input_digests": dict(zip(inputs, input_digests)),
        "generated_policy_digests": expected_rules, "avc_records": evidence,
        "initial_enforcement": initial, "final_enforcement": final, "baseline_policy_restored": rollback,
    }, indent=2) + "\n")
