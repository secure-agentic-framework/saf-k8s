"""Verify exact AppArmor profile delivery, guest enforcement and a scheduling gate."""

import hashlib
import json
from pathlib import Path

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
NAME = "fixture-apparmor-profile"
PROFILE = "saf_read_boundary"
LABEL = "saf-lab.node-restriction.kubernetes.io/apparmor-probe"
BUILD_LABEL = "org.saf.fixture.apparmor-build"
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
IMAGE = "saf-lab-apparmor:source-" + SOURCE[:24]
SCOPE = (
    "Deliver an immutable AppArmor profile through Kubernetes, demonstrate enforcement "
    "and restoration inside a disconnected guest, and exercise explicitly labeled eligibility. "
    "Guest profile readiness supplies only a lab marker for the scheduling exercise."
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


def scheduling_probe(name, token):
    unit = container("marker", command=["sh", "-ec", "printf '%s\n' SAF-AA-ELIGIBLE"])
    return pod(name, [unit], restartPolicy="Never", automountServiceAccountToken=False,
               nodeSelector={LABEL: token})


def unscheduled(lab, name):
    result = lab.kubectl("wait", "--for=jsonpath={.status.conditions[?(@.type=='PodScheduled')].reason}=Unschedulable",
                         "pod/" + name, "--timeout=32s", timeout=40, allow_failure=True)
    data = json.loads(lab.kubectl("get", "pod/" + name, "-o", "json").stdout)
    return result.returncode == 0 and not data["spec"].get("nodeName")


def run(lab):
    profile = (HERE / "profile.apparmor").read_text()
    digest = hashlib.sha256(profile.encode()).hexdigest()
    token = digest[:40]
    lab.create(scheduling_probe("fixture-awaits-profile", token))
    no_initial_label = unscheduled(lab, "fixture-awaits-profile")

    if lab.command("docker", "image", "inspect", IMAGE, allow_failure=True).returncode:
        lab.command("docker", "build", "-q", "-t", IMAGE, "--label", f"{BUILD_LABEL}={SOURCE}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
    image, = json.loads(lab.command("docker", "image", "inspect", IMAGE).stdout)
    if image["Config"].get("Labels", {}).get(BUILD_LABEL) != SOURCE:
        lab.block("The guest fixture image does not match the pinned build recipe")
    lab.command("kind", "load", "docker-image", IMAGE, "--name", lab.cluster, timeout=220)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"profile": profile,
                                            "boot.sh": (HERE / "apparmor-fixture.sh").read_text()}})
    lab.create(profile_job())
    completion = lab.kubectl("wait", "--for=condition=Complete", "job/" + NAME,
                             "--timeout=98s", timeout=108, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    if completion.returncode or logs.returncode or len(rows) != 1:
        lab.block("The disconnected AppArmor guest did not complete; inspect the owned Job evidence")
    guest_pod, = rows
    status, = guest_pod["status"]["containerStatuses"]
    messages = set(logs.stdout.splitlines())
    missing = "SAF-AA: missing profile refused and unrestricted comparison read available" in messages
    exact = ("SAF-AA-INPUT: " + digest in messages
             and "SAF-AA: exact profile loaded in enforce mode" in messages)
    enforced = "SAF-AA: expected read allowed and second read denied" in messages
    restored = "SAF-AA: profile removed and comparison restored" in messages
    lab.check("red", "Without the readiness label the Pod is unschedulable, and the guest reports the missing named profile",
              no_initial_label and missing, {"initial_selector_unsatisfied": no_initial_label, "missing_guest_profile": missing})
    lab.check("green", "The guest loads the exact delivered profile in enforce mode, denies the inert canary and restores on removal",
              exact and enforced and restored, {"profile_sha256": digest, "enforced": enforced, "restored": restored})

    node = guest_pod["spec"]["nodeName"]
    lab.kubectl("label", "node", node, f"{LABEL}={token}")
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/fixture-awaits-profile",
                "--timeout=55s", timeout=65)
    selected = json.loads(lab.kubectl("get", "pod/fixture-awaits-profile", "-o", "json").stdout)["spec"]["nodeName"]
    marker = lab.kubectl("logs", "fixture-awaits-profile").stdout.strip()
    lab.kubectl("label", "node", node, LABEL + "-")
    lab.create(scheduling_probe("fixture-after-readiness-withdrawn", token))
    blocked_after = unscheduled(lab, "fixture-after-readiness-withdrawn")
    lab.check("positive", "The scheduler places the marker on the eligible node, and the next Pod waits after label withdrawal",
              selected == node and marker == "SAF-AA-ELIGIBLE" and blocked_after,
              {"selected_expected_node": selected == node, "marker": marker, "blocked_after_withdrawal": blocked_after})
    (lab.evidence / "apparmor-profile-observations.json").write_text(json.dumps({
        "profile": PROFILE, "sha256": digest, "guest_image": image["Id"],
        "running_guest_image": status["imageID"], "missing_guest_profile": missing,
        "loaded_expected_profile": exact, "guest_enforcement": enforced, "guest_rollback": restored,
        "initial_selector_unsatisfied": no_initial_label, "after_withdrawal_unsatisfied": blocked_after,
        "selected_expected_node": selected == node, "readiness_scope": "disconnected guest and explicit lab scheduling label",
    }, indent=2) + "\n")
