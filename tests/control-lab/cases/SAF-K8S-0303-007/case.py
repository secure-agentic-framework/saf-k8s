"""Verify exact AppArmor profile delivery, guest enforcement and a scheduling gate."""

import hashlib
import json
from pathlib import Path
import time

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
    "and restoration inside a disconnected guest, and exercise explicitly labeled eligibility "
    "with native scheduling and RBAC. The fixture publishes one guest-derived readiness marker. "
    "A separate workload checks missing-profile startup on the actual node."
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


def live_scheduling_probe(name, token):
    unit = container("marker", command=[
        "sh", "-ec", "printf '%s\n' SAF-AA-LIVE-STARTED; exec sleep 90"
    ])
    return pod(name, [unit], restartPolicy="Never", automountServiceAccountToken=False,
               nodeSelector={LABEL: token}, terminationGracePeriodSeconds=1)


def unscheduled(lab, name):
    result = lab.kubectl("wait", "--for=jsonpath={.status.conditions[?(@.type=='PodScheduled')].reason}=Unschedulable",
                         "pod/" + name, "--timeout=32s", timeout=40, allow_failure=True)
    data = json.loads(lab.kubectl("get", "pod/" + name, "-o", "json").stdout)
    return result.returncode == 0 and not data["spec"].get("nodeName")


def readiness_publisher(lab, node):
    namespace = "saf-test"
    accounts = ("fixture-readiness-publisher", "fixture-readiness-observer")
    for name in accounts:
        lab.kubectl("create", "serviceaccount", name)
    for name, verbs, subject in (
        ("fixture-profile-publisher", "get,patch", accounts[0]),
        ("fixture-profile-observer", "get", accounts[1]),
    ):
        lab.kubectl("create", "clusterrole", name, "--resource=nodes", f"--verb={verbs}",
                    f"--resource-name={node}")
        lab.kubectl("create", "clusterrolebinding", name, f"--clusterrole={name}",
                    f"--serviceaccount={namespace}:{subject}")
    return tuple(f"system:serviceaccount:{namespace}:{name}" for name in accounts)


def verify_unavailable_localhost(lab):
    name = "fixture-unavailable-apparmor-profile"
    app = container("marker", command=["sh", "-ec", "echo UNEXPECTED-APPARMOR-START"])
    workload = pod(name, [app], restartPolicy="Never", automountServiceAccountToken=False,
                   securityContext={"appArmorProfile": {
                       "type": "Localhost", "localhostProfile": "saf-unloaded-readiness-fixture",
                   }})
    lab.create(workload)
    details = {}
    definitive_denial = False
    for _ in range(30):
        observed = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
        status = observed.get("status", {})
        waiting = [c.get("state", {}).get("waiting", {}) for c in status.get("containerStatuses", [])]
        events = json.loads(lab.kubectl("get", "events", "--field-selector",
                                       f"involvedObject.name={name}", "-o", "json").stdout)["items"]
        details = {"phase": status.get("phase"), "pod_reason": status.get("reason"),
                   "pod_message": status.get("message"), "waiting": waiting,
                   "event_messages": [event.get("message", "") for event in events]}
        messages = " ".join(str(item) for item in details.values()).lower()
        if status.get("phase") in {"Running", "Succeeded"}:
            break
        definitive_denial = bool(observed["spec"].get("nodeName")) and "apparmor" in messages and any(
            word in messages for word in ("not loaded", "not available", "not enabled", "cannot", "not found", "disabled")
        )
        if definitive_denial:
            break
        time.sleep(1)
    logs = lab.kubectl("logs", name, allow_failure=True)
    approved_marker_absent = "UNEXPECTED-APPARMOR-START" not in logs.stdout
    (lab.evidence / "apparmor-localhost-admission.json").write_text(json.dumps(details, indent=2) + "\n")
    lab.check("green", "An explicitly requested unavailable Localhost profile prevents workload startup on the node",
              definitive_denial and approved_marker_absent,
              {"apparmor_startup_denial": definitive_denial, "marker_absent": approved_marker_absent})


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
    publisher, observer = readiness_publisher(lab, node)
    accepted_label = f"{LABEL}={token}"
    observer_result = lab.kubectl("--as=" + observer, "label", "node", node, accepted_label,
                                   "--dry-run=server", allow_failure=True)
    node_result = lab.kubectl("--as=system:node:" + node, "--as-group=system:nodes",
                               "label", "node", node, accepted_label, "--dry-run=server",
                               allow_failure=True)
    observer_denied = observer_result.returncode != 0 and "cannot patch" in observer_result.stderr.lower()
    node_denied = (node_result.returncode != 0 and "is not allowed" in node_result.stderr.lower()
                   and LABEL in node_result.stderr)
    lab.check("green", "Read-only observer and NodeRestriction-protected kubelet identity cannot publish readiness",
              observer_denied and node_denied,
              {"observer_patch_denied": observer_denied, "node_restriction_denied": node_denied})
    stale_token = "stale-" + token
    lab.kubectl("--as=" + publisher, "label", "node", node, f"{LABEL}={stale_token}", "--overwrite")
    lab.create(scheduling_probe("fixture-stale-profile-readiness", token))
    stale_blocked = unscheduled(lab, "fixture-stale-profile-readiness")
    lab.kubectl("--as=" + publisher, "label", "node", node, f"{LABEL}={token}", "--overwrite")
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/fixture-awaits-profile",
                "--timeout=55s", timeout=65)
    selected = json.loads(lab.kubectl("get", "pod/fixture-awaits-profile", "-o", "json").stdout)["spec"]["nodeName"]
    marker = lab.kubectl("logs", "fixture-awaits-profile").stdout.strip()
    lab.kubectl("--as=" + publisher, "label", "node", node, LABEL + "-")
    lab.create(scheduling_probe("fixture-after-readiness-withdrawn", token))
    blocked_after = unscheduled(lab, "fixture-after-readiness-withdrawn")
    lab.check("positive", "The scheduler places the marker on the eligible node, and the next Pod waits after label withdrawal",
              selected == node and marker == "SAF-AA-ELIGIBLE" and blocked_after,
              {"selected_expected_node": selected == node, "marker": marker, "blocked_after_withdrawal": blocked_after})

    lab.kubectl("--as=" + publisher, "label", "node", node, f"{LABEL}={token}", "--overwrite")
    lab.create(live_scheduling_probe("fixture-live-after-withdrawal", token))
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Running", "pod/fixture-live-after-withdrawal",
                "--timeout=45s", timeout=52)
    lab.kubectl("--as=" + publisher, "label", "node", node, LABEL + "-")
    live_after_withdrawal = json.loads(lab.kubectl(
        "get", "pod/fixture-live-after-withdrawal", "-o", "json").stdout)
    remained_running = (live_after_withdrawal["status"].get("phase") == "Running"
                        and live_after_withdrawal["spec"].get("nodeName") == node)
    live_log = lab.kubectl("logs", "fixture-live-after-withdrawal").stdout
    lab.kubectl("delete", "pod", "fixture-live-after-withdrawal", "--wait=true", "--timeout=35s",
                timeout=42)
    deleted = lab.kubectl("get", "pod", "fixture-live-after-withdrawal", allow_failure=True)
    stopped = deleted.returncode != 0 and "(NotFound)" in deleted.stderr
    lab.check("positive", "A benign workload starts on the labeled node; withdrawal leaves it running until explicit deletion",
              remained_running and "SAF-AA-LIVE-STARTED" in live_log and stopped,
              {"live_workload_remained_running_after_withdrawal": remained_running,
               "live_workload_started": "SAF-AA-LIVE-STARTED" in live_log,
               "explicitly_stopped": stopped})
    lab.check("positive", "A stale readiness value does not satisfy the current profile revision selector",
              stale_blocked, {"stale_readiness_unschedulable": stale_blocked})
    verify_unavailable_localhost(lab)
    (lab.evidence / "apparmor-profile-observations.json").write_text(json.dumps({
        "profile": PROFILE, "sha256": digest, "guest_image": image["Id"],
        "running_guest_image": status["imageID"], "missing_guest_profile": missing,
        "loaded_expected_profile": exact, "guest_enforcement": enforced, "guest_rollback": restored,
        "initial_selector_unsatisfied": no_initial_label, "after_withdrawal_unsatisfied": blocked_after,
        "stale_readiness_unschedulable": stale_blocked,
        "selected_expected_node": selected == node, "readiness_scope": "disconnected guest and explicit lab scheduling label",
        "live_workload_remained_running_after_withdrawal": remained_running,
        "live_workload_explicitly_stopped": stopped,
    }, indent=2) + "\n")
