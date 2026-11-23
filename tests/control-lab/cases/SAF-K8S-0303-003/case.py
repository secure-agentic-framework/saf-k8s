"""Verify SELinux category intent in Kubernetes and MCS enforcement in an isolated guest."""

import hashlib
import json
from pathlib import Path

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
NAME = "fixture-selinux-categories"
NS = "saf-test"
LEVELS = ("s0:c10,c20", "s0:c11,c21")
BUILD_LABEL = "org.saf.fixture.selinux-build"
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
IMAGE = "saf-lab-selinux:source-" + SOURCE[:24]
SCOPE = (
    "Verify explicit SELinux category declarations and the native Pod Security boundary, then "
    "exercise two process category labels, matching DAC, and an object relabel in a disconnected "
    "SELinux guest. The guest consumes the levels read back from Kubernetes; kubelet/runtime "
    "application and CSI relabeling require a SELinux-capable deployment."
)


def intent(name, level=None, *, custom_role=False):
    fields = {"schedulingGates": [{"name": "saf.example.org/hold-mcs-fixture"}],
              "automountServiceAccountToken": False}
    if level is not None:
        options = {"type": "container_t", "level": level}
        if custom_role:
            options["role"] = "fixture_custom_r"
        fields["securityContext"] = {"seLinuxOptions": options}
    return pod(name, [container("marker", command=["sh", "-c", "exit 0"])], **fields)


def guest_job(levels):
    guest = {"name": "guest", "image": IMAGE, "imagePullPolicy": "Never",
             "command": ["sh", "/fixture/boot.sh", *levels],
             "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                              {"name": "scratch", "mountPath": "/tmp"}],
             "securityContext": {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                 "capabilities": {"drop": ["ALL"]}},
             "resources": {"requests": {"cpu": "200m", "memory": "256Mi"},
                           "limits": {"cpu": "1500m", "memory": "768Mi"}}}
    return {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME},
            "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90, "template": {"spec": {
                "restartPolicy": "Never", "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [guest], "volumes": [{"name": "fixture", "configMap": {"name": NAME}},
                                                 {"name": "scratch", "emptyDir": {}}],
            }}}}


def run(lab):
    lab.kubectl("label", "namespace", NS, "pod-security.kubernetes.io/enforce=restricted",
                "pod-security.kubernetes.io/enforce-version=v1.36", "--overwrite")
    unset = lab.create(intent("fixture-category-omitted"), dry_run=True, allow_failure=True)
    custom = lab.create(intent("fixture-category-custom-role", LEVELS[0], custom_role=True),
                        dry_run=True, allow_failure=True)
    role_denied = (custom.returncode != 0 and "PodSecurity" in custom.stderr
                   and "seLinuxOptions" in custom.stderr and "role may not be set" in custom.stderr)
    observed = []
    for suffix, level in zip(("a", "b"), LEVELS):
        name = "fixture-category-" + suffix
        lab.create(intent(name, level))
        reading = json.loads(lab.kubectl("get", "pod/" + name, "-o", "json").stdout)
        if not reading["spec"].get("schedulingGates"):
            lab.block("The isolated intent fixture was expected to remain scheduling-gated")
        observed.append(reading["spec"]["securityContext"]["seLinuxOptions"]["level"])

    if lab.command("docker", "image", "inspect", IMAGE, allow_failure=True).returncode:
        lab.command("docker", "build", "-q", "-t", IMAGE, "--label", f"{BUILD_LABEL}={SOURCE}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
    image, = json.loads(lab.command("docker", "image", "inspect", IMAGE).stdout)
    if image["Config"].get("Labels", {}).get(BUILD_LABEL) != SOURCE:
        lab.block("The isolated SELinux image does not match the pinned guest fixture recipe")
    lab.command("kind", "load", "docker-image", IMAGE, "--name", lab.cluster, timeout=220)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME}, "immutable": True,
                "data": {"boot.sh": (HERE / "selinux-fixture.sh").read_text()}})
    lab.create(guest_job(observed))
    completion = lab.kubectl("wait", "--for=condition=Complete", "job/" + NAME, "--timeout=104s",
                             timeout=112, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    if completion.returncode or logs.returncode or len(rows) != 1:
        lab.block("The isolated SELinux guest did not complete; inspect the owned Job evidence")
    worker, = rows
    status, = worker["status"]["containerStatuses"]
    messages = set(logs.stdout.splitlines())
    policy, = (line.rsplit(" ", 1)[-1] for line in messages if line.startswith("SAF-SELINUX-POLICY: "))
    contexts = " ".join("system_u:system_r:container_t:" + level for level in observed)
    context_match = "SAF-SELINUX-CONTEXTS: " + contexts in messages
    dac = "SAF-SELINUX: matched DAC comparison and enforcing" in messages
    boundary = "SAF-SELINUX: both category boundaries enforced with process category observations" in messages
    relabel = "SAF-SELINUX: changing only object categories changes both decisions" in messages
    lab.check("red", "Native Restricted admission accepts level omission and the inert cross-category canary is readable in permissive mode",
              unset.returncode == 0 and dac, {"omission_accepted": unset.returncode == 0, "matched_dac_comparison": dac})
    lab.check("green", "Native admission refuses a custom role and the guest enforces distinct actual process categories",
              role_denied and tuple(observed) == LEVELS and context_match and boundary,
              {"custom_role_denied": role_denied, "admitted_levels": observed, "observed_process_contexts": context_match,
               "both_category_boundaries": boundary})
    lab.check("positive", "Changing only the fixture object category flips the two decisions in enforcing mode",
              relabel, {"relabel_changes_both_decisions": relabel})
    (lab.evidence / "selinux-category-observations.json").write_text(json.dumps({
        "approved_levels": observed, "loaded_policy_sha256": policy, "guest_image": image["Id"],
        "running_guest_image": status["imageID"], "matching_guest_contexts": context_match,
        "isolated_guest_boundary": boundary, "isolated_guest_relabel": relabel,
        "node_selinux_runtime_application_tested": False, "csi_relabel_tested": False,
    }, indent=2) + "\n")
