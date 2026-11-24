"""Check a synthetic finding lifecycle and recheck a live safe kubelet state."""
from copy import deepcopy
import importlib.util
from pathlib import Path


HERE = Path(__file__).parent
NODE_IMAGE = "kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256"
SCOPE = (
    "Synthetic finding workflow with an owned corrective revision, deadline, independent "
    "retest and linked closure. The historical example is separate from the live scan. "
    "The disposable Kind v1.34.8 node runs a selected CIS 1.12 kube-bench check before "
    "and after tightening its kubelet configuration file mode. The permissions change and "
    "scan results are live. The change owner, approval and reviewer are fixture identities."
)


def prepare_kind(lab, temporary):
    profile = temporary / "kind.yaml"
    profile.write_text("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n- role: control-plane\n")
    return profile


def run(lab):
    spec = importlib.util.spec_from_file_location("synthetic_workflow", HERE / "validate_workflow.py")
    workflow = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(workflow)
    complete = workflow.load("remediation-workflow.json")
    same_reviewer = deepcopy(complete)
    same_reviewer["retest"]["reviewer"]["name"] = complete["remediation"]["owner"]["name"]
    failure = None
    try:
        workflow.validate(same_reviewer)
    except AssertionError as error:
        failure = str(error)
    lab.check("red", "Closure fails when the remediation owner conducts the retest",
              failure == "owner cannot approve own retest", {"workflow_error": failure})
    workflow.validate(complete)
    lab.check("green", "Closure links a passing independent retest to the owned revision and deadline",
              True, {"finding": complete["finding"]["id"], "tested_revision": complete["retest"]["tested_revision"]})

    node = f"{lab.cluster}-control-plane"
    config = lab.command("docker", "exec", node, "awk",
                         r"/^readOnlyPort:[[:space:]]*/ {print $2}",
                         "/var/lib/kubelet/config.yaml").stdout.split()
    script = r'''awk '$4 == "0A" && ($2 ~ /:280A$/ || $2 ~ /:280F$/) {print substr($2, length($2)-3)}' /proc/net/tcp /proc/net/tcp6'''
    listeners = lab.command("docker", "exec", node, "sh", "-ec", script).stdout.split()
    live_mitigated = config in ([], ["0"]) and "280F" not in listeners and "280A" in listeners
    lab.check("positive", "The live kubelet has the secure listener and no read-only listener",
              live_mitigated, {"configured_read_only_port": int(config[0]) if config else None,
                               "live_read_only_listener": "280F" in listeners,
                               "live_secure_listener": "280A" in listeners})

    scan_spec = importlib.util.spec_from_file_location("cis_scan_remediation", HERE / "scan-remediation.py")
    scan = importlib.util.module_from_spec(scan_spec)
    scan_spec.loader.exec_module(scan)
    scan.run(lab)
