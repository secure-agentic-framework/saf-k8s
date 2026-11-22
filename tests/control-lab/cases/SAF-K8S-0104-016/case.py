"""Check a synthetic finding lifecycle and recheck a live safe kubelet state."""
from copy import deepcopy
import importlib.util
from pathlib import Path


HERE = Path(__file__).parent
SCOPE = (
    "Synthetic finding workflow with an owned corrective revision, deadline, independent "
    "retest and linked closure. A read-only recheck observes the safe kubelet configuration "
    "and local listener state on a disposable kind v1.36.1 node. The historical finding and "
    "workflow actors are synthetic. Production coverage and licensed benchmark results "
    "require separate evidence."
)


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
