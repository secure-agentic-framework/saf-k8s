"""Validate explicit RuntimeClass enforcement, node scheduling, and CRI handler choice."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time

IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
NAMESPACE = "saf-test"
PROTECTED = "saf-k8s-0202-002.protected"
NODE_LABEL = "saf-k8s-0202-002.runtime-handler"
HANDLER = "saf-runc"
STATE_ROOT = "/run/saf-runtimeclass-runc/k8s.io"
DENIAL = "protected workloads must select RuntimeClass saf-runc"
GVISOR_HANDLER = "saf-gvisor"
GVISOR_NAMESPACE = "saf-gvisor-test"
GVISOR_NODE_LABEL = "saf-k8s-0202-002.runtime-gvisor"
GVISOR_ROOT = "/run/containerd/runsc/k8s.io"
GVISOR_MARKER = "SAF-K8S-0202-002-GVISOR-MARKER"
GVISOR_DENIAL = "gvisor-profile namespace workloads must select RuntimeClass saf-gvisor"

GVISOR_SHA256 = {
    "aarch64": "c849ede41d4349b008e775a71c1021bee8ff648432f8751178727c9066c1e353",
    "x86_64": "e22638939473759a8602e80f2b96a9b67e4afcdf58f2c51db52b1a8e9031ea45",
}

SCOPE = (
    "One-node isolated Kind case: preserves the saf-runc io.containerd.runc.v2 baseline "
    "and adds release-20261116.0 gVisor runsc systrap through the containerd 2.x "
    "io.containerd.runsc.v1 shim. It verifies pinned archive hashes, a namespace-scoped "
    "gVisor profile, scheduling, a /proc/version marker, and exact CRI sandbox/runsc/shim "
    "identity. This is a harmless local runtime-selection demonstration, not production "
    "assurance, GPU validation, Kata evidence, or an escape-resistance test."
)


def pod(name, runtime_class=None):
    spec = {
        "restartPolicy": "Always",
        "automountServiceAccountToken": False,
        "containers": [{
            "name": "fixture",
            "image": IMAGE,
            "command": ["sh", "-c", "sleep 3600"],
            "securityContext": {
                "allowPrivilegeEscalation": False,
                "capabilities": {"drop": ["ALL"]},
                "runAsNonRoot": True,
                "runAsUser": 65534,
                "readOnlyRootFilesystem": True,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
        }],
    }
    if runtime_class is not None:
        spec["runtimeClassName"] = runtime_class
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "labels": {PROTECTED: "true"}},
        "spec": spec,
    }


def deployment():
    labels = {"app": "saf-0202-rollout", PROTECTED: "true"}
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "saf-0202-permitted-rollout"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": labels["app"]}},
            "template": {
                "metadata": {"labels": labels},
                "spec": pod("template", HANDLER)["spec"],
            },
        },
    }


def gvisor_pod(name, runtime_class=None):
    command = (
        'test "$(id -u)" = 65534; '
        f"echo '{GVISOR_MARKER}'; "
        "sleep 3600"
    )
    result = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": GVISOR_NAMESPACE},
        "spec": {
            "restartPolicy": "Always", "automountServiceAccountToken": False,
            "containers": [{
                "name": "fixture", "image": IMAGE,
                "command": ["sh", "-ec", command],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                    "runAsNonRoot": True, "runAsUser": 65534,
                    "readOnlyRootFilesystem": True,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
            }],
        },
    }
    if runtime_class is not None:
        result["spec"]["runtimeClassName"] = runtime_class
    return result


def crictl_sandbox(lab, pod_name):
    node = f"{lab.cluster}-control-plane"
    listed = json.loads(lab.command(
        "docker", "exec", node, "crictl", "pods", "-o", "json", timeout=30
    ).stdout)
    rows = listed.get("items", listed) if isinstance(listed, dict) else listed
    match = [row for row in rows
             if row.get("metadata", {}).get("name") == pod_name
             and row.get("metadata", {}).get("namespace") == NAMESPACE]
    if len(match) != 1:
        lab.block(f"CRI did not return exactly one sandbox for {pod_name}")
    row = match[0]
    sandbox = row.get("id", "")
    if not re.fullmatch(r"[a-f0-9]{64}", sandbox) or row.get("state") != "SANDBOX_READY":
        lab.block("CRI did not report the expected ready sandbox ID")
    present = lab.command("docker", "exec", node, "test", "-d", f"{STATE_ROOT}/{sandbox}",
                          allow_failure=True, timeout=10)
    if present.returncode not in (0, 1):
        lab.block("Could not measure the case-owned runtime's state root")
    return present.returncode == 0


def crictl_gvisor_identity(lab, pod_name):
    """Correlate one Ready CRI sandbox with its runsc state and shim process."""
    node = f"{lab.cluster}-control-plane"
    listed = json.loads(lab.command(
        "docker", "exec", node, "crictl", "pods", "-o", "json", timeout=30
    ).stdout)
    rows = listed.get("items", listed) if isinstance(listed, dict) else listed
    match = [row for row in rows
             if row.get("metadata", {}).get("name") == pod_name
             and row.get("metadata", {}).get("namespace") == GVISOR_NAMESPACE]
    if len(match) != 1:
        lab.block(f"CRI did not return exactly one gVisor sandbox for {pod_name}")
    row = match[0]
    sandbox = row.get("id", "")
    if not re.fullmatch(r"[a-f0-9]{64}", sandbox) or row.get("state") != "SANDBOX_READY":
        lab.block("CRI did not report the expected ready gVisor sandbox ID")
    state = lab.command(
        "docker", "exec", node, "runsc", "--root", GVISOR_ROOT, "list", "-quiet",
        timeout=20,
    )
    state_ids = {line.strip() for line in state.stdout.splitlines() if line.strip()}
    if sandbox not in state_ids:
        lab.block("Exact CRI sandbox ID is absent from runsc's state listing")
    process = lab.command(
        "docker", "exec", node, "sh", "-ceu",
        """ps -eww -o pid=,args= | awk -v id="$1" '
          $2 ~ /(^|\/)containerd-shim-runsc-v1$/ {
            for (i=3; i<=NF; i++)
              if (($i=="-id" && $(i+1)==id) || $i=="-id=" id) print $1
          }
        '""", "sh", sandbox, timeout=20,
    )
    pids = process.stdout.split()
    if len(pids) != 1 or not pids[0].isdecimal():
        lab.block("Could not bind the exact CRI sandbox to one runsc shim PID")
    executable = lab.command("docker", "exec", node, "readlink", "-f", f"/proc/{pids[0]}/exe").stdout.strip()
    if executable != "/usr/local/bin/containerd-shim-runsc-v1":
        lab.block("The case did not observe the approved gVisor shim executable")
    return {"sandbox_id": sandbox, "cri_state": row.get("state"),
            "runsc_state_contains_sandbox": True, "shim_executable": executable}


def await_denial(lab, fixture, message=DENIAL):
    deadline = time.monotonic() + 30
    while True:
        response = lab.create(fixture, dry_run=True, allow_failure=True)
        if response.returncode and message in response.stderr:
            return True
        if response.returncode or time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


def await_ready(lab, name, namespace=None):
    args = ["wait", "--for=condition=Ready", f"pod/{name}"]
    if namespace is not None:
        args.extend(["-n", namespace])
    args.append("--timeout=90s")
    lab.kubectl(*args,
                timeout=100)
    get_args = ["get", f"pod/{name}", "-o", "json"]
    if namespace is not None:
        get_args.extend(["-n", namespace])
    current = json.loads(lab.kubectl(*get_args).stdout)
    return current



def setup_gvisor(lab, node):
    architecture = lab.command("docker", "exec", node, "uname", "-m").stdout.strip()
    if architecture not in GVISOR_SHA256:
        lab.block("The pinned gVisor release has no verified asset for this architecture")
    with tempfile.TemporaryDirectory(prefix="saf-gvisor-package-") as temp:
        archive = Path(temp) / "gvisor.tar.bz2"
        transfer = Path(temp) / "gvisor-reviewed.tar.gz"
        url = f"https://storage.googleapis.com/gvisor/releases/release/20261116.0/{architecture}/gvisor.tar.bz2"
        lab.command("curl", "-q", "--fail", "--silent", "--show-error", "--location", "--proto", "=https",
                    "--connect-timeout", "15", "--max-time", "120", "--output", str(archive), url, timeout=130)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != GVISOR_SHA256[architecture]:
            lab.block("The official gVisor bundle did not match its pinned digest")
        required = {"runsc", "containerd-shim-runsc-v1"}
        included = set()
        with tarfile.open(archive, "r:bz2") as inputs, tarfile.open(transfer, "w:gz") as output:
            for member in inputs:
                filename = member.name.rstrip("/")
                if member.isdir() and filename == "gvisor-bin":
                    continue
                approved = filename in required or re.fullmatch(r"gvisor-bin/[A-Za-z0-9._+-]+", filename)
                if (not approved or not member.isfile() or filename in included
                        or not 0 < member.size <= 128 * 1024 * 1024
                        or filename.split("/")[-1] in (".", "..")):
                    lab.block("The verified gVisor archive had an unexpected member")
                included.add(filename)
                output.addfile(member, inputs.extractfile(member))
        if not required <= included or not any(name.startswith("gvisor-bin/") for name in included):
            lab.block("The reviewed archive did not contain the required runtime and sidecars")
        script = Path(__file__).with_name("install-gvisor.sh").read_text()
        with transfer.open("rb") as contents:
            installed = subprocess.run(["docker", "exec", "-i", node, "bash", "-ec", script],
                                       stdin=contents, env=lab.env, capture_output=True, timeout=120)
        if installed.returncode:
            lab.block("The approved gVisor archive could not be installed on the owned node: "
                      + installed.stderr.decode(errors="replace")[-700:])
    lab.check("positive", "Pinned runsc systrap package installs inside the owned node",
              True, {"approved_release": "20261116.0", "verified_archive_sha256": digest})

def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s-0202-002.case=enabled", "--overwrite")
    lab.create({
        "apiVersion": "node.k8s.io/v1",
        "kind": "RuntimeClass",
        "metadata": {"name": HANDLER},
        "handler": HANDLER,
        "scheduling": {"nodeSelector": {NODE_LABEL: HANDLER}},
    })

    node = f"{lab.cluster}-control-plane"
    setup_gvisor(lab, node)
    lab.kubectl("label", "node", node, f"{GVISOR_NODE_LABEL}={GVISOR_HANDLER}")
    lab.kubectl("create", "namespace", GVISOR_NAMESPACE)
    lab.kubectl("label", "namespace", GVISOR_NAMESPACE,
                "saf-k8s-0202-002.profile=gvisor", "--overwrite")
    lab.create({
        "apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass",
        "metadata": {"name": GVISOR_HANDLER}, "handler": GVISOR_HANDLER,
        "scheduling": {"nodeSelector": {GVISOR_NODE_LABEL: GVISOR_HANDLER}},
    })
    denied_fixture = gvisor_pod("saf-0202-gvisor-denied")
    admission_probe = ("-n", GVISOR_NAMESPACE, "create", "-f", "-", "--dry-run=server")
    payload = json.dumps(denied_fixture)
    admitted = lab.kubectl(*admission_probe, payload=payload, allow_failure=True).returncode == 0
    lab.check("red", "The gVisor namespace marker is admitted before the class requirement applies",
              admitted, {"baseline_admitted": admitted})
    lab.apply(Path(__file__).with_name("admission-gvisor.yaml"))
    deadline = time.monotonic() + 25
    while True:
        denied_response = lab.kubectl(*admission_probe, payload=payload, allow_failure=True)
        gvisor_denied = denied_response.returncode != 0 and GVISOR_DENIAL in denied_response.stderr
        if gvisor_denied or time.monotonic() >= deadline:
            break
        if denied_response.returncode:
            lab.block("The gVisor admission fixture was rejected for a different reason")
        time.sleep(0.5)
    lab.check("green",
              "Namespace-classified gVisor profile denies the marker workload without its class",
              gvisor_denied, {"exact_policy_denial": gvisor_denied,
                              "classification_source": "operator-controlled namespace label"})

    # Red: the same protected fixture is admitted and runs with the node's
    # default runtime when no RuntimeClass is selected.
    baseline = pod("saf-0202-baseline")
    red = lab.create(baseline, dry_run=True, allow_failure=True)
    lab.check("red", "Unassigned protected workload reaches API admission before validation",
              red.returncode == 0, red.stderr.strip() or "server dry-run admitted")
    lab.create(baseline)
    running = await_ready(lab, baseline["metadata"]["name"])
    custom_state = crictl_sandbox(lab, baseline["metadata"]["name"])
    lab.check("red", "Ready baseline sandbox has no state under the explicit handler root",
              running["status"].get("phase") == "Running" and not custom_state,
              {"pod_running": running["status"].get("phase") == "Running",
               "custom_handler_state_exists": custom_state})

    lab.kubectl("delete", f"pod/{baseline['metadata']['name']}", "--wait=true", "--timeout=40s", timeout=50)
    lab.apply(Path(__file__).with_name("admission-policy.yaml"))
    denied = await_denial(lab, baseline)
    lab.check("green", "Admission denies protected workload without explicit RuntimeClass",
              denied, {"exact_policy_denial": denied})

    # Positive: an allowed Deployment rollout must land on the RuntimeClass
    # node and the CRI sandbox must report the named runtime handler.
    lab.create(deployment())
    rollout = lab.kubectl("rollout", "status", "deployment/saf-0202-permitted-rollout",
                          "--timeout=100s", timeout=110)
    pods = json.loads(lab.kubectl("get", "pods", "-l", "app=saf-0202-rollout",
                                  "-o", "json").stdout)["items"]
    if len(pods) != 1:
        lab.block("Permitted Deployment did not produce exactly one Pod")
    name = pods[0]["metadata"]["name"]
    current = await_ready(lab, name)
    selected_node = current["spec"].get("nodeName", "")
    if selected_node != f"{lab.cluster}-control-plane":
        lab.block("Permitted Pod did not reach the expected owned kind node")
    node = json.loads(lab.kubectl("get", "node", selected_node, "-o", "json").stdout)
    label = node["metadata"].get("labels", {}).get(NODE_LABEL)
    selector = current["spec"].get("nodeSelector", {}).get(NODE_LABEL)
    scheduled = (current["spec"].get("runtimeClassName") == HANDLER
                 and current["status"].get("phase") == "Running"
                 and selector == HANDLER and label == HANDLER)
    lab.check("positive", "RuntimeClass rollout runs Ready with the selector on its supported node",
              rollout.returncode == 0 and scheduled,
              {"pod_running": current["status"].get("phase") == "Running",
               "runtimeclass_selector_matches_node": selector == label == HANDLER})

    custom_state = crictl_sandbox(lab, name)
    lab.check("positive", "Native runc state confirms handler selection for the exact CRI sandbox",
              custom_state, {"custom_handler_state_exists": custom_state})

    positive = gvisor_pod("saf-0202-gvisor-positive", GVISOR_HANDLER)
    lab.kubectl("-n", GVISOR_NAMESPACE, "create", "-f", "-", payload=json.dumps(positive))
    current = await_ready(lab, positive["metadata"]["name"], GVISOR_NAMESPACE)
    selected_node = current["spec"].get("nodeName", "")
    if selected_node != f"{lab.cluster}-control-plane":
        lab.block("gVisor Pod did not reach the expected owned Kind node")
    node_state = json.loads(lab.kubectl("get", "node", selected_node, "-o", "json").stdout)
    node_label = node_state["metadata"].get("labels", {}).get(GVISOR_NODE_LABEL)
    selector = current["spec"].get("nodeSelector", {}).get(GVISOR_NODE_LABEL)
    scheduled = (current["spec"].get("runtimeClassName") == GVISOR_HANDLER
                 and current["status"].get("phase") == "Running"
                 and node_label == selector == GVISOR_HANDLER)
    lab.check("positive", "Approved RuntimeClass schedules the Ready workload to its gVisor node",
              scheduled, {"pod_running": current["status"].get("phase") == "Running",
                          "runtimeclass_selector_matches_node": node_label == selector == GVISOR_HANDLER})
    probe = lab.kubectl("-n", GVISOR_NAMESPACE, "exec", f"pod/{positive['metadata']['name']}",
                        "-c", "fixture", "--", "sh", "-ceu",
                        'test "$(id -u)" = 65534; printf "%s\n" "$1"', "sh", GVISOR_MARKER)
    marker_seen = probe.stdout.strip() == GVISOR_MARKER
    lab.check("positive", "The approved workload executes a non-root marker through its live sandbox",
              marker_seen, {"marker_seen": marker_seen})
    identity = crictl_gvisor_identity(lab, positive["metadata"]["name"])
    lab.check("positive", "Exact Ready CRI sandbox appears in runsc state and uses the approved gVisor shim",
              identity["runsc_state_contains_sandbox"],
              {"runsc_state_matches": True, "expected_shim_owns_sandbox": True})
    (lab.evidence / "gvisor-runtime-observations.json").write_text(json.dumps(identity, indent=2) + "\n")
