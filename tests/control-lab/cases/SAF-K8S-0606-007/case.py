"""Observe the owned runner's harmless command and public marker access."""
from hashlib import sha256
import json
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE, container

HERE = Path(__file__).resolve().parent
CHART = "https://helm.cilium.io/tetragon-1.8.0.tgz"
CHART_HASH = "38a10bca4bffd3efac7cbcc7f99b24dbcd3ef76402aa7bbb72c0b2e2dc0c8111"
AGENT = "quay.io/cilium/tetragon:v1.8.0@sha256:5ed9088a1582131d71b06c98e0d549a37a71ae63ab13aabefc7a47553c822a9d"
OPERATOR = ("quay.io/cilium/tetragon-operator:v1.8.0@sha256:"
            "af2b6f0a8609d66190f1d5bbdea38a160d5460f2ea416beea42a615aadd8b35a")
EXPORTER = ("quay.io/cilium/hubble-export-stdout:v1.1.1@sha256:"
            "cf701f96d1c8de30231792e35733e1ab07451e11751ef4f676f482836759da06")
AGENT_NS = "saf-fixture-observer"
POD = "saf-runner-marker"
POLICY = "saf-public-marker-read"
MARKER = "/tmp/saf-fixture-public.txt"
OTHER = "/tmp/saf-fixture-control.txt"
SCOPE = (
    "A disposable Kind node with pinned Tetragon, namespace-scoped JSON export and a "
    "non-enforcing filename observation rule. Only the fixture runner and its public "
    "harmless markers are observed. Operator audit integration, network and credential "
    "coverage, event loss and downstream alert delivery require separate evidence."
)


def scoped(lab, namespace, obj):
    return lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(obj))


def install(lab, namespace):
    chart = lab.kubeconfig.parent / "tetragon-1.8.0.tgz"
    values = chart.with_name("tetragon-values.json")
    lab.command("curl", "-fLsS", "--max-time", "25", "-o", str(chart), CHART, timeout=30)
    if sha256(chart.read_bytes()).hexdigest() != CHART_HASH:
        lab.block("The fixture's downloaded chart does not match its immutable expected checksum")
    values.write_text(json.dumps({
        "tetragon": {
            "image": {"override": AGENT},
            "enableK8sAPI": True,
            "exportAllowList": json.dumps({"namespace": [namespace],
                                          "event_set": ["PROCESS_EXEC", "PROCESS_KPROBE"]}),
        },
        "tetragonOperator": {"image": {"override": OPERATOR}},
        "export": {"stdout": {"image": {"override": EXPORTER}}},
        "crds": {"installMethod": "helm"},
    }))
    lab.command("helm", "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
                "upgrade", "--install", "tetragon", str(chart), "--namespace", AGENT_NS, "--create-namespace",
                "--values", str(values), "--wait", "--timeout", "100s", timeout=110)
    lab.kubectl("-n", AGENT_NS, "rollout", "status", "daemonset/tetragon", "--timeout=80s", timeout=90)


def sample(lab, namespace):
    start = f"printf 'public fixture marker\\n' > {MARKER} && printf 'owned comparison marker\\n' > {OTHER} && sleep 400"
    scoped(lab, namespace, {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD},
                            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                     "containers": [container("marker", command=["sh", "-c", start])]}})
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{POD}", "--timeout=45s", timeout=55)


def events(lab, namespace):
    output = lab.kubectl("-n", AGENT_NS, "logs", "daemonset/tetragon", "-c", "export-stdout", "--tail=100")
    results = []
    for line in output.stdout.splitlines():
        if not line.startswith("{"):
            continue
        data = json.loads(line)
        key = next((kind for kind in ("process_exec", "process_kprobe") if kind in data), None)
        if key is None:
            continue
        record = data[key]
        pod = record.get("process", {}).get("pod", {})
        if pod.get("namespace") == namespace and pod.get("name") == POD:
            results.append((key, record))
    return results


def command(lab, namespace, path):
    result = lab.kubectl("-n", namespace, "exec", POD, "--", "/bin/busybox", "cat", path)
    expected = "public fixture marker" if path == MARKER else "owned comparison marker"
    if result.stdout.strip() != expected:
        lab.block("The read did not return the declared public fixture bytes")


def exec_ids(rows, path):
    return {record["process"]["exec_id"] for kind, record in rows if kind == "process_exec"
            and record["process"]["arguments"] == f"cat {path}"}


def filename_events(rows, ids):
    return [record for kind, record in rows
            if kind == "process_kprobe" and record.get("process", {}).get("exec_id") in ids
            and record.get("function_name") == "security_file_permission"
            and record.get("policy_name") == POLICY and MARKER in json.dumps(record.get("args", []))]


def wait_for(lab, namespace, match, reason):
    end = time.monotonic() + 24
    while time.monotonic() < end:
        snapshot = events(lab, namespace)
        if match(snapshot):
            return snapshot
        time.sleep(0.65)
    lab.block(reason)


def add_rule(lab, namespace):
    scoped(lab, namespace, {
        "apiVersion": "cilium.io/v1alpha1", "kind": "TracingPolicyNamespaced", "metadata": {"name": POLICY},
        "spec": {"kprobes": [{
            "call": "security_file_permission", "syscall": False, "return": True,
            "args": [{"index": 0, "type": "file"}, {"index": 1, "type": "int"}],
            "returnArg": {"index": 0, "type": "int"},
            "selectors": [{"matchArgs": [
                {"index": 0, "operator": "Equal", "values": [MARKER]},
                {"index": 1, "operator": "Equal", "values": ["4"]},
            ]}],
        }]},
    })
    end = time.monotonic() + 25
    while time.monotonic() < end:
        status = lab.kubectl("-n", AGENT_NS, "exec", "daemonset/tetragon", "-c", "tetragon",
                             "--", "tetra", "tracingpolicy", "list", allow_failure=True)
        if status.returncode == 0 and any(
            POLICY in line and "enabled" in line.lower() for line in status.stdout.splitlines()
        ):
            return
        time.sleep(0.5)
    lab.block("The namespaced public-marker observation policy did not become active")


def run(lab):
    namespace = "saf-observed-" + lab.cluster[-9:]
    lab.kubectl("create", "namespace", namespace)
    install(lab, namespace)
    sample(lab, namespace)
    command(lab, namespace, MARKER)
    before = wait_for(lab, namespace, lambda rows: exec_ids(rows, MARKER), "The fixture process did not reach export")
    old = exec_ids(before, MARKER)
    baseline_detected = bool(old) and not filename_events(before, old)
    lab.check("red", "Before the rule Tetragon sees fixture execution and lacks the marker-specific observation",
              baseline_detected, {"execution_visible": bool(old), "specific_file_observation_absent": baseline_detected})

    add_rule(lab, namespace)
    command(lab, namespace, MARKER)
    matched = wait_for(lab, namespace, lambda rows: filename_events(rows, exec_ids(rows, MARKER) - old),
                       "The active policy did not correlate the public marker access with its executing process")
    current = exec_ids(matched, MARKER) - old
    observed = filename_events(matched, current)
    lab.check("green", "The exact marker path is correlated with the same newly executed fixture process",
              bool(observed), {"marker_observed": bool(observed), "fixture_workload_identity_verified": bool(current)})

    command(lab, namespace, OTHER)
    compared = wait_for(lab, namespace, lambda rows: exec_ids(rows, OTHER), "The unselected marker command was absent")
    unrelated = exec_ids(compared, OTHER)
    omitted = bool(unrelated) and not filename_events(compared, unrelated)
    lab.check("positive", "The other harmless read remains visible as execution without a matching file observation",
              omitted, {"comparison_execution_visible": bool(unrelated), "marker_specific_filter_preserved": omitted})
    (lab.evidence / "fixture-observation.json").write_text(json.dumps({
        "chart_sha256": CHART_HASH, "before_exec_ids": sorted(old), "matched_exec_ids": sorted(current),
        "observations": observed,
    }, indent=2, sort_keys=True) + "\n")
