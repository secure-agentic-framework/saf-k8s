"""Inventory one configured non-default feature gate from effective API server metrics."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess

from lab import Lab


HERE = Path(__file__).parent
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
GATE = "TaintTolerationComparisonOperators"
COMPONENT = "kube-apiserver"
SCOPE = (
    "Paired disposable Kubernetes v1.36.1 clusters. The stock API server supplies the "
    "effective default and the second API server enables one alpha gate. The test inventories "
    "that component and gate. Full production component inventory and governance need separate evidence."
)

_spec = importlib.util.spec_from_file_location(
    "saf_k8s_0104_022_evaluator", HERE / "evaluator.py")
evaluator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evaluator)


def prepare_kind(lab, temporary: Path) -> Path:
    """Generate kubeadm config that enables exactly the case gate on kube-apiserver."""
    config = temporary / "kind.yaml"
    config.write_text(
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n"
        "- role: control-plane\n"
        "kubeadmConfigPatches:\n"
        "- |\n"
        "  apiVersion: kubeadm.k8s.io/v1beta4\n"
        "  kind: ClusterConfiguration\n"
        "  apiServer:\n"
        "    extraArgs:\n"
        "      - name: feature-gates\n"
        f"        value: {GATE}=true\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    return config


def _metric_observation(metrics):
    pattern = re.compile(
        r'^kubernetes_feature_enabled\{(?P<labels>[^}]*)\}\s+(?P<value>[01](?:\.0+)?)$')
    matches = []
    for line in metrics.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        labels = dict(re.findall(r'([A-Za-z_][A-Za-z0-9_]*)="([^"]*)"', match["labels"]))
        if labels.get("name") == GATE:
            matches.append({"component": COMPONENT, "feature": GATE,
                            "enabled": float(match["value"]) == 1.0,
                            "stage": labels.get("stage")})
    if len(matches) != 1:
        raise ValueError(f"expected one API server metric for {GATE}; found {len(matches)}")
    return matches[0]


def _component_arguments(pod):
    containers = pod.get("spec", {}).get("containers", [])
    component = next((item for item in containers if item.get("name") == COMPONENT), None)
    if component is None:
        raise ValueError("API server static pod has no kube-apiserver container")
    return component.get("command", []) + component.get("args", [])


def observe(lab):
    response = subprocess.run(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--request-timeout=20s", "get", "--raw", "/metrics"],
        capture_output=True, text=True, env=lab.env, timeout=25,
    )
    if response.returncode:
        lab.block("The owned kube-apiserver metrics were unavailable")
    return _metric_observation(response.stdout)


def observe_stock(lab):
    stock = Lab(lab.evidence, lab.context, lab.kubeconfig.parent / "stock-kubeconfig")
    if stock.cluster in stock.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("Generated stock cluster name is already in use")
    try:
        stock.command("kind", "create", "cluster", "--name", stock.cluster, "--image", NODE_IMAGE,
                      "--kubeconfig", str(stock.kubeconfig), "--wait", "90s", timeout=480)
        data = observe(stock)
        version = json.loads(stock.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    finally:
        stock.command("kind", "delete", "cluster", "--name", stock.cluster,
                      "--kubeconfig", str(stock.kubeconfig), timeout=90)
    deleted = stock.cluster not in stock.command("kind", "get", "clusters").stdout.splitlines()
    return data, version, deleted


def run(lab):
    baseline = json.loads((HERE / "baseline.json").read_text(encoding="utf-8"))
    expected = json.loads((HERE / "expected-effective.json").read_text(encoding="utf-8"))

    stock, stock_version, stock_deleted = observe_stock(lab)
    default_inventory = evaluator.evaluate(baseline, [stock])
    lab.check("red", "The stock API server reports the versioned default and no override",
              stock["enabled"] == baseline["default"] and default_inventory == []
              and stock_version == f"v{baseline['kubernetes_version']}" and stock_deleted,
              {"stock_metric": stock, "classified_inventory": default_inventory,
               "stock_version": stock_version, "stock_cleanup": stock_deleted})

    pod_name = f"kube-apiserver-{lab.cluster}-control-plane"
    pod = json.loads(lab.kubectl("get", "pod", "-n", "kube-system", pod_name,
                                  "-o", "json").stdout)
    args = _component_arguments(pod)
    configured = f"--feature-gates={GATE}=true" in args
    effective = observe(lab)
    inventory = evaluator.evaluate(baseline, [effective])
    expected_inventory = expected["expected_inventory"]
    lab.check("green", "Effective read-only API server state is statically classified",
              inventory == expected_inventory and effective["enabled"],
              {"effective_metric": effective, "classified_inventory": inventory,
               "expected_inventory": expected_inventory})
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    lab.check("positive", "Generated configuration and effective metric agree",
              configured and effective["enabled"] is True and version == stock_version,
              {"api_server_feature_gate_argument_present": configured,
               "effective_metric_enabled": effective["enabled"],
               "metric_source": "kube-apiserver /metrics via read-only Kubernetes API GET"})
