"""Exercise targeted drain, namespace policy placement, and native suspension."""
import json
from pathlib import Path
import time

from lab import InfrastructureError


HERE = Path(__file__).resolve().parent
FIXTURES = json.loads((HERE / "fixtures.json").read_text())
IMAGE = FIXTURES["image"]
MAINT_NS = FIXTURES["namespaces"]["maintenance"]
INDEP_NS = FIXTURES["namespaces"]["independent"]
MAINT_DEPLOY = FIXTURES["workloads"]["maintenance"]
INDEP_DEPLOY = FIXTURES["workloads"]["independent"]
PROBE_DEPLOY = "independent-probe"
MARKER = FIXTURES["synthetic_marker"]
LABEL = "app.kubernetes.io/name"
PLACEMENT_TAINT = "saf-k8s.example/initial-placement"
SCOPE = (
    "Disposable two-node Kubernetes v1.36.1 Kind only. The case observes eviction of one "
    "owned Deployment Pod, placement on the control-plane node, ingress and egress isolation "
    "of its namespace using the bundled CNI, scale-to-zero, and retention of an unrelated "
    "ready Pod and its HTTP path. Production authorization, incident procedures, CNI and "
    "tenant coverage, disruption budgets, and production workloads require independent review."
)


def kubectl(lab, namespace, *args, payload=None, timeout=45, allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "-n", namespace, *args, payload=payload, timeout=timeout, allow_failure=allow_failure,
    )


def cluster_kubectl(lab, *args, timeout=45, allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        *args, timeout=timeout, allow_failure=allow_failure,
    )


def save_raw(lab, filename, content):
    (lab.evidence / filename).write_text(content if content.endswith("\n") else content + "\n")


def apply(lab, namespace, resource):
    kubectl(lab, namespace, "apply", "-f", "-", "-o", "json", payload=json.dumps(resource))


def get_json(lab, namespace, *resource_args):
    raw = kubectl(lab, namespace, "get", *resource_args, "-o", "json").stdout
    return json.loads(raw), raw


SERVER = """from http.server import BaseHTTPRequestHandler, HTTPServer
from os import environ

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(environ["FIXTURE_NAME"].encode())

    def log_message(self, *_args):
        pass

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"""


def deployment(name, namespace, node_selector=None, tolerates_control_plane=False):
    labels = {LABEL: name, MARKER: "synthetic-maintenance"}
    pod_spec = {
        "automountServiceAccountToken": False,
        "terminationGracePeriodSeconds": 3,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 65532,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [{
            "name": "mock-http",
            "image": IMAGE,
            "imagePullPolicy": "IfNotPresent",
            "command": ["python", "-c", SERVER],
            "env": [{"name": "FIXTURE_NAME", "value": name}],
            "ports": [{"name": "http", "containerPort": 8080}],
            "readinessProbe": {"httpGet": {"path": "/", "port": "http"},
                               "periodSeconds": 2, "timeoutSeconds": 2},
            "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                          "limits": {"cpu": "250m", "memory": "96Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
        }],
    }
    if node_selector is not None:
        pod_spec["nodeSelector"] = node_selector
    if tolerates_control_plane:
        pod_spec["tolerations"] = [{"key": "node-role.kubernetes.io/control-plane",
                                    "operator": "Exists", "effect": "NoSchedule"}]
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace,
                     "labels": {MARKER: "synthetic-maintenance"}},
        "spec": {"replicas": 1, "selector": {"matchLabels": {LABEL: name}},
                 "template": {"metadata": {"labels": labels}, "spec": pod_spec}},
    }


def ready_pod(lab, namespace, name, target_node=None, timeout=100):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        items, _ = get_json(lab, namespace, "pods", "-l", f"{LABEL}={name}")
        for pod in items["items"]:
            if pod["metadata"].get("deletionTimestamp"):
                continue
            if target_node is not None and pod["spec"].get("nodeName") != target_node:
                continue
            if any(c["type"] == "Ready" and c["status"] == "True"
                   for c in pod["status"].get("conditions", [])):
                return pod
        time.sleep(0.5)
    raise InfrastructureError(f"Ready Pod not observed for {namespace}/{name}")


def route(lab, namespace, pod, destination, expected):
    address = destination["status"]["podIP"]
    host = f"[{address}]" if ":" in address else address
    source = """import sys
from urllib.error import URLError
from urllib.request import urlopen
try:
    with urlopen(sys.argv[1], timeout=2) as response:
        print(response.read().decode())
except URLError as error:
    if not isinstance(error.reason, (ConnectionRefusedError, TimeoutError)):
        raise
    print("blocked")
except TimeoutError:
    print("blocked")
"""
    result = kubectl(lab, namespace, "exec", f"pod/{pod['metadata']['name']}", "--",
                     "python", "-c", source, f"http://{host}:8080/", timeout=12)
    text = result.stdout.strip()
    if text not in {expected, "blocked"}:
        lab.block("The fixed HTTP probe returned an unexpected fixture marker")
    return text


def run(lab):
    for namespace in (MAINT_NS, INDEP_NS):
        cluster_kubectl(lab, "create", "namespace", namespace)

    nodes, _ = get_json(lab, "default", "nodes")
    control_planes = [n["metadata"]["name"] for n in nodes["items"]
                      if "node-role.kubernetes.io/control-plane" in n["metadata"].get("labels", {})]
    workers = [n["metadata"]["name"] for n in nodes["items"]
               if "node-role.kubernetes.io/control-plane" not in n["metadata"].get("labels", {})]
    if len(control_planes) != 1 or len(workers) != 1:
        lab.block("Expected exactly one control-plane and one worker in the owned Kind cluster")
    control_plane, worker = control_planes[0], workers[0]
    if {control_plane, worker} != {f"{lab.cluster}-control-plane", f"{lab.cluster}-worker"}:
        lab.block("Node names do not match this run's disposable cluster")
    independent = deployment(INDEP_DEPLOY, INDEP_NS,
                             {"node-role.kubernetes.io/control-plane": ""}, tolerates_control_plane=True)
    apply(lab, INDEP_NS, independent)
    apply(lab, INDEP_NS, deployment(PROBE_DEPLOY, INDEP_NS,
                                   {"node-role.kubernetes.io/control-plane": ""},
                                   tolerates_control_plane=True))
    unaffected_before = ready_pod(lab, INDEP_NS, INDEP_DEPLOY, control_plane)
    probe_pod = ready_pod(lab, INDEP_NS, PROBE_DEPLOY, control_plane)

    # The owned temporary taint drives initial placement without rolling the Deployment.
    cluster_kubectl(lab, "taint", "node", control_plane, f"{PLACEMENT_TAINT}=worker-first:NoSchedule")
    apply(lab, MAINT_NS, deployment(MAINT_DEPLOY, MAINT_NS, tolerates_control_plane=True))
    target_before = ready_pod(lab, MAINT_NS, MAINT_DEPLOY, worker)
    cluster_kubectl(lab, "taint", "node", control_plane, f"{PLACEMENT_TAINT}:NoSchedule-")
    target_dep_before, _ = get_json(lab, MAINT_NS, f"deployment/{MAINT_DEPLOY}")
    pods_on_worker, _ = get_json(lab, MAINT_NS, "pods", "--field-selector", f"spec.nodeName={worker}",
                                "-l", f"{LABEL}={MAINT_DEPLOY}")
    if {pod["metadata"]["uid"] for pod in pods_on_worker["items"]} != {target_before["metadata"]["uid"]}:
        lab.block("Drain selector does not resolve to exactly one owned maintenance Pod")

    initial_ingress = route(lab, INDEP_NS, unaffected_before, target_before, MAINT_DEPLOY)
    initial_egress = route(lab, MAINT_NS, target_before, unaffected_before, INDEP_DEPLOY)
    unaffected_initial = route(lab, INDEP_NS, probe_pod, unaffected_before, INDEP_DEPLOY)
    lab.check("red", "Before containment the maintenance mock is reachable in both directions",
              initial_ingress == MAINT_DEPLOY and initial_egress == INDEP_DEPLOY
              and unaffected_initial == INDEP_DEPLOY,
              {"ingress": initial_ingress, "egress": initial_egress,
               "maintenance_on_worker": target_before["spec"]["nodeName"] == worker,
               "independent_http": unaffected_initial})

    drain = cluster_kubectl(lab, "drain", worker, "--ignore-daemonsets",
                            f"--pod-selector={LABEL}={MAINT_DEPLOY}", "--timeout=90s", timeout=105)
    target_after = ready_pod(lab, MAINT_NS, MAINT_DEPLOY, control_plane)
    nodes_after, _ = get_json(lab, "default", "nodes")
    target_dep_after, _ = get_json(lab, MAINT_NS, f"deployment/{MAINT_DEPLOY}")
    worker_cordoned = next(n for n in nodes_after["items"] if n["metadata"]["name"] == worker)["spec"].get("unschedulable") is True
    control_plane_cordoned = next(n for n in nodes_after["items"] if n["metadata"]["name"] == control_plane)["spec"].get("unschedulable", False)
    old_uid_replaced = target_after["metadata"]["uid"] != target_before["metadata"]["uid"]
    same_generation = target_dep_after["metadata"]["generation"] == target_dep_before["metadata"]["generation"]
    unaffected_after_drain = route(lab, INDEP_NS, probe_pod, unaffected_before, INDEP_DEPLOY)
    lab.check("green", "The scoped drain cordons only the worker and replaces its mock on the other node",
              worker_cordoned and not control_plane_cordoned and old_uid_replaced and same_generation
              and unaffected_after_drain == INDEP_DEPLOY,
              {"worker_cordoned": worker_cordoned, "control_plane_cordoned": control_plane_cordoned,
               "replacement_on_control_plane": target_after["spec"]["nodeName"] == control_plane,
               "pod_uid_changed": old_uid_replaced, "deployment_generation_unchanged": same_generation,
               "independent_http": unaffected_after_drain})

    ingress = route(lab, INDEP_NS, unaffected_before, target_after, MAINT_DEPLOY)
    egress = route(lab, MAINT_NS, target_after, unaffected_before, INDEP_DEPLOY)
    lab.check("red", "After rescheduling both directions still carry the exact fixture markers",
              ingress == MAINT_DEPLOY and egress == INDEP_DEPLOY, {"ingress": ingress, "egress": egress})

    policy_spec = {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
    apply(lab, MAINT_NS, {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                         "metadata": {"name": "default-deny-all", "namespace": MAINT_NS},
                         "spec": policy_spec})
    policy, _ = get_json(lab, MAINT_NS, "networkpolicy/default-deny-all")
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        blocked_ingress = route(lab, INDEP_NS, unaffected_before, target_after, MAINT_DEPLOY)
        blocked_egress = route(lab, MAINT_NS, target_after, unaffected_before, INDEP_DEPLOY)
        if blocked_ingress == blocked_egress == "blocked":
            break
        time.sleep(0.5)
    still_ready = ready_pod(lab, MAINT_NS, MAINT_DEPLOY, control_plane)
    same_isolated_pod = still_ready["metadata"]["uid"] == target_after["metadata"]["uid"]
    unaffected_after_policy = route(lab, INDEP_NS, probe_pod, unaffected_before, INDEP_DEPLOY)
    lab.check("green", "Namespace default-deny blocks both paths while both mock Pods stay Ready",
              policy["spec"] == policy_spec and blocked_ingress == blocked_egress == "blocked"
              and same_isolated_pod and unaffected_after_policy == INDEP_DEPLOY,
              {"policy_namespace": policy["metadata"]["namespace"], "ingress": blocked_ingress,
               "egress": blocked_egress, "same_isolated_pod_ready": same_isolated_pod,
               "independent_http": unaffected_after_policy})

    kubectl(lab, MAINT_NS, "scale", f"deployment/{MAINT_DEPLOY}", "--replicas=0")
    kubectl(lab, MAINT_NS, "wait", "--for=delete", f"pod/{target_after['metadata']['name']}",
            "--timeout=60s", timeout=70)
    target_dep_final, _ = get_json(lab, MAINT_NS, f"deployment/{MAINT_DEPLOY}")
    target_pods_final, _ = get_json(lab, MAINT_NS, "pods", "-l", f"{LABEL}={MAINT_DEPLOY}")
    target_retained = target_dep_final["metadata"]["uid"] == target_dep_before["metadata"]["uid"]
    lab.check("green", "Scaling to zero removes the mock Pod and retains its Deployment",
              target_retained and target_dep_final["spec"]["replicas"] == 0 and not target_pods_final["items"],
              {"deployment_retained": target_retained, "desired_replicas": target_dep_final["spec"]["replicas"],
               "matching_pods": len(target_pods_final["items"])})

    unaffected_final = ready_pod(lab, INDEP_NS, INDEP_DEPLOY, control_plane)
    same_pod = unaffected_final["metadata"]["uid"] == unaffected_before["metadata"]["uid"]
    no_restart = unaffected_final["status"]["containerStatuses"][0]["restartCount"] == 0
    final_http = route(lab, INDEP_NS, probe_pod, unaffected_final, INDEP_DEPLOY)
    lab.check("positive", "The same independent Pod stayed Ready and returned its marker at all checkpoints",
              same_pod and no_restart and final_http == INDEP_DEPLOY,
              {"same_pod": same_pod, "no_restart": no_restart, "final_http": final_http})

    save_raw(lab, "containment-observations.raw.json", json.dumps({
        "nodes_before": nodes, "nodes_after": nodes_after, "drain": drain.stdout + drain.stderr,
        "target_pod_before": target_before, "target_pod_after_drain": target_after,
        "target_pod_after_policy": still_ready, "target_deployment_after_scale": target_dep_final,
        "independent_pod_before": unaffected_before, "independent_pod_after": unaffected_final,
        "policy": policy, "checks": lab.checks,
    }, indent=2))
