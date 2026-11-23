"""Verify ClusterIP service defaults, admission and endpoint NetworkPolicy."""
import hashlib
import json
from pathlib import Path
import time


CILIUM_CHART = "oci://quay.io/cilium/charts/cilium"
CILIUM_VERSION = "1.20.5"
CILIUM_AGENT = "quay.io/cilium/cilium:v1.20.5@sha256:aa72499f075ad729947ea91b026218aceba24f1a8e4534bf36b8368c7c561526"
CILIUM_OPERATOR_GENERIC = "quay.io/cilium/operator-generic:v1.20.5@sha256:c6e7de6665aa9701db86c4fe46828a75a0d167afe084a9ffb5bce34b2c4fa8c4"
CILIUM_ENVOY = "quay.io/cilium/cilium-envoy:v1.39.6-1794557904-dee711ff0e84b106edd0abcdd71961af1b870359@sha256:bdef13043ebaa7b9dcd8e3a86be41080bb5369e017cd759a12daf89e2b8fafe7"
HERE = Path(__file__).resolve().parent
CHART_SHA = "0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21"

def _install_cilium(lab):
    work = lab.kubeconfig.parent
    registry = work / "helm-registry.json"
    lab.command("helm", "pull", CILIUM_CHART, "--version", CILIUM_VERSION,
                "--destination", str(work), "--registry-config", str(registry), timeout=100)
    chart = work / f"cilium-{CILIUM_VERSION}.tgz"
    if hashlib.sha256(chart.read_bytes()).hexdigest() != CHART_SHA:
        lab.block("The downloaded Cilium chart differs from the pinned artifact")
    lab.command("helm", "install", "cilium", str(chart),
        "--namespace", "kube-system",
        "--kubeconfig", str(lab.kubeconfig),
        "--kube-context", f"kind-{lab.cluster}",
        "-f", str(HERE / "cilium-values.yaml"),
        "--wait", "--timeout", "4m",
        timeout=260,
    )


def _node_ready(lab):
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}"]
    for resource in ("daemonset/cilium", "daemonset/cilium-envoy", "deployment/cilium-operator"):
        lab.command(*args, "-n", "kube-system", "rollout", "status", resource,
                    "--timeout=80s", timeout=90)
    state = json.loads(lab.command(*args, "-n", "kube-system", "get", "pods", "-o", "json").stdout)
    ready_images = set()
    for pod in state["items"]:
        ready = {container["name"] for container in pod.get("status", {}).get("containerStatuses", [])
                 if container["ready"]}
        ready_images.update(container["image"] for container in pod["spec"]["containers"]
                            if container["name"] in ready)
    observed = {image.split("@")[0]: image in ready_images
                for image in (CILIUM_AGENT, CILIUM_ENVOY, CILIUM_OPERATOR_GENERIC)}
    lab.check("positive", "The pinned Cilium agent, operator and Envoy are ready",
              all(observed.values()), observed)



SCOPE = (
    "One fresh Kubernetes v1.36.1 cluster with pinned Cilium 1.20.5. Inspect the API default, "
    "selector-backed headless DNS, and an explicit admission policy requiring ClusterIP for "
    "services in the owned namespace. An ingress NetworkPolicy protects the selected endpoint "
    "on TCP/8080. Both internal clients reach both service types and the pod IP before policy. "
    "The unselected client times out on all three routes after policy while the selected "
    "client still reaches the marker on each. Production inventory and exceptions remain open."
)
TARGET = "saf0505003-server"
ALLOWED = "saf0505003-allowed"
OTHER = "saf0505003-denied"
NORMAL = "saf0505003-default"
HEADLESS = "saf0505003-headless"
MARKER = "saf0505003-fixture-ok"
ADMISSION_MESSAGE = "Owned internal Services must have ClusterIP type"


def request(lab, identity, host):
    script = (HERE / "probe.py").read_text()
    result = lab.kubectl("exec", identity, "--", "python", "-c", script, host,
                         timeout=10, allow_failure=True)
    if result.returncode:
        lab.block(f"The owned {identity} probe did not return a transport result")
    return json.loads(result.stdout)


def service(lab, name, service_type=None):
    spec = {"ports": [{"port": 8080}]}
    if service_type:
        spec["type"] = service_type
    return lab.kubectl("create", "--dry-run=server", "-f", "-", "-o", "json",
                       payload=json.dumps({"apiVersion": "v1", "kind": "Service",
                                           "metadata": {"name": name}, "spec": spec}),
                       allow_failure=True)


def state(lab, label, **kwargs):
    return json.loads(lab.kubectl(*label, "-o", "json", **kwargs).stdout)


def run(lab):
    _install_cilium(lab)
    _node_ready(lab)
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}"]
    lab.command(*args, "-n", "kube-system", "rollout", "restart", "deployment/coredns")
    lab.command(*args, "-n", "kube-system", "rollout", "status", "deployment/coredns",
                "--timeout=75s", timeout=85)
    lab.apply(HERE / "fixtures.yaml")
    lab.kubectl("wait", "--for=condition=Ready", *(f"pod/{pod}" for pod in (TARGET, ALLOWED, OTHER)),
                "--timeout=95s", timeout=105)

    normal = state(lab, ("get", "service", NORMAL))["spec"]
    headless = state(lab, ("get", "service", HEADLESS))["spec"]
    pod_ip = state(lab, ("get", "pod", TARGET))["status"]["podIP"]
    slices = state(lab, ("get", "endpointslice", "-l", f"kubernetes.io/service-name={HEADLESS}"))
    slices_ips = {address for item in slices["items"] for endpoint in item["endpoints"]
                  if endpoint["conditions"].get("ready") for address in endpoint["addresses"]}
    dns = lab.kubectl("exec", ALLOWED, "--", "python", "-c",
                      "import json,socket,sys; print(json.dumps(socket.gethostbyname_ex(sys.argv[1])[2]))",
                      f"{HEADLESS}.saf-test.svc.cluster.local")
    asserted = {"default_type_cluster_ip": normal["type"] == "ClusterIP",
                "ordinary_service_has_virtual_ip": normal["clusterIP"] not in ("None", pod_ip, ""),
                "headless_type_cluster_ip": headless["type"] == "ClusterIP",
                "headless_has_no_virtual_ip": headless["clusterIP"] == "None",
                "headless_dns_matches_only_ready_endpoint": set(json.loads(dns.stdout)) == slices_ips == {pod_ip}}
    lab.check("positive", "The API defaults type and headless DNS returns the Ready Pod address",
              all(asserted.values()), asserted)

    paths = {"ClusterIP": NORMAL, "headless DNS": HEADLESS, "direct pod IP": pod_ip}
    expected = {"transport": "http", "status": 200, "body": MARKER}
    for identity in (ALLOWED, OTHER):
        for label, host in paths.items():
            before = request(lab, identity, host)
            lab.check("red", f"The {identity} fixture reaches the marker through {label} before policy",
                      before == expected, before)

    nodeport_before = service(lab, "internal-port-before", "NodePort")
    accepted = nodeport_before.returncode == 0 and json.loads(nodeport_before.stdout)["spec"]["type"] == "NodePort"
    lab.check("red", "The API accepts an explicit NodePort before internal-service admission policy",
              accepted, {"accepted_explicit_nodeport": accepted})
    lab.apply(HERE / "admission.yaml")
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        denied = service(lab, "internal-port-after", "NodePort")
        if denied.returncode and ADMISSION_MESSAGE in denied.stderr:
            break
        time.sleep(0.7)
    else:
        lab.block("The namespace admission policy did not become effective")
    lab.check("green", "The applied admission policy rejects explicit NodePort in the internal namespace",
              True, {"denied_nodeport_by_expected_rule": True})
    permitted = service(lab, "internal-default-after")
    allowed = permitted.returncode == 0 and json.loads(permitted.stdout)["spec"]["type"] == "ClusterIP"
    lab.check("positive", "The admission policy still permits an omitted Service type defaulted to ClusterIP",
              allowed, {"admitted_defaulted_cluster_ip": allowed})

    lab.apply(HERE / "policy.yaml")
    deadline = time.monotonic() + 35
    expired = {"transport": "connect_timeout"}
    while time.monotonic() < deadline:
        if request(lab, OTHER, pod_ip) == expired:
            break
        time.sleep(0.5)
    else:
        lab.block("Cilium did not show the expected NetworkPolicy data-plane convergence")

    verdicts = {}
    for label, host in paths.items():
        negative = request(lab, OTHER, host)
        positive = request(lab, ALLOWED, host)
        lab.check("green", f"The unselected client cannot connect through {label} after network policy",
                  negative == expired, negative)
        lab.check("positive", f"The selected client still receives the marker through {label}",
                  positive == expected, positive)
        verdicts[label] = {"unselected": negative, "selected": positive}

    (lab.evidence / "service-observations.json").write_text(
        json.dumps({"services": asserted, "admission": {"nodeport_accepted_before": accepted,
                    "nodeport_rejected_after": True, "clusterip_allowed_after": allowed},
                    "data_plane": verdicts}, indent=2, sort_keys=True) + "\n")
