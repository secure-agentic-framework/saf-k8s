"""Prove an HPA maxReplicas cap under sustained synthetic CPU demand."""
import json
from hashlib import sha256
from pathlib import Path
import subprocess
import time

from fixtures import BUSYBOX_IMAGE


METRICS_SERVER_VERSION = "v0.9.1"
METRICS_SERVER_MANIFEST_SHA256 = "3c7f57cdbee0f57fb0259a150e8f6d6cb4f29d72d1aa5dce8803151dd6d4c2a1"
METRICS_SERVER_MANIFEST = (
    "https://github.com/kubernetes-sigs/metrics-server/releases/download/"
    f"{METRICS_SERVER_VERSION}/components.yaml"
)
METRICS_SERVER_IMAGE = f"registry.k8s.io/metrics-server/metrics-server:{METRICS_SERVER_VERSION}"
METRICS_SERVER_DIGEST = "9b0ba1926e1d3089673f45461c3c1416109dea33b3ba3434048defd380df329b"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
SERVING_CERT_DIR = "/etc/kubernetes/saf-hpa-tls"
DEPLOYMENT = "saf-0703-014-ai-worker"
HPA = "saf-0703-014-ai-worker"
CAP = 2
PERMISSIVE_MAX = 4
SCOPE = (
    "Kubernetes v1.36.1 on a disposable kind cluster. A benign BusyBox container "
    "uses a bounded 100m CPU limit and 25m request to generate deterministic local "
    "resource metrics through Metrics Server v0.9.1. The case demonstrates that an "
    "autoscaling/v2 HPA can scale above a chosen replica threshold when maxReplicas "
    "is permissive, and that lowering maxReplicas limits its Deployment target under "
    "the same demand. It creates no GPU or provider resources and makes no cloud bill, "
    "spend-ceiling, billing-alert, node-group or node-autoscaler claim. Metrics Server "
    "authenticates the fixture kubelet against a locally issued serving certificate."
)


def openssl(lab, *args):
    result = subprocess.run(["openssl", *map(str, args)], capture_output=True, timeout=25)
    if result.returncode:
        lab.block(f"Could not prepare the fixture serving certificate with openssl {args[0]}")


def prepare_kind(lab, temporary: Path) -> Path:
    serving = temporary / "serving"
    serving.mkdir(mode=0o700)
    root_key = temporary / "ca-key.pem"
    ca = serving / "ca.pem"
    extensions = temporary / "openssl.conf"
    node = f"{lab.cluster}-control-plane"
    extensions.write_text(
        "[req]\ndistinguished_name=dn\n[dn]\n"
        "[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
        "[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{node}\n"
    )
    openssl(lab, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-sha256", "-config", extensions, "-extensions", "ca",
            "-subj", "/CN=SAF Synthetic HPA Kubelet CA", "-keyout", root_key, "-out", ca)
    root_key.chmod(0o600)
    request = temporary / "node.csr"
    node_key = serving / "node-key.pem"
    openssl(lab, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-config", extensions,
            "-subj", f"/CN={node}", "-keyout", node_key, "-out", request)
    node_key.chmod(0o600)
    openssl(lab, "x509", "-req", "-in", request, "-CA", ca, "-CAkey", root_key,
            "-set_serial", "1", "-sha256", "-days", "1", "-extfile", extensions,
            "-extensions", "leaf", "-out", serving / "node.pem")
    root_key.unlink()
    kind_config = temporary / "kind.yaml"
    kind_config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
kubeadmConfigPatches:
- |
  apiVersion: kubelet.config.k8s.io/v1beta1
  kind: KubeletConfiguration
  serverTLSBootstrap: false
  tlsCertFile: {SERVING_CERT_DIR}/node.pem
  tlsPrivateKeyFile: {SERVING_CERT_DIR}/node-key.pem
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(serving))}
    containerPath: {SERVING_CERT_DIR}
    readOnly: true
""")
    return kind_config


def get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def condition(obj, kind):
    return next((row for row in (obj.get("status", {}).get("conditions") or [])
                 if row.get("type") == kind), {})


def current_cpu_utilization(hpa):
    for metric in (hpa.get("status", {}).get("currentMetrics") or []):
        resource = metric.get("resource", {})
        if resource.get("name") == "cpu":
            return resource.get("current", {}).get("averageUtilization")
    return None


def wait_for(lab, predicate, description, timeout=210):
    deadline = time.monotonic() + timeout
    latest = None
    while time.monotonic() < deadline:
        latest = get_json(lab, "get", "hpa", HPA)
        deployment = get_json(lab, "get", "deployment", DEPLOYMENT)
        if predicate(latest, deployment):
            return latest, deployment
        time.sleep(2)
    lab.block(f"Timed out waiting for {description}; hpa={latest}")


def install_metrics_server(lab):
    manifest = lab.kubeconfig.parent / "metrics-server-components.yaml"
    lab.command("curl", "--fail", "--silent", "--show-error", "--location", "--max-time", "90",
                METRICS_SERVER_MANIFEST, "-o", str(manifest), timeout=100)
    contents = manifest.read_text(encoding="utf-8")
    if sha256(contents.encode("utf-8")).hexdigest() != METRICS_SERVER_MANIFEST_SHA256:
        lab.block("Metrics Server release manifest failed its published SHA-256")
    if contents.count(METRICS_SERVER_IMAGE) != 1:
        lab.block("Metrics Server release manifest did not contain the expected single versioned image")
    manifest.write_text(contents.replace(
        METRICS_SERVER_IMAGE, f"{METRICS_SERVER_IMAGE}@sha256:{METRICS_SERVER_DIGEST}",
    ))
    node = f"{lab.cluster}-control-plane"
    ipv4 = next(address["address"] for address in get_json(lab, "get", "node", node)["status"]["addresses"]
                if address["type"] == "InternalIP" and ":" not in address["address"])
    ca = lab.kubeconfig.parent / "serving" / "ca.pem"
    lab.kubectl("-n", "kube-system", "create", "configmap", "saf-hpa-kubelet-ca", f"--from-file=ca.crt={ca}")
    kubectl = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}"]
    lab.command(*kubectl, "apply", "--server-side", "-f", str(manifest), timeout=90)
    adapter = get_json(lab, "-n", "kube-system", "get", "deployment", "metrics-server")
    pod = adapter["spec"]["template"]["spec"]
    container = pod["containers"][0]
    args = [arg for arg in container["args"] if not arg.startswith("--kubelet-preferred-address-types")]
    args.extend(("--kubelet-preferred-address-types=Hostname",
                 "--kubelet-certificate-authority=/saf-ca/ca.crt"))
    patch = {"spec": {"template": {"spec": {
        "hostAliases": [{"ip": ipv4, "hostnames": [node]}],
        "volumes": [{"name": "saf-kubelet-ca", "configMap": {"name": "saf-hpa-kubelet-ca"}}],
        "containers": [{"name": "metrics-server", "args": args,
                        "volumeMounts": [{"name": "saf-kubelet-ca", "mountPath": "/saf-ca", "readOnly": True}]}],
    }}}}
    lab.kubectl("-n", "kube-system", "patch", "deployment", "metrics-server", "--type=strategic",
                "-p", json.dumps(patch))
    lab.kubectl("-n", "kube-system", "wait", "--for=condition=Available",
                "deployment/metrics-server", "--timeout=120s", timeout=125)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "--raw", "/apis/metrics.k8s.io/v1beta1/nodes",
                             allow_failure=True)
        if result.returncode == 0:
            return
        time.sleep(2)
    lab.block("Metrics Server did not serve the resource Metrics API")


def workload():
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": DEPLOYMENT, "labels": {"app": DEPLOYMENT}},
        "spec": {
            "selector": {"matchLabels": {"app": DEPLOYMENT}},
            "template": {
                "metadata": {"labels": {"app": DEPLOYMENT}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [{
                        "name": "bounded-cpu-fixture", "image": BUSYBOX_IMAGE,
                        "command": ["sh", "-c", "while true; do :; done"],
                        "resources": {
                            "requests": {"cpu": "25m", "memory": "16Mi"},
                            "limits": {"cpu": "100m", "memory": "32Mi"},
                        },
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                    }],
                },
            },
        },
    }


def hpa(maximum):
    return {
        "apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler",
        "metadata": {"name": HPA},
        "spec": {
            "scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": DEPLOYMENT},
            "minReplicas": 1, "maxReplicas": maximum,
            "metrics": [{"type": "Resource", "resource": {
                "name": "cpu", "target": {"type": "Utilization", "averageUtilization": 50},
            }}],
            "behavior": {
                "scaleUp": {"stabilizationWindowSeconds": 0,
                            "policies": [{"type": "Pods", "value": 4, "periodSeconds": 15}]},
                "scaleDown": {"stabilizationWindowSeconds": 0,
                              "policies": [{"type": "Pods", "value": 4, "periodSeconds": 15}]},
            },
        },
    }


def ready_replicas(deployment):
    status = deployment.get("status", {})
    return status.get("readyReplicas", 0) or 0


def run(lab):
    install_metrics_server(lab)
    app = workload()
    lab.create(app)
    lab.kubectl("wait", "--for=condition=Available", f"deployment/{DEPLOYMENT}",
                "--timeout=90s", timeout=95)
    lab.create(hpa(PERMISSIVE_MAX))

    # Red: sustained load causes real resource-metric HPA recommendations and
    # Deployment replicas to cross the policy threshold while maxReplicas is 4.
    red_hpa, red_deployment = wait_for(
        lab,
        lambda autoscaler, target: autoscaler.get("status", {}).get("desiredReplicas") == PERMISSIVE_MAX
        and target.get("status", {}).get("replicas") == PERMISSIVE_MAX
        and ready_replicas(target) == PERMISSIVE_MAX
        and (current_cpu_utilization(autoscaler) or 0) > 50,
        "permissive HPA to scale above the selected two-replica safety threshold",
    )
    lab.check(
        "red", "With maxReplicas=4, measured CPU demand scales beyond the two-replica threshold",
        red_hpa["status"].get("desiredReplicas", 0) > CAP
        and red_deployment.get("status", {}).get("replicas", 0) > CAP
        and ready_replicas(red_deployment) > CAP,
        {"max_replicas": PERMISSIVE_MAX,
         "desired_replicas": red_hpa["status"].get("desiredReplicas"),
         "observed_replicas": red_deployment.get("status", {}).get("replicas"),
         "ready_replicas": ready_replicas(red_deployment),
         "cpu_utilization_above_target": (current_cpu_utilization(red_hpa) or 0) > 50},
    )

    lab.kubectl("patch", "hpa", HPA, "--type=merge", "-p", json.dumps({"spec": {"maxReplicas": CAP}}))
    green_hpa, green_deployment = wait_for(
        lab,
        lambda autoscaler, target: autoscaler.get("spec", {}).get("maxReplicas") == CAP
        and autoscaler.get("status", {}).get("desiredReplicas") == CAP
        and target.get("status", {}).get("replicas") == CAP
        and ready_replicas(target) == CAP
        and (current_cpu_utilization(autoscaler) or 0) > 50,
        "the Deployment to converge to the two-replica cap under continued demand",
    )
    limited = condition(green_hpa, "ScalingLimited")
    lab.check(
        "green", "Lowered maxReplicas holds desired and ready Deployment replicas at two under load",
        green_hpa.get("spec", {}).get("maxReplicas") == CAP
        and green_hpa.get("status", {}).get("desiredReplicas") == CAP
        and green_deployment.get("status", {}).get("replicas") == CAP
        and ready_replicas(green_deployment) == CAP,
        {"max_replicas": green_hpa.get("spec", {}).get("maxReplicas"),
         "desired_replicas": green_hpa.get("status", {}).get("desiredReplicas"),
         "observed_replicas": green_deployment.get("status", {}).get("replicas"),
         "ready_replicas": ready_replicas(green_deployment),
         "cpu_utilization_above_target": (current_cpu_utilization(green_hpa) or 0) > 50,
         "scaling_limited": limited.get("status"), "scaling_limited_reason": limited.get("reason")},
    )

    lab.check(
        "positive", "Both capped replicas remain Ready while CPU demand remains measurable",
        ready_replicas(green_deployment) == CAP
        and (current_cpu_utilization(green_hpa) or 0) > 50,
        {"ready_replicas": ready_replicas(green_deployment),
         "cpu_utilization_above_target": (current_cpu_utilization(green_hpa) or 0) > 50,
         "target_utilization_percent": 50},
    )
