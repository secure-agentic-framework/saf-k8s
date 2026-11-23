"""Exercise a pinned Cilium Helm release and a reversible failed upgrade.

The harness owns the fresh Kind cluster. This case owns only its Helm release,
the marker namespace workloads, and bounded in-cluster HTTP requests.
"""
import hashlib
import json
from pathlib import Path
import time


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
KIND_VERSION = "kind v0.32.0"
KUBERNETES_VERSION = "v1.36.1"
CILIUM_VERSION = "1.20.5"
CHART_SOURCE = "oci://quay.io/cilium/charts/cilium"
CHART_SHA256 = "0c7592eb75179ecf46dd3ec22145916f0164c4401214ea15afb5b230b1d11a21"
AGENT_IMAGE = (
    "quay.io/cilium/cilium:v1.20.5@sha256:"
    "aa72499f075ad729947ea91b026218aceba24f1a8e4534bf36b8368c7c561526"
)
OPERATOR_IMAGE = (
    "quay.io/cilium/operator-generic:v1.20.5@sha256:"
    "c6e7de6665aa9701db86c4fe46828a75a0d167afe084a9ffb5bce34b2c4fa8c4"
)
RELEASE = "cilium"
NAMESPACE = "saf-test"
SERVER = "marker-server"
CLIENT = "marker-client"
SERVICE = "marker"
PORT = 18080
MARKER = "saf-0502-004-baseline-marker"
INSTALLS_CNI = True
SCOPE = (
    "One fresh harness-owned Kind v0.32.0 / Kubernetes v1.36.1 cluster, with "
    "Kind's default CNI disabled and Cilium 1.20.5 installed from the checked "
    "OCI chart archive. The case verifies the chart and Cilium agent/operator "
    "image pins, then checks one TCP marker request between two case-owned "
    "pods in the cluster. A deliberately invalid readiness-probe threshold is "
    "submitted through Helm with and without --atomic. The case requires API "
    "rejection for both attempts, a deployed rollback revision for the atomic trial, restored user "
    "values, and the same marker request afterward. This does not assess a "
    "production baseline, CVE status or patch timeliness, provider SLAs, RBAC "
    "process, PSA configuration, or production-scale availability."
)


def prepare_kind(_lab, temporary):
    profile = temporary / "kind.yaml"
    profile.write_bytes(Path(__file__).with_name("kind-profile.yaml").read_bytes())
    return profile


def _kubectl(lab, *args, timeout=60, allow_failure=False, payload=None):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", f"--request-timeout={timeout - 5}s", *args,
        payload=payload, timeout=timeout, allow_failure=allow_failure,
    )


def _helm(lab, *args, timeout=90, allow_failure=False):
    return lab.command(
        "helm", *args, "--kubeconfig", str(lab.kubeconfig),
        "--kube-context", f"kind-{lab.cluster}", timeout=timeout,
        allow_failure=allow_failure,
    )


def _json(result):
    return json.loads(result.stdout)


def _create(lab, resource):
    _kubectl(lab, "create", "-f", "-", payload=json.dumps(resource))


def _container(name, command):
    return {
        "name": name,
        "image": "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec",
        "command": command,
        "resources": {"requests": {"cpu": "5m", "memory": "8Mi"},
                      "limits": {"cpu": "75m", "memory": "24Mi"}},
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }


def _pod(name, command, labels):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": labels},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 1,
            "containers": [_container(name, command)],
        },
    }


def _prepare_workloads(lab):
    _create(lab, _pod(
        SERVER,
        ["sh", "-ec", f"mkdir -p /tmp/www; printf %s {MARKER} >/tmp/www/index.html; exec httpd -f -p {PORT} -h /tmp/www"],
        {"app": SERVER},
    ))
    _create(lab, _pod(CLIENT, ["sh", "-ec", "exec sleep 1800"], {"app": CLIENT}))
    _create(lab, {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": SERVICE, "namespace": NAMESPACE},
        "spec": {"selector": {"app": SERVER},
                 "ports": [{"name": "http", "port": PORT, "targetPort": PORT}]},
    })
    for name in (SERVER, CLIENT):
        _kubectl(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready",
                 f"pod/{name}", "--timeout=90s", timeout=100)


def marker_observation(returncode, stdout, marker=MARKER):
    """Pure evaluator shared by the executable case and deterministic checks."""
    return returncode == 0 and stdout.strip() == marker


def rollback_observation(upgrade_returncode, history, current_values, baseline_values):
    """Require Helm failure, a failed revision, a later deployed rollback, and values."""
    rows = sorted(history, key=lambda row: int(row["revision"]))
    failed_revisions = [int(row["revision"]) for row in rows if row["status"] == "failed"]
    deployed_revisions = [int(row["revision"]) for row in rows if row["status"] == "deployed"]
    rollback_follows_failure = bool(failed_revisions and deployed_revisions
                                    and max(deployed_revisions) > max(failed_revisions))
    return (upgrade_returncode != 0 and rollback_follows_failure
            and current_values == baseline_values)


def _marker_request(lab):
    result = _kubectl(
        lab, "-n", NAMESPACE, "exec", f"pod/{CLIENT}", "--", "wget", "-q",
        "-T", "3", "-O", "-", f"http://{SERVICE}:{PORT}/", timeout=15,
        allow_failure=True,
    )
    return marker_observation(result.returncode, result.stdout), {
        "returncode": result.returncode,
        "marker_received": result.stdout.strip() == MARKER,
    }


def _wait_for_marker(lab):
    deadline = time.monotonic() + 30
    while True:
        reachable, result = _marker_request(lab)
        if reachable or time.monotonic() >= deadline:
            return reachable, result
        time.sleep(1)


def _assert_images(lab):
    ds = _json(_kubectl(lab, "-n", "kube-system", "get", "daemonset/cilium", "-o", "json"))
    agent_images = [c["image"] for c in ds["spec"]["template"]["spec"]["containers"]
                    if c["name"] == "cilium-agent"]
    operator = _json(_kubectl(lab, "-n", "kube-system", "get", "deployment/cilium-operator", "-o", "json"))
    operator_images = [c["image"] for c in operator["spec"]["template"]["spec"]["containers"]]
    return agent_images == [AGENT_IMAGE] and OPERATOR_IMAGE in operator_images, {
        "agent_images": agent_images,
        "operator_images": operator_images,
    }


def _install(lab, chart, values):
    _helm(
        lab, "install", RELEASE, str(chart), "--namespace", "kube-system",
        "--values", str(values), "--wait", "--timeout", "4m",
        timeout=260,
    )
    _kubectl(lab, "wait", "--for=condition=Ready", "node", "--all",
             "--timeout=120s", timeout=135)


def _revision_and_values(lab):
    history = _json(_helm(lab, "history", RELEASE, "-n", "kube-system", "-o", "json"))
    values = _json(_helm(lab, "get", "values", RELEASE, "-n", "kube-system", "-o", "json"))
    return history, values


def _invalid_upgrade(lab, chart, *, atomic):
    settings = ["--atomic"] if atomic else []
    return _helm(
        lab, "upgrade", RELEASE, str(chart), "--namespace", "kube-system",
        "--reuse-values", "--set", "debug.enabled=true",
        "--set", "readinessProbe.failureThreshold=-1", "--skip-schema-validation",
        *settings, "--wait", "--timeout", "45s", timeout=100,
        allow_failure=True,
    )


def _invalid_probe(upgrade):
    diagnostic = (upgrade.stdout + upgrade.stderr).lower()
    return (upgrade.returncode != 0 and "readinessprobe.failurethreshold" in diagnostic
            and "invalid value" in diagnostic)


def _new_revision_statuses(history, revision):
    ordered = sorted(history, key=lambda row: int(row["revision"]))
    return [row["status"] for row in ordered if int(row["revision"]) > revision]


def run(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith(KIND_VERSION):
        lab.block(f"Expected {KIND_VERSION}, got {kind_version!r}")
    server_version = _json(_kubectl(lab, "version", "-o", "json"))
    actual_k8s = server_version.get("serverVersion", {}).get("gitVersion")
    if actual_k8s != KUBERNETES_VERSION:
        lab.block(f"Expected Kubernetes {KUBERNETES_VERSION}, got {actual_k8s!r}")

    work = Path(lab.kubeconfig).parent
    registry = work / "helm-registry.json"
    _helm(lab, "pull", CHART_SOURCE, "--version", CILIUM_VERSION,
          "--destination", str(work), "--registry-config", str(registry), timeout=120)
    chart = work / f"cilium-{CILIUM_VERSION}.tgz"
    chart_hash = hashlib.sha256(chart.read_bytes()).hexdigest()
    if chart_hash != CHART_SHA256:
        lab.block(f"Cilium chart digest mismatch: {chart_hash}")
    values = Path(__file__).with_name("cilium-values.yaml")
    _install(lab, chart, values)

    images_ok, images = _assert_images(lab)
    lab.check("positive", "Baseline Cilium agent and operator images match digest pins",
              images_ok, images)
    _prepare_workloads(lab)
    baseline_ok, baseline_result = _wait_for_marker(lab)
    lab.check("positive", "Baseline in-cluster marker service is reachable",
              baseline_ok, baseline_result)

    # A negative threshold survives API defaulting and produces a typed
    # Kubernetes validation error for both otherwise identical upgrades.
    before_history, baseline_values = _revision_and_values(lab)
    original_revision = max(int(row["revision"]) for row in before_history)
    plain_upgrade = _invalid_upgrade(lab, chart, atomic=False)
    plain_history, _ = _revision_and_values(lab)
    plain_new = _new_revision_statuses(plain_history, original_revision)
    lab.check("red", "A failed non-atomic upgrade has no automatic rollback revision",
              _invalid_probe(plain_upgrade) and plain_new == ["failed"],
              {"api_rejected_readiness_threshold": _invalid_probe(plain_upgrade),
               "new_revision_statuses": plain_new})

    _helm(lab, "rollback", RELEASE, str(original_revision), "-n", "kube-system",
          "--wait", "--timeout", "90s", timeout=110)
    restored_history, restored_baseline = _revision_and_values(lab)
    if restored_baseline != baseline_values:
        lab.block("Manual reset did not restore the approved baseline before the atomic trial")
    restored_revision = max(int(row["revision"]) for row in restored_history)

    failed_upgrade = _invalid_upgrade(lab, chart, atomic=True)
    after_history, restored_values = _revision_and_values(lab)
    statuses = _new_revision_statuses(after_history, restored_revision)
    lab.check("green", "The same invalid upgrade triggers atomic rollback to approved values",
              _invalid_probe(failed_upgrade) and statuses == ["failed", "deployed"]
              and rollback_observation(failed_upgrade.returncode, after_history,
                                       restored_values, baseline_values),
              {"api_rejected_readiness_threshold": _invalid_probe(failed_upgrade),
               "new_revision_statuses": statuses,
               "values_restored": restored_values == baseline_values})

    images_restored, restored_image_details = _assert_images(lab)
    lab.check("green", "Rollback restored the digest-pinned CNI workloads",
              images_restored, restored_image_details)
    green_ok, green_result = _wait_for_marker(lab)
    lab.check("green", "Post-rollback marker service remains reachable",
              green_ok, green_result)
