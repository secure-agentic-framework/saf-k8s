"""Compare default and explicitly configured terminated-Pod garbage collection."""
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import time

from fixtures import container, pod


SCOPE = (
    "Case-owned kind clusters only: default kube-controller-manager behavior is "
    "compared with --terminated-pod-gc-threshold=2 using three inert pinned-image "
    "Pods that exit directly and one running benign control Pod. The assertion is "
    "count-based across two namespaces. The test checks fixture retention, while "
    "provider availability and production retention requirements depend on the deployment."
)

NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
THRESHOLD = 2
PODS = ("gc-success-old", "gc-failure-middle", "gc-success-new")
PHASES = dict(zip(PODS, ("Succeeded", "Failed", "Succeeded")))
EXTRA_NAMESPACE = "saf-podgc-extra"
LABEL = "saf-k8s-control=terminated-pod-gc"


def configured_kind_yaml():
    return (
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "kubeadmConfigPatches:\n"
        "  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    controllerManager:\n"
        "      extraArgs:\n"
        f"        - name: terminated-pod-gc-threshold\n          value: \"{THRESHOLD}\"\n"
    )


@contextmanager
def threshold_cluster(lab):
    cluster = f"{lab.cluster}-threshold"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Additional PodGC cluster already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix="saf-podgc-") as temp:
        kubeconfig = Path(temp) / "kubeconfig"
        config = Path(temp) / "kind.yaml"
        config.write_text(configured_kind_yaml())
        created = False
        try:
            created = True  # Also attempt cleanup after a partially failed create.
            lab.command(
                "kind", "create", "cluster", "--name", cluster,
                "--image", NODE_IMAGE, "--config", str(config),
                "--kubeconfig", str(kubeconfig), "--wait", "90s",
                timeout=480,
            )
            yield kubeconfig, cluster
        finally:
            if created:
                result = lab.command(
                    "kind", "delete", "cluster", "--name", cluster,
                    "--kubeconfig", str(kubeconfig), timeout=90, allow_failure=True,
                )
                if result.returncode:
                    lab.block(f"Could not confirm cleanup of PodGC cluster {cluster}")


def kubectl(lab, kubeconfig, cluster, *args, timeout=45, payload=None):
    return lab.command(
        "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
        "--namespace", "saf-test", f"--request-timeout={timeout - 5}s", *args,
        timeout=timeout, payload=payload,
    )


def create_fixture(lab, kubeconfig, cluster, namespace_exists):
    if not namespace_exists:
        kubectl(lab, kubeconfig, cluster, "create", "namespace", "saf-test")
    kubectl(lab, kubeconfig, cluster, "create", "namespace", EXTRA_NAMESPACE)
    pod_specs = (
        (PODS[0], "saf-test", "0"),
        (PODS[1], EXTRA_NAMESPACE, "17"),
        (PODS[2], EXTRA_NAMESPACE, "0"),
    )
    observed = {}
    for name, namespace, code in pod_specs:
        manifest = pod(name, [container("exit", command=["sh", "-c", f"exit {code}"])],
                       automountServiceAccountToken=False)
        key, value = LABEL.split("=", 1)
        manifest["metadata"].update(namespace=namespace, labels={key: value})
        kubectl(lab, kubeconfig, cluster, "-n", namespace, "create", "-f", "-",
                payload=json.dumps(manifest))
        result = kubectl(lab, kubeconfig, cluster, "-n", namespace, "wait", f"pod/{name}",
                         f"--for=jsonpath={{.status.phase}}={PHASES[name]}",
                         "--timeout=120s", timeout=130)
        observed[name] = result.stdout.strip()
        # Kubernetes creation timestamps have one-second precision.
        time.sleep(1.05)

    running = pod("gc-running-control", [container("pause")], automountServiceAccountToken=False)
    kubectl(lab, kubeconfig, cluster, "create", "-f", "-", payload=json.dumps(running))
    kubectl(lab, kubeconfig, cluster, "wait", "--for=condition=Ready",
            "pod/gc-running-control", "--timeout=120s", timeout=130)
    return observed


def pod_rows(lab, kubeconfig, cluster):
    result = kubectl(lab, kubeconfig, cluster, "get", "pods", "--all-namespaces",
                     "--selector", LABEL, "-o", "json")
    return {item["metadata"]["name"]: item for item in json.loads(result.stdout)["items"]}


def wait_for_gc(lab, kubeconfig, cluster):
    deadline = time.monotonic() + 90
    rows = pod_rows(lab, kubeconfig, cluster)
    while PODS[0] in rows and time.monotonic() < deadline:
        time.sleep(2)
        rows = pod_rows(lab, kubeconfig, cluster)
    return rows


def terminal_summary(rows):
    return {
        name: {"phase": rows[name]["status"].get("phase"),
               "namespace": rows[name]["metadata"]["namespace"]}
        for name in PODS if name in rows
    }


def assert_running_control(lab, kubeconfig, cluster):
    result = kubectl(lab, kubeconfig, cluster, "get", "pod/gc-running-control", "-o", "json")
    status = json.loads(result.stdout)["status"]
    ok = status.get("phase") == "Running" and any(
        c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", []))
    lab.check("positive", "Running benign control remains Ready and accessible",
              ok, {"phase": status.get("phase")})


def run(lab):
    create_fixture(lab, lab.kubeconfig, lab.cluster, namespace_exists=True)
    baseline = pod_rows(lab, lab.kubeconfig, lab.cluster)
    phases_ok = all(baseline.get(name, {}).get("status", {}).get("phase") == phase
                    for name, phase in PHASES.items())
    lab.check("red", "Default cluster retains all exact terminal outcomes",
              phases_ok and all(name in baseline for name in PODS),
              terminal_summary(baseline))
    assert_running_control(lab, lab.kubeconfig, lab.cluster)

    with threshold_cluster(lab) as (kubeconfig, cluster):
        controller = json.loads(kubectl(lab, kubeconfig, cluster, "-n", "kube-system",
                                       "get", f"pod/kube-controller-manager-{cluster}-control-plane",
                                       "-o", "json").stdout)
        expected_flag = f"--terminated-pod-gc-threshold={THRESHOLD}"
        argv = controller["spec"]["containers"][0]["command"]
        lab.check("green", "The running controller has the configured cluster-wide threshold",
                  expected_flag in argv, expected_flag if expected_flag in argv else "flag absent")
        observed = create_fixture(lab, kubeconfig, cluster, namespace_exists=False)
        lab.check("green", "Configured cluster observes the same three terminal Pod states",
                  all(f"pod/{name} condition met" == observed[name] for name in PODS), PHASES)
        rows = wait_for_gc(lab, kubeconfig, cluster)
        count = sum(name in rows and rows[name].get("status", {}).get("phase") in
                    ("Succeeded", "Failed") for name in PODS)
        oldest_gone = PODS[0] not in rows
        newest_retained = PODS[1] in rows and PODS[2] in rows
        retained_exact = (
            rows.get(PODS[1], {}).get("status", {}).get("phase") == "Failed"
            and rows.get(PODS[2], {}).get("status", {}).get("phase") == "Succeeded"
        )
        lab.check(
            "green", "Older terminal Pod is collected and retained terminal count equals threshold",
            oldest_gone and newest_retained and retained_exact and count == THRESHOLD,
            {"terminal_fixture_count": count, "threshold": THRESHOLD,
             "oldest_present": not oldest_gone, "retained_exact": retained_exact,
             "retained": terminal_summary(rows)},
        )
        assert_running_control(lab, kubeconfig, cluster)

    retained = pod_rows(lab, lab.kubeconfig, lab.cluster)
    lab.check("red", "The default profile still retains all terminal Pods after the tuned comparison",
              terminal_summary(retained) == terminal_summary(baseline), terminal_summary(retained))
