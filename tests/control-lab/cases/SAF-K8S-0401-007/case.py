"""Verify separated GPU-like quota, PriorityClass, and telemetry RBAC."""
import json
from pathlib import Path

from fixtures import BUSYBOX_IMAGE, container, pod


HERE = Path(__file__).parent
NAMESPACE = "saf-0401-007"
SCOPE = (
    "Kubernetes v1.36.1 synthetic ServiceAccount tests for a namespaced GPU-like quota dry-run "
    "increase, an exact named PriorityClass metadata dry run, and an actual test-owned HTTP "
    "metrics marker through the Service proxy. Isolated fixture roles preserve ownership of "
    "each distinct action. Actual GPU allocation, workload priority assignment, provider "
    "and group governance, and production metrics pipeline authorization remain separate."
)
PODS = {
    "workload": "saf-0401-007-workload-probe",
    "quota": "saf-0401-007-quota-probe",
    "priority": "saf-0401-007-priority-probe",
    "monitor": "saf-0401-007-monitor-probe",
    "independent": "saf-0401-007-independent-check-probe",
}
OPERATIONS = ("quota-dry-run-patch", "priorityclass-dry-run-patch",
             "synthetic-metrics-read")
EXPECTED = {
    "workload": {operation: 403 for operation in OPERATIONS},
    "quota": {OPERATIONS[0]: 200, OPERATIONS[1]: 403, OPERATIONS[2]: 403},
    "priority": {OPERATIONS[0]: 403, OPERATIONS[1]: 200, OPERATIONS[2]: 403},
    "monitor": {OPERATIONS[0]: 403, OPERATIONS[1]: 403, OPERATIONS[2]: 200},
    "independent": {operation: 200 for operation in OPERATIONS},
}
SERVICE_ACCOUNTS = {
    "workload": "saf-0401-007-workload",
    "quota": "saf-0401-007-quota-admin",
    "priority": "saf-0401-007-priority-admin",
    "monitor": "saf-0401-007-monitor",
    "independent": "saf-0401-007-independent-check",
}


def run_probe_pods(lab, phase):
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "probes.yaml"))
    observed = {}
    for function, pod in PODS.items():
        lab.kubectl("-n", NAMESPACE, "wait", "--for=jsonpath={.status.phase}=Succeeded",
                    f"pod/{pod}", "--timeout=90s", timeout=100)
        lines = lab.kubectl("-n", NAMESPACE, "logs", pod).stdout.splitlines()
        records = [json.loads(line) for line in lines if line.strip()]
        identity = next((record.get("subject") for record in records
                         if record.get("probe") == "projected-service-account-identity"), None)
        decisions = {entry["probe"]: {"status": entry["status"],
                                      "metric_marker": entry["metric_marker"],
                                      "quota_raised_in_dry_run": entry["quota_raised_in_dry_run"]}
                     for entry in records if entry.get("probe") in OPERATIONS}
        expected_identity = f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNTS[function]}"
        observed[function] = {"identity": identity, "expected_identity": expected_identity,
                              "decisions": decisions}
    lab.check(
        "positive", f"{phase}: each probe request uses its actual projected ServiceAccount token",
        all(observed[name]["identity"] == observed[name]["expected_identity"]
            and set(observed[name]["decisions"]) == set(OPERATIONS) for name in PODS),
        observed,
    )
    return observed


def assert_decisions(lab, observed, phase):
    expected = (
        {name: {operation: 403 for operation in OPERATIONS} for name in PODS}
        if phase == "before binding" else EXPECTED
    )
    matches = {
        name: {operation: observed[name]["decisions"].get(operation, {}).get("status") == status
               for operation, status in expected[name].items()}
        for name in PODS
    }
    lab.check(
        "red" if phase == "before binding" else "green",
        f"{phase}: quota, PriorityClass, and synthetic monitoring read permissions stay separate",
        all(all(result.values()) for result in matches.values()),
        {"matches": matches, "observed": observed},
    )


def run(lab):
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "fixtures.yaml"))
    install_metrics_fixture(lab)
    baseline = run_probe_pods(lab, "before binding")
    assert_decisions(lab, baseline, "before binding")

    # Pods are one-shot. Recreate them after binding to keep the same projected
    # identities while taking a new set of authorization decisions.
    lab.kubectl("-n", NAMESPACE, "delete", "-f", str(HERE / "probes.yaml"))
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "roles-and-bindings.yaml"))
    green = run_probe_pods(lab, "after binding")
    assert_decisions(lab, green, "after binding")
    observed_marker = {name: value["decisions"][OPERATIONS[2]]["metric_marker"] for name, value in green.items()}
    expected = {name: name in ("monitor", "independent") for name in PODS}
    lab.check("positive", "Only the approved identities retrieve the exact served metrics marker",
              observed_marker == expected, {"metrics_marker_reached": observed_marker})
    raised = {name: value["decisions"][OPERATIONS[0]]["quota_raised_in_dry_run"] for name, value in green.items()}
    lab.check("positive", "Only approved identities stage the actual synthetic quota increase",
              raised == {name: name in ("quota", "independent") for name in PODS},
              {"quota_increase_staged": raised})

    quota = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "resourcequota", "saf-0401-007-gpu-quota", "-o", "json",
    ).stdout)
    priority = json.loads(lab.kubectl(
        "get", "priorityclass", "saf-0401-007-low", "-o", "json",
    ).stdout)
    quota_unchanged = (
        quota.get("spec", {}).get("hard", {}).get("requests.saf-k8s.example/gpu") == "2"
        and "saf-k8s.example/probe" not in quota.get("metadata", {}).get("annotations", {})
    )
    priority_unchanged = (
        priority.get("value") == 100
        and "saf-k8s.example/probe" not in priority.get("metadata", {}).get("annotations", {})
    )
    lab.check("positive", "Quota dry-run probes did not persist a quota mutation",
              quota_unchanged, {"unchanged": quota_unchanged})
    lab.check("positive", "PriorityClass dry-run probes did not persist a priority mutation",
              priority_unchanged, {"unchanged": priority_unchanged})



def install_metrics_fixture(lab):
    name = "saf-0401-007-gpu-metrics"
    selector = {"saf-k8s.example/fixture": name}
    spec = pod(name, [container("metrics", image=BUSYBOX_IMAGE, command=[
        "sh", "-ec",
        "printf 'saf_synthetic_gpu_utilization 42\\n' >/tmp/metrics; exec httpd -f -p 8080 -h /tmp",
    ])], automountServiceAccountToken=False)
    spec["metadata"]["labels"] = selector
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
               "spec": {"selector": selector, "ports": [{"port": 80, "targetPort": 8080}]}}
    for obj in (spec, service):
        lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(obj))
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=95s", timeout=105)
    path = f"/api/v1/namespaces/{NAMESPACE}/services/{name}/proxy/metrics"
    observed = lab.kubectl("get", "--raw", path).stdout.strip()
    lab.check("positive", "The API proxy reaches the intended live synthetic metrics endpoint",
              observed == "saf_synthetic_gpu_utilization 42", {"owned_metric_marker": observed == "saf_synthetic_gpu_utilization 42"})
