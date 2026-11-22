"""Check observed ServiceAccount defaults, workload identities and scoped RBAC."""
import json
from pathlib import Path
import time

from fixtures import pod, ready

SCOPE = (
    "Two synthetic application Pods and one defaulting control Pod in the runner's "
    "disposable Kubernetes v1.36.1 kind cluster. Tests the Pod default ServiceAccount, "
    "explicit per-workload ServiceAccount assignment, namespaced ConfigMap get permission, "
    "and cross-fixture denial by SelfSubjectAccessReview. Synthetic marker data only. "
    "Does not validate native X.509 identities, cloud workload identity federation, "
    "or cloud IAM authorization; the release review must assess those separately."
)
API_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
DEFAULT_POD = "workload-defaulting-control"
WORKLOADS = {
    "workload-alpha": ("saf-0402-019-alpha", "saf-0402-019-alpha-fixture", "alpha-marker"),
    "workload-beta": ("saf-0402-019-beta", "saf-0402-019-beta-fixture", "beta-marker"),
}


def api_pod(name, service_account=None):
    spec = {
        "automountServiceAccountToken": service_account is not None,
        "volumes": [{"name": "probe", "configMap": {"name": "saf-0402-019-probe"}}],
    }
    if service_account is not None:
        spec["serviceAccountName"] = service_account
    resource = pod(name, [{
        "name": "probe", "image": API_IMAGE,
        "command": ["python", "-c", "import time; time.sleep(3600)"],
        "volumeMounts": [{"name": "probe", "mountPath": "/fixture", "readOnly": True}],
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 65534,
                            "readOnlyRootFilesystem": True,
                            "seccompProfile": {"type": "RuntimeDefault"}},
    }], **spec)
    resource["metadata"].update(
        namespace=NAMESPACE,
        labels={"app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "saf-0402-019"},
        annotations={"saf-k8s.example/fixture": "synthetic-only"},
    )
    return resource


def observed_service_account(lab, name):
    return lab.kubectl(
        "get", "pod", name, "-o", "jsonpath={.spec.serviceAccountName}"
    ).stdout.strip()


def probe(lab, pod_name, mode, configmap, *details):
    return lab.kubectl("exec", pod_name, "--", "python", "/fixture/probe.py",
                       mode, configmap, *details).stdout.strip()


def wait_for_binding(lab, pod_name, configmap):
    end = time.monotonic() + 20
    while True:
        decision = probe(lab, pod_name, "review", configmap)
        if decision != "201 denied" or time.monotonic() >= end:
            return decision
        time.sleep(0.5)


def run(lab):
    case_dir = Path(__file__).parent
    server = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]
    server_version = server.get("gitVersion", "")
    lab.check("positive", "Case is running against Kubernetes v1.36.1",
              server_version == "v1.36.1", server_version)

    lab.apply(case_dir / "fixtures-and-identities.yaml")
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf-0402-019-probe"},
        "data": {"probe.py": (case_dir / "probe.py").read_text()},
    })

    # Omit serviceAccountName to observe the API server's default on a real Pod.
    lab.create(api_pod(DEFAULT_POD))
    ready(lab, DEFAULT_POD)
    defaulted = observed_service_account(lab, DEFAULT_POD)
    lab.check("positive", "An omitted Pod serviceAccountName defaults to namespace default",
              defaulted == "default", f"observed={defaulted}")

    observed = {}
    for name, (service_account, _, _) in WORKLOADS.items():
        lab.create(api_pod(name, service_account))
        ready(lab, name)
        observed[name] = observed_service_account(lab, name)
    identities_match = all(
        observed[name] == service_account
        for name, (service_account, _, _) in WORKLOADS.items()
    ) and len(set(observed.values())) == len(WORKLOADS) and defaulted not in observed.values()
    lab.check(
        "positive", "Running application Pods retain distinct explicit ServiceAccount assignments",
        identities_match, f"default={defaulted}; dedicated={observed}",
    )

    # The SelfSubjectAccessReview is a permitted authorization query, not an
    # attempted GET of the target ConfigMap. It must say no before the binding.
    for pod_name, (_, own_fixture, _) in WORKLOADS.items():
        decision = probe(lab, pod_name, "review", own_fixture)
        lab.check("red", f"{pod_name} lacks its fixture permission before its RoleBinding",
                  decision == "201 denied", decision)

    lab.apply(case_dir / "scoped-roles-and-bindings.yaml")

    for pod_name, (_, own_fixture, own_marker) in WORKLOADS.items():
        decision = wait_for_binding(lab, pod_name, own_fixture)
        lab.check("green", f"{pod_name} self-review allows only its bound fixture get",
                  decision == "201 allowed", decision)
        observed_read = probe(lab, pod_name, "read", own_fixture, own_marker)
        lab.check("positive", f"{pod_name} completes permitted read of inert own fixture",
                  observed_read == "200 expected-marker", observed_read)

        other_fixture = next(
            fixture for other_name, (_, fixture, _) in WORKLOADS.items()
            if other_name != pod_name
        )
        other_decision = probe(lab, pod_name, "review", other_fixture)
        lab.check("green", f"{pod_name} self-review denies the other workload fixture",
                  other_decision == "201 denied", other_decision)
