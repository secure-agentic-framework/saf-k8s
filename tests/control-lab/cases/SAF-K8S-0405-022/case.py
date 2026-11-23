"""Verify the effective namespace scope of two actual temporary callers."""
import importlib.util
import json
from pathlib import Path
import time

NS = "saf-test"
NEIGHBOR = "fixture-other-tenant"
RBAC = "rbac.authorization.k8s.io/v1"
TARGET = "fixture-recovery-record"
OTHER = "fixture-unrelated-record"
CALLER = "fixture-emergency-reader"
SEPARATE = "fixture-neighbor-reader"
SCOPE = (
    "Two real temporary Kubernetes credentials read only named case-owned ConfigMaps. "
    "Withdrawing the extra tenant grant removes the actual cross-namespace read despite "
    "the caller and credential remaining unchanged. An independently authorized neighbor "
    "still reads its own record. The fixture exercises namespace RBAC, with deployed "
    "tenant boundaries and external access paths requiring their own evidence."
)


def recovery_fixture():
    path = Path(__file__).resolve().parents[1] / "SAF-K8S-0405-020" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_fixture_recovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def put(lab, kind, name, namespace=None, api="v1", **fields):
    metadata = {"name": name}
    resource = {"apiVersion": api, "kind": kind, "metadata": metadata, **fields}
    if not namespace or namespace == NS:
        return lab.create(resource)
    metadata["namespace"] = namespace
    return json.loads(lab.kubectl("--namespace", namespace, "create", "-f", "-", "-o", "json",
                                  payload=json.dumps(resource)).stdout)


def allow(lab, account, namespace):
    put(lab, "RoleBinding", account, namespace, RBAC,
        roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": TARGET},
        subjects=[{"kind": "ServiceAccount", "name": account, "namespace": NS}])


def observe(lab, profile, namespace, name):
    result = lab.command("kubectl", "--kubeconfig", str(profile), "--context", "fixture",
                         "--request-timeout=6s", "get",
                         f"--raw=/api/v1/namespaces/{namespace}/configmaps/{name}",
                         allow_failure=True, timeout=12)
    if result.returncode == 0 and json.loads(result.stdout)["data"]["marker"] == namespace:
        return "allowed"
    if "(Forbidden)" in result.stderr:
        return "forbidden"
    lab.block("The fixture read did not return an authorized record or a genuine denial")


def run(lab):
    recover = recovery_fixture()
    put(lab, "Namespace", NEIGHBOR)
    for actor in (CALLER, SEPARATE):
        put(lab, "ServiceAccount", actor, NS, automountServiceAccountToken=False)
    for namespace in (NS, NEIGHBOR):
        for record in (TARGET, OTHER):
            put(lab, "ConfigMap", record, namespace, data={"marker": namespace})
        put(lab, "Role", TARGET, namespace, RBAC, rules=[{
            "apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"], "resourceNames": [TARGET],
        }])
        allow(lab, CALLER, namespace)
    allow(lab, SEPARATE, NEIGHBOR)
    caller = recover.identity(lab, CALLER, "tenant-emergency")
    neighbor = recover.identity(lab, SEPARATE, "tenant-neighbor")
    initial = {"approved_tenant_read_allowed": observe(lab, caller, NS, TARGET) == "allowed",
               "excess_role_allows_other_tenant": observe(lab, caller, NEIGHBOR, TARGET) == "allowed"}
    lab.check("red", "A context and credential do not themselves enforce the intended tenant boundary",
              all(initial.values()), initial)

    lab.kubectl("delete", "rolebinding", CALLER, "-n", NEIGHBOR, "--wait=true")
    for _ in range(6):
        decision = observe(lab, caller, NEIGHBOR, TARGET)
        if decision == "forbidden":
            break
        time.sleep(1)
    enforced = {"actual_cross_tenant_read_denied": decision == "forbidden",
                "approved_named_tenant_read_remains_allowed": observe(lab, caller, NS, TARGET) == "allowed",
                "unrelated_object_in_same_tenant_denied": observe(lab, caller, NS, OTHER) == "forbidden"}
    lab.check("green", "The effective authorization limits the original caller to its intended tenant and object",
              all(enforced.values()), enforced)

    positive = {"neighbor_independently_reads_own_record": observe(lab, neighbor, NEIGHBOR, TARGET) == "allowed",
                "neighbor_cannot_read_the_original_tenant": observe(lab, neighbor, NS, TARGET) == "forbidden"}
    lab.check("positive", "The correction preserves the independent authorized workflow",
              all(positive.values()), positive)
    (lab.evidence / "tenant-emergency-observations.json").write_text(json.dumps({
        "baseline": initial, "enforced": enforced, "independent_access": positive,
    }, indent=2) + "\n")
