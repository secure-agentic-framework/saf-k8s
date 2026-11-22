"""Live-by-ID synthetic budget-rate admission probe.

Kueue sees a raw Workload and a fictional rate resource. No Job or Pod is created.
"""
from hashlib import sha256
import json
import time


KUEUE_VERSION = "v0.20.6"
KUEUE_MANIFEST = (
    "https://github.com/kubernetes-sigs/kueue/releases/download/"
    f"{KUEUE_VERSION}/manifests.yaml"
)
MANIFEST_SHA256 = "b5f643595cfe4799b47acd3499f535fb7137af1dd734a5a66ed67a4fe9f9e466"
IMAGE_SHA256 = "20465f0e56a4eed90ec07fa7838866a90f7b6890c0adc84be86aaee307a6744a"
NAMESPACE = "saf-0703-009-team"
LOCAL_QUEUE = "synthetic-budget"
CLUSTER_QUEUE = "saf-0703-009-team-budget"
RESOURCE = "example.com/usd-per-hour"
BUDGET_RATE_UNITS_PER_HOUR = 5
RATE_REQUESTS = {"baseline": 3, "at-bound": 2, "over-bound": 1}

SCOPE = (
    "Kueue v0.20.6 ClusterQueue quota admission for one isolated team namespace. "
    "The only accounted resource is a synthetic integer example.com/usd-per-hour "
    "request, with one declared unit standing for a fictional whole USD/hour of "
    "requested rate and a five-unit cap. Raw Kueue Workloads are used; this creates "
    "no Job, Pod, GPU allocation, device request, cloud budget, invoice, charge, "
    "billing record, external notification, job suspension, or scale-down. It does "
    "not measure actual GPU use, provider prices, cumulative spend, a budget window, "
    "or production tenant ownership/RBAC."
)


def cluster_resources():
    return [
        {
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": NAMESPACE,
                         "labels": {"saf.example/team": "synthetic-budget-team"}},
        },
        {
            "apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "ResourceFlavor",
            "metadata": {"name": "synthetic-budget-rate"},
            "spec": {"nodeLabels": {}},
        },
        {
            "apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "ClusterQueue",
            "metadata": {"name": CLUSTER_QUEUE},
            "spec": {
                "namespaceSelector": {
                    "matchLabels": {"saf.example/team": "synthetic-budget-team"}
                },
                "resourceGroups": [{
                    "coveredResources": [RESOURCE],
                    "flavors": [{
                        "name": "synthetic-budget-rate",
                        "resources": [{
                            "name": RESOURCE,
                            "nominalQuota": str(BUDGET_RATE_UNITS_PER_HOUR + 1),
                        }],
                    }],
                }],
            },
        },
        {
            "apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "LocalQueue",
            "metadata": {"name": LOCAL_QUEUE, "namespace": NAMESPACE},
            "spec": {"clusterQueue": CLUSTER_QUEUE},
        },
    ]


def workload(name, rate_units):
    """Create a raw Workload; its fake image is never pulled or instantiated."""
    return {
        "apiVersion": "kueue.x-k8s.io/v1beta2", "kind": "Workload",
        "metadata": {"name": f"saf-0703-009-{name}", "namespace": NAMESPACE},
        "spec": {
            "active": True,
            "queueName": LOCAL_QUEUE,
            "podSets": [{
                "count": 1,
                "name": "synthetic-rate-only",
                "template": {"spec": {
                    "containers": [{
                        "name": "never-instantiated",
                        "image": "example.invalid/synthetic-only:never-pulled",
                        "resources": {"requests": {RESOURCE: str(rate_units)},
                                      "limits": {RESOURCE: str(rate_units)}},
                    }],
                    "restartPolicy": "Never",
                }},
            }],
        },
    }


def get_workload(lab, name):
    result = lab.kubectl(
        "get", "workload", f"saf-0703-009-{name}", "-n", NAMESPACE,
        "-o", "json", allow_failure=True,
    )
    return None if result.returncode else json.loads(result.stdout)


def condition(obj, kind):
    return next((item for item in obj.get("status", {}).get("conditions", [])
                 if item.get("type") == kind), {})


def admitted(obj):
    return condition(obj, "Admitted").get("status") == "True"


def has_quota_pending(obj):
    reserved = condition(obj, "QuotaReserved")
    return reserved.get("status") == "False" and reserved.get("reason") == "WaitingForQuota"


def wait_for(lab, predicate, description, timeout=120):
    deadline = time.monotonic() + timeout
    latest = {}
    while time.monotonic() < deadline:
        latest = {}
        for name in RATE_REQUESTS:
            item = get_workload(lab, name)
            if item is not None:
                latest[name] = item
        if predicate(latest):
            return latest
        time.sleep(1)
    lab.block(f"Timed out waiting for Kueue synthetic budget status: {description}; "
              f"last={latest}")


def no_pods(lab):
    pods = json.loads(lab.kubectl("get", "pods", "-n", NAMESPACE, "-o", "json").stdout)
    return len(pods.get("items", [])) == 0



def create(lab, resource):
    namespace = resource["metadata"].get("namespace")
    args = ("-n", namespace) if namespace else ()
    lab.kubectl(*args, "create", "-f", "-", payload=json.dumps(resource))


def install(lab):
    package = lab.kubeconfig.parent / "kueue.yaml"
    lab.command("curl", "--fail", "--silent", "--show-error", "--location", "--max-time", "90",
                KUEUE_MANIFEST, "-o", str(package), timeout=100)
    contents = package.read_bytes()
    if sha256(contents).hexdigest() != MANIFEST_SHA256:
        lab.block("Kueue release manifest failed its publisher digest")
    image = f"registry.k8s.io/kueue/kueue:{KUEUE_VERSION}"
    line = f"        image: {image}\n".encode()
    if contents.count(line) != 1:
        lab.block("Expected one Kueue controller image reference in the release asset")
    package.write_bytes(contents.replace(line, f"        image: {image}@sha256:{IMAGE_SHA256}\n".encode()))
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "apply", "--server-side", "-f", str(package), timeout=120)
    lab.kubectl("wait", "--for=condition=available", "deploy/kueue-controller-manager",
                "-n", "kueue-system", "--timeout=150s", timeout=155)
    flavor = next(item for item in cluster_resources() if item["kind"] == "ResourceFlavor")
    end = time.monotonic() + 40
    while True:
        reply = lab.kubectl("create", "-f", "-", "--dry-run=server", payload=json.dumps(flavor),
                            allow_failure=True)
        if reply.returncode == 0:
            break
        if "failed calling webhook" not in reply.stderr or time.monotonic() >= end:
            lab.block(f"Kueue admission readiness: {reply.stderr.strip()}")
        time.sleep(0.75)


def units(state, name):
    assignments = state.get(name, {}).get("status", {}).get("admission", {}).get("podSetAssignments", [])
    if len(assignments) != 1:
        return None
    return assignments[0].get("resourceUsage", {}).get(RESOURCE)


def run(lab):
    install(lab)
    for item in cluster_resources():
        create(lab, item)
    lab.kubectl("wait", "--for=condition=Active", f"clusterqueue/{CLUSTER_QUEUE}",
                "--timeout=60s", timeout=65)
    lab.kubectl("wait", "--for=condition=Active", f"localqueue/{LOCAL_QUEUE}",
                "-n", NAMESPACE, "--timeout=60s", timeout=65)

    for name, wanted in RATE_REQUESTS.items():
        create(lab, workload(name, wanted))
        wait_for(lab, lambda state: name in state and admitted(state[name]), f"{name} initial reservation")
    before = wait_for(lab, lambda state: all(name in state and admitted(state[name]) for name in RATE_REQUESTS),
                      "three initial reservations")
    accounted = {name: units(before, name) for name in RATE_REQUESTS}
    lab.check("red", "The permissive queue can reserve six declared units above the five-unit target",
              accounted == {name: str(rate) for name, rate in RATE_REQUESTS.items()},
              {"reserved": accounted, "intended_cap": BUDGET_RATE_UNITS_PER_HOUR})

    over_name = "saf-0703-009-over-bound"
    lab.kubectl("delete", "workload", over_name, "-n", NAMESPACE, "--wait=true")
    patch = [{"op": "replace", "path": "/spec/resourceGroups/0/flavors/0/resources/0/nominalQuota",
              "value": str(BUDGET_RATE_UNITS_PER_HOUR)}]
    lab.kubectl("patch", "clusterqueue", CLUSTER_QUEUE, "--type=json", "-p", json.dumps(patch))
    create(lab, workload("over-bound", RATE_REQUESTS["over-bound"]))
    after = wait_for(lab, lambda state: "over-bound" in state and has_quota_pending(state["over-bound"]),
                     "one-unit overage waiting for insufficient quota")
    over = after["over-bound"]
    pending = condition(over, "QuotaReserved")
    lab.check("green", "The same request remains pending specifically because the target cap is full",
              not admitted(over) and "insufficient unused quota" in pending.get("message", "").lower()
              and [units(after, base) for base in ("baseline", "at-bound")] == ["3", "2"],
              {"overage_pending": has_quota_pending(over), "reserved_before_overage": 5, "cap": BUDGET_RATE_UNITS_PER_HOUR})

    lab.kubectl("delete", "workload", "saf-0703-009-at-bound", "-n", NAMESPACE, "--wait=true")
    freed = wait_for(lab, lambda state: "over-bound" in state and admitted(state["over-bound"]),
                     "formerly pending request admitted after capacity release")
    lab.check("positive", "Releasing a reservation admits the waiting request with no fixture Pods",
              [units(freed, base) for base in ("baseline", "over-bound")] == ["3", "1"] and no_pods(lab),
              {"remaining_reservations": 4, "previous_overage_admitted": admitted(freed["over-bound"]),
               "fixture_pods": 0 if no_pods(lab) else "nonzero"})
