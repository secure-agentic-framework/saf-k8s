"""Admission-only probe for SAF-K8S-0503-004."""
import json
from pathlib import Path
import time


SCOPE = ("Real v1.36.1 API admission for Services in the case-owned namespace. "
         "The explicit AWS scheme, separated fixture identities and allowed source ranges are checked "
         "on create and update. This cluster installs no cloud load-balancer controller. "
         "Provider reconciliation, reachability and production approval need separate evidence.")
POLICY_MESSAGE = (
    "LoadBalancer must use the internal scheme or an authorized bounded-CIDR exception."
)
TENANT = "system:serviceaccount:saf-test:tenant"
APPROVER = "system:serviceaccount:saf-approvers:lb-exception-approver"
POLICY = Path(__file__).resolve().parent / "fixtures" / "policy.yaml"
RBAC = Path(__file__).resolve().parent / "fixtures" / "rbac.yaml"
NAMESPACE = Path(__file__).resolve().parent / "fixtures" / "namespace.yaml"
SCHEME = "service.beta.kubernetes.io/aws-load-balancer-scheme"
LEGACY_INTERNAL = "service.beta.kubernetes.io/aws-load-balancer-internal"
BOUNDED_CIDRS = ["198.51.100.0/24", "2001:db8:1234::/48"]


def service(name, *, annotations=None, ranges=None, kind="LoadBalancer"):
    spec = {
        "type": kind,
        "ports": [{"name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP"}],
        "selector": {"app": "fixture"},
    }
    if ranges is not None:
        spec["loadBalancerSourceRanges"] = ranges
    metadata = {"name": name}
    if annotations is not None:
        metadata["annotations"] = annotations
    return {"apiVersion": "v1", "kind": "Service", "metadata": metadata, "spec": spec}


def api(lab, identity, *args, payload=None, allow_failure=False):
    """Send a real Kubernetes API request through kubectl impersonation."""
    return lab.kubectl(*args, f"--as={identity}", payload=payload, allow_failure=allow_failure)


def submit(lab, identity, verb, resource, *, dry_run=False):
    args = ["create", "-f", "-", "-o", "json"]
    if verb == "update":
        name = resource["metadata"]["name"]
        current = api(lab, identity, "get", "service", name, "-o", "json")
        updated = json.loads(current.stdout)
        updated["metadata"]["annotations"] = resource["metadata"].get("annotations", {})
        updated["metadata"]["labels"] = {"saf-k8s.example/update-marker": "observed"}
        updated["spec"].pop("loadBalancerSourceRanges", None)
        updated["spec"].update(resource["spec"])
        resource = updated
        args[0] = "replace"
    if dry_run:
        args.append("--dry-run=server")
    return api(lab, identity, *args, payload=json.dumps(resource), allow_failure=True)


def request_ok(lab, identity, verb, resource):
    result = submit(lab, identity, verb, resource)
    observed = json.loads(result.stdout) if result.returncode == 0 else {}
    metadata = observed.get("metadata", {})
    spec = observed.get("spec", {})
    wanted = resource["spec"]
    facts = {
        "is_service": observed.get("kind") == "Service",
        "stored_uid_present": bool(metadata.get("uid")),
        "type_matched": spec.get("type") == wanted["type"],
        "source_ranges_matched": spec.get("loadBalancerSourceRanges", []) == wanted.get("loadBalancerSourceRanges", []),
        "annotation_matched": metadata.get("annotations", {}) == resource["metadata"].get("annotations", {}),
        "update_marker_matched": (verb != "update" or
                                  metadata.get("labels", {}).get("saf-k8s.example/update-marker") == "observed"),
    }
    lab.check("positive", f"Real API {verb} stored {resource['metadata']['name']}", all(facts.values()), facts)
    return observed


def admission_result(result):
    output = result.stdout + result.stderr
    return {
        "rejected": result.returncode != 0,
        "policy_message_matched": POLICY_MESSAGE in output,
        "policy_and_binding_named": output.count("saf-0503-004-service-scheme") >= 2,
    }


def request_denied(lab, identity, verb, resource, label):
    facts = admission_result(submit(lab, identity, verb, resource))
    lab.check("green", label, all(facts.values()), facts)


def wait_for_binding(lab):
    probe = service("propagation-probe")
    deadline = time.monotonic() + 30
    while True:
        result = submit(lab, TENANT, "create", probe, dry_run=True)
        if all(admission_result(result).values()):
            return
        if time.monotonic() >= deadline:
            lab.block("The Service admission binding did not become active in time")
        time.sleep(0.5)


def run(lab):
    # Namespace and narrowly scoped identities/RBAC are fixtures; no label or
    # annotation on an individual Service is treated as authorization.
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "apply", "-f", str(NAMESPACE))
    lab.apply(RBAC)

    # Same real API route, same owned namespace and Service type, before policy.
    baseline = request_ok(lab, TENANT, "create", service("baseline-unannotated"))
    lab.check("red", "owned unannotated LoadBalancer accepts before policy",
              baseline["spec"]["type"] == "LoadBalancer" and
              not baseline.get("metadata", {}).get("annotations"),
              "API returned the created unannotated LoadBalancer Service")

    lab.apply(POLICY)
    wait_for_binding(lab)

    # CREATE denials distinguish absent scheme, unapproved public exposure,
    # missing CIDRs, an unbounded CIDR and stale legacy-only configuration.
    request_denied(lab, TENANT, "create", service("deny-no-scheme"),
                   "CREATE without an explicit current scheme is denied by VAP")
    request_denied(lab, TENANT, "create", service("deny-public", annotations={SCHEME: "internet-facing"},
                                                   ranges=BOUNDED_CIDRS),
                   "CREATE public scheme without exception identity is denied")
    request_denied(lab, APPROVER, "create", service("deny-no-cidrs", annotations={SCHEME: "internet-facing"}),
                   "CREATE approved public scheme without source ranges is denied")
    request_denied(lab, APPROVER, "create", service("deny-wide-cidr", annotations={SCHEME: "internet-facing"},
                                                      ranges=["0.0.0.0/0"]),
                   "CREATE approved public scheme with unbounded CIDR is denied")
    request_denied(lab, TENANT, "create", service("deny-legacy-only", annotations={LEGACY_INTERNAL: "true"}),
                   "CREATE relying on deprecated legacy key alone is denied")

    request_ok(lab, TENANT, "create", service("allow-internal", annotations={SCHEME: "internal"}))
    request_ok(lab, APPROVER, "create", service("allow-approved-public",
                                                 annotations={SCHEME: "internet-facing"},
                                                 ranges=[BOUNDED_CIDRS[0]]))
    request_ok(lab, TENANT, "create", service("allow-clusterip", kind="ClusterIP"))

    # Existing internal object: exercise an actual UPDATE PUT, then prove a
    # policy-compliant update is still possible.
    request_ok(lab, TENANT, "create", service("update-target", annotations={SCHEME: "internal"}))
    request_denied(lab, TENANT, "update", service("update-target", annotations={SCHEME: "internet-facing"},
                                                  ranges=BOUNDED_CIDRS),
                   "UPDATE to public scheme by non-approver is denied by VAP")
    current = json.loads(api(lab, TENANT, "get", "service", "update-target", "-o", "json").stdout)
    unchanged = (current["metadata"]["annotations"].get(SCHEME) == "internal"
                 and not current["spec"].get("loadBalancerSourceRanges"))
    lab.check("positive", "Denied update left the stored internal Service unchanged",
              unchanged, {"internal_scheme_unchanged": unchanged})
    request_ok(lab, TENANT, "update", service("update-target", annotations={SCHEME: "internal"}))

    # Independent exception identity must still provide bounded explicit CIDRs.
    request_denied(lab, APPROVER, "create", service("deny-other-cidr", annotations={SCHEME: "internet-facing"},
                                                      ranges=["203.0.113.0/24"]),
                   "CREATE by exception identity outside the explicit CIDR allowlist is denied")
