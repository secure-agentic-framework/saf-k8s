"""Observe a placement boundary for synthetic accelerator fabric domains."""

import json
import time

SCOPE = "Real Kubernetes admission and scheduling on separate Kind nodes for modeled accelerator domains."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
LABEL = "fixture.example.node-restriction.kubernetes.io/placement-domain"
POLICY = "fixture-fabric-placement"
MESSAGE = "Fixture workload must use its approved placement domain"


def prepare_kind(_lab, temporary):
    config = temporary / "kind-fabric-placement.yaml"
    config.write_text("""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
""")
    return config


def pod(name, domain):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "nodeSelector": {LABEL: domain},
                     "tolerations": [{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}],
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "fixture", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(150)"],
                                     "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                   "limits": {"cpu": "100m", "memory": "40Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}]}}


def enforce(lab):
    api = "admissionregistration.k8s.io/v1"
    clauses = [f"(object.metadata.name == 'fixture-{domain}' && object.spec.nodeSelector['{LABEL}'] == '{domain}')"
               for domain in ("tenant-a", "tenant-b")]
    rule = f"!has(object.spec.nodeName) && has(object.spec.nodeSelector) && '{LABEL}' in object.spec.nodeSelector && ({' || '.join(clauses)})"
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail",
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE"], "resources": ["pods"]}]},
                         "validations": [{"expression": rule, "message": MESSAGE}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {"fixture.example/fabric-placement": "true"}}}}})


def denied(lab, request):
    result = lab.create(request, dry_run=True, allow_failure=True)
    return result.returncode != 0 and MESSAGE in result.stderr


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted",
                "fixture.example/fabric-placement=true")
    nodes = sorted(row["metadata"]["name"] for row in json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"])
    if len(nodes) != 2:
        lab.block("Expected two owned nodes for the placement boundary")
    placement = dict(zip(("tenant-a", "tenant-b"), nodes))
    for domain, node in placement.items():
        lab.kubectl("label", "node", node, f"{LABEL}={domain}")
    incorrect = pod("fixture-tenant-a", "tenant-b")
    before = lab.create(incorrect, dry_run=True, allow_failure=True).returncode == 0
    lab.check("red", "The API accepts the contrary modeled domain before placement enforcement",
              before, {"unapproved_domain_initially_admitted": before})

    enforce(lab)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if denied(lab, incorrect):
            break
        time.sleep(0.4)
    else:
        lab.block("The fixture policy did not deny the contrary placement")
    direct = pod("fixture-tenant-a", "tenant-a")
    direct["spec"]["nodeName"] = placement["tenant-a"]
    direct_denied = denied(lab, direct)
    lab.check("green", "Admission denies the contrary selector and requires scheduler-mediated placement",
              direct_denied, {"contrary_domain_denied": True, "direct_assignment_denied": direct_denied})

    observed = {}
    for domain, node in placement.items():
        name = f"fixture-{domain}"
        lab.create(pod(name, domain))
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=60s", timeout=70)
        actual = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
        observed[domain] = actual["spec"]["nodeName"] == node
    lab.check("positive", "Both approved fixture Pods run on their separate intended nodes",
              all(observed.values()), {"approved_placement": observed, "distinct_nodes": len(set(placement.values()))})
    (lab.evidence / "fabric-placement-observations.json").write_text(json.dumps({
        "initially_admitted": before, "contrary_domain_denied": True, "direct_assignment_denied": direct_denied,
        "approved_placement": observed, "distinct_nodes": len(set(placement.values())),
        "physical_fabric_tested": False}, indent=2) + "\n")
