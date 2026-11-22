"""Counterfactually check AI pool scheduling isolation with inert fixture Pods."""
import json
import time

POOL = "saf.example/node-pool"
TAINT = "saf.example/ai-pool"
PRODUCT = "saf.example/gpu-product"
WORKLOAD_LABEL = "saf-k8s.example/ai-fixture"
POLICY = "saf-0703-012-ai-placement"
AI_TOLERATION = {
    "key": TAINT, "operator": "Equal", "value": "reserved", "effect": "NoSchedule",
}
SCOPE = (
    "Kubernetes v1.36.1 on a disposable three-node kind cluster. Synthetic worker labels and a "
    "NoSchedule taint exercise required node affinity, taint rejection, a matching toleration, "
    "and permitted general scheduling with inert Pods. A separate admission policy enforces "
    "the exact fields for labeled AI fixtures. Production label authority, hardware, device plugins "
    "and operator coverage require their own evidence."
)


def pod(name, *, pool, product=None, toleration=False):
    """Create an owned inert Pod with required node affinity when a pool is specified."""
    expressions = [{"key": POOL, "operator": "In", "values": [pool]}]
    if product is not None:
        expressions.append({"key": PRODUCT, "operator": "In", "values": [product]})
    spec = {
        "automountServiceAccountToken": False,
        "restartPolicy": "Never",
        "containers": [{
            "name": "probe",
            "image": "registry.k8s.io/pause:3.10.1@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c",
        }],
        "affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {
            "nodeSelectorTerms": [{"matchExpressions": expressions}],
        }}},
    }
    if toleration:
        spec["tolerations"] = [AI_TOLERATION]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": spec}


def as_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def pod_record(lab, name):
    return as_json(lab, "get", "pod", name)


def wait_for(lab, name, predicate, seconds=20):
    end = time.monotonic() + seconds
    record = pod_record(lab, name)
    while time.monotonic() < end:
        if predicate(record):
            return record
        time.sleep(0.5)
        record = pod_record(lab, name)
    return record


def scheduled(record):
    return bool(record.get("spec", {}).get("nodeName"))


def node_pool(nodes, name):
    return nodes.get(name, {}).get("metadata", {}).get("labels", {}).get(POOL)


def install_placement_policy(lab):
    version = "admissionregistration.k8s.io/v1"
    terms = "object.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms"
    lab.create({"apiVersion": version, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"],
                }]}, "validations": [{
                    "expression": "has(object.spec.affinity) && has(object.spec.affinity.nodeAffinity) && "
                                  "has(object.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution) && "
                                  f"size({terms}) > 0 && {terms}.all(term, has(term.matchExpressions) && "
                                  f"term.matchExpressions.exists(e, e.key == '{POOL}' && e.operator == 'In' && e.values == ['ai']) && "
                                  f"term.matchExpressions.exists(e, e.key == '{PRODUCT}' && e.operator == 'In' && e.values == ['synthetic'])) && "
                                  "has(object.spec.tolerations) && object.spec.tolerations.exists(t, "
                                  f"t.key == '{TAINT}' && t.operator == 'Equal' && t.value == 'reserved' && t.effect == 'NoSchedule')",
                    "message": "fixture AI workload requires exact affinity and toleration", "reason": "Forbidden",
                }], "matchConditions": [{"name": "fixture-namespace", "expression": "request.namespace == 'saf-test'"}]}})
    lab.create({"apiVersion": version, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "objectSelector": {"matchLabels": {WORKLOAD_LABEL: "required"}},
                }}})


def check_placement_admission(lab):
    lacking = pod("saf-0703-012-admission-incomplete", pool="ai", product="synthetic")
    lacking["metadata"]["labels"] = {WORKLOAD_LABEL: "required"}
    before = lab.create(lacking, dry_run=True, allow_failure=True)
    lab.check("red", "The API admits the labeled incomplete declaration before its policy exists",
              before.returncode == 0, {"dry_run_admitted": before.returncode == 0})
    install_placement_policy(lab)
    end = time.monotonic() + 20
    while True:
        after = lab.create(lacking, dry_run=True, allow_failure=True)
        rejected = (after.returncode != 0 and "(Forbidden)" in after.stderr
                    and f"ValidatingAdmissionPolicy '{POLICY}'" in after.stderr
                    and "fixture AI workload requires exact affinity and toleration" in after.stderr)
        if rejected or time.monotonic() >= end:
            break
        time.sleep(0.5)
    lab.check("green", "The scoped policy rejects the same incomplete AI declaration",
              rejected, {"expected_policy_denial": rejected})
    complete = pod("saf-0703-012-admission-complete", pool="ai", product="synthetic", toleration=True)
    complete["metadata"]["labels"] = {WORKLOAD_LABEL: "required"}
    permitted = lab.create(complete, dry_run=True, allow_failure=True)
    lab.check("positive", "The scoped policy admits the exact permitted AI declaration",
              permitted.returncode == 0, {"complete_declaration_admitted": permitted.returncode == 0})


def run(lab):
    nodes = as_json(lab, "get", "nodes")["items"]
    by_pool = {}
    for node in nodes:
        pool = node.get("metadata", {}).get("labels", {}).get(POOL)
        if pool:
            by_pool[pool] = node["metadata"]["name"]
    ai_node, general_node = by_pool.get("ai"), by_pool.get("general")
    lab.check("positive", "Fixture exposes distinct AI and general scheduling targets",
              bool(ai_node and general_node and ai_node != general_node),
              {"distinct_workers": bool(ai_node and general_node and ai_node != general_node)})

    # Counterfactual: same required AI affinity schedules to the synthetic AI worker
    # while its dedicated-pool taint is absent.
    lab.create(pod("saf-0703-012-before", pool="ai", product="synthetic"))
    before = wait_for(lab, "saf-0703-012-before", scheduled)
    before_node = before.get("spec", {}).get("nodeName")
    lab.check("red", "Without the dedicated-pool taint, an AI-affine Pod schedules to the AI worker",
              before_node == ai_node,
              {"assigned_to_ai_pool": before_node == ai_node, "taint_configured": False})

    # Activate the dedicated-pool control and challenge the same affinity without
    # its matching toleration. It must remain pending specifically for the taint.
    lab.kubectl("taint", "node", ai_node, f"{TAINT}=reserved:NoSchedule")
    lab.create(pod("saf-0703-012-denied", pool="ai", product="synthetic"))
    denied = wait_for(lab, "saf-0703-012-denied", lambda item: any(
        condition.get("type") == "PodScheduled" and condition.get("reason") == "Unschedulable"
        for condition in item.get("status", {}).get("conditions", [])))
    condition = next((item for item in denied.get("status", {}).get("conditions", [])
                      if item.get("type") == "PodScheduled"), {})
    denied_for_taint = (not scheduled(denied) and condition.get("reason") == "Unschedulable"
                        and "untolerated taint" in condition.get("message", "").lower())
    lab.check("green", "AI-affine Pod without the matching toleration is rejected by the taint",
              denied_for_taint,
              {"scheduled": scheduled(denied), "reason": condition.get("reason"),
               "taint_confirmed": denied_for_taint})
    previous_remains = pod_record(lab, "saf-0703-012-before")["spec"].get("nodeName") == ai_node
    lab.check("positive", "The existing assignment persists after adding a NoSchedule taint",
              previous_remains, {"prior_assignment_preserved": previous_remains})

    # A permitted AI workload has both required AI/product affinity and the exact
    # toleration. A normal workload has no toleration and should remain on general.
    lab.create(pod("saf-0703-012-allowed-ai", pool="ai", product="synthetic", toleration=True))
    ai_allowed = wait_for(lab, "saf-0703-012-allowed-ai", scheduled)
    ai_placed = ai_allowed.get("spec", {}).get("nodeName")
    lab.check("positive", "AI Pod with required affinity and matching toleration schedules to AI pool",
              ai_placed == ai_node,
              {"assigned_to_ai_pool": ai_placed == ai_node,
               "required_product_affinity": PRODUCT + "=synthetic", "matching_toleration": True})

    lab.create(pod("saf-0703-012-general", pool="general"))
    general = wait_for(lab, "saf-0703-012-general", scheduled)
    general_placed = general.get("spec", {}).get("nodeName")
    lab.check("positive", "Ordinary Pod without an AI toleration schedules to the general pool",
              general_placed == general_node and node_pool(
                  {item["metadata"]["name"]: item for item in nodes}, general_placed) == "general",
              {"assigned_to_general_pool": general_placed == general_node,
               "has_ai_toleration": False})
    check_placement_admission(lab)
