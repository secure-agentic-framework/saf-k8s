"""Exercise workload identity metadata RBAC and registry admission in Kind."""
import json
from pathlib import Path
import subprocess
import time

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NAMESPACE = "saf-test"
GROUP = "security.saf-lab.example"
REGISTRY = "synthetic-identity-approvals"
REGISTRAR = "registrar"
TARGET_SA = "synthetic-workload"
DENIED_SA = "synthetic-unapproved-v1"
APPROVED_SA = "synthetic-approved-profile-v1"
DENIED_NAMESPACE = "synthetic-unapproved-tenant-v1"
APPROVED_NAMESPACE = "synthetic-approved-tenant-v1"
SA_KEY = "saf.example/identity-profile"
NS_KEY = "saf.example/identity-tenant"
SA_POLICY = "saf-0402-004-serviceaccount-policy"
NS_POLICY = "saf-0402-004-namespace-policy"
SA_BINDING = "saf-0402-004-serviceaccount-binding"
NS_BINDING = "saf-0402-004-namespace-binding"
AUDIT_POLICY = "/etc/kubernetes/saf-0402-004-audit.yaml"
AUDIT_LOG = "/var/log/kubernetes/saf-0402-004-audit.jsonl"
HERE = Path(__file__).resolve().parent

SCOPE = (
    "Fresh local Kind Kubernetes v1.36.1 only. Uses synthetic case-owned ServiceAccounts, "
    "one synthetic namespace, a namespaced approval-registry CRD, narrowly scoped RBAC, "
    "and two ValidatingAdmissionPolicy bindings. Demonstrates baseline acceptance of "
    "unapproved metadata, RBAC denial for an ordinary workload identity, typed admission "
    "denial for an RBAC-authorized registrar with stored-value preservation, and approved "
    "metadata registration/readback. RequestResponse audit covers updates to the named "
    "synthetic ServiceAccount and namespace. Secret and token resources are excluded. "
    "Does not establish production policy coverage, cloud federation behavior, token "
    "audiences, or audit retention outside this disposable cluster."
)


def prepare_kind(lab, temporary: Path) -> Path:
    (temporary / "audit-log").mkdir(mode=0o700)
    audit = temporary / "saf-0402-004-audit.yaml"
    audit.write_text(f"""apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
- level: None
  resources:
  - group: ""
    resources: [secrets, serviceaccounts/token]
- level: RequestResponse
  verbs: [update]
  namespaces: [{NAMESPACE}]
  resources:
  - group: ""
    resources: [serviceaccounts]
    resourceNames: [{TARGET_SA}]
- level: RequestResponse
  verbs: [update]
  resources:
  - group: ""
    resources: [namespaces]
    resourceNames: [{NAMESPACE}]
- level: None
""")
    config = temporary / "kind.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(audit))}
    containerPath: {AUDIT_POLICY}
    readOnly: true
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta4
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
    - name: audit-policy-file
      value: {AUDIT_POLICY}
    - name: audit-log-path
      value: {AUDIT_LOG}
    extraVolumes:
    - name: saf-0402-004-audit-policy
      hostPath: {AUDIT_POLICY}
      mountPath: {AUDIT_POLICY}
      readOnly: true
      pathType: File
    - name: saf-0402-004-audit-log
      hostPath: /var/log/kubernetes
      mountPath: /var/log/kubernetes
      readOnly: false
      pathType: DirectoryOrCreate
""")
    return config


def approval_registry():
    return {
        "apiVersion": f"{GROUP}/v1", "kind": "WorkloadIdentityApproval",
        "metadata": {"name": REGISTRY, "namespace": NAMESPACE},
        "spec": {
            "serviceAccounts": [{"namespace": NAMESPACE, "name": TARGET_SA, "value": APPROVED_SA}],
            "namespaces": [{"name": NAMESPACE, "value": APPROVED_NAMESPACE}],
        },
    }


def policy(name, resource, expression, *, namespaced):
    if namespaced:
        scope = f'object.metadata.namespace == "{NAMESPACE}" && object.metadata.name == "{TARGET_SA}"'
    else:
        scope = f'object.metadata.name == "{NAMESPACE}"'
    return {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": name},
        "spec": {
            "failurePolicy": "Fail",
            "paramKind": {"apiVersion": f"{GROUP}/v1", "kind": "WorkloadIdentityApproval"},
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"],
                "operations": ["CREATE", "UPDATE"], "resources": [resource],
            }]},
            "matchConditions": [{"name": "only-named-fixture-object", "expression": scope}],
            "validations": [{"expression": expression,
                "message": "workload identity metadata must match the approved case registry",
                "reason": "Forbidden"}],
        },
    }


def binding(name, policy_name):
    result = {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": name},
        "spec": {
            "policyName": policy_name,
            "validationActions": ["Deny"],
            "paramRef": {"name": REGISTRY, "namespace": NAMESPACE, "parameterNotFoundAction": "Deny"},
        },
    }
    return result


def change(lab, identity, resource, name, metadata, *, dry_run=False):
    body = parsed(lab, resource, name)
    for group, attributes in metadata.items():
        fields = body["metadata"].setdefault(group, {})
        for key, value in attributes.items():
            if value is None:
                fields.pop(key, None)
            else:
                fields[key] = value
    if resource == "serviceaccount":
        target = f"/api/v1/namespaces/{NAMESPACE}/serviceaccounts/{name}"
    else:
        target = f"/api/v1/namespaces/{name}"
    if dry_run:
        target += "?dryRun=All"
    return lab.kubectl("--as", identity, "replace", "--raw", target, "-f", "-",
                       payload=json.dumps(body), allow_failure=True)


def parsed(lab, resource, name, *, namespace=NAMESPACE):
    return json.loads(lab.kubectl("-n", namespace, "get", resource, name, "-o", "json").stdout)


def policy_denial(result, policy_name):
    message = result.stderr + result.stdout
    return result.returncode != 0 and "(Forbidden)" in message and policy_name in message


def rbac_denial(result):
    message = result.stderr + result.stdout
    return result.returncode != 0 and "(Forbidden)" in message and "cannot update" in message


def install_rbac(lab):
    lab.kubectl("-n", NAMESPACE, "create", "serviceaccount", REGISTRAR)
    lab.kubectl("-n", NAMESPACE, "create", "serviceaccount", TARGET_SA)
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "saf-0402-004-registrar", "namespace": NAMESPACE},
        "rules": [{"apiGroups": [""], "resources": ["serviceaccounts"],
                    "resourceNames": [TARGET_SA], "verbs": ["update"]}],
    }
    role_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "saf-0402-004-registrar", "namespace": NAMESPACE},
        "subjects": [{"kind": "ServiceAccount", "name": REGISTRAR, "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role["metadata"]["name"]},
    }
    cluster_role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
        "metadata": {"name": "saf-0402-004-namespace-registrar"},
        "rules": [{"apiGroups": [""], "resources": ["namespaces"],
                    "resourceNames": [NAMESPACE], "verbs": ["update"]}],
    }
    cluster_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
        "metadata": {"name": "saf-0402-004-namespace-registrar"},
        "subjects": [{"kind": "ServiceAccount", "name": REGISTRAR, "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": cluster_role["metadata"]["name"]},
    }
    for obj in (role, role_binding, cluster_role, cluster_binding):
        lab.create(obj)


def verify_audit(lab):
    expected = {
        "serviceaccounts": (TARGET_SA, "annotations", SA_KEY, APPROVED_SA),
        "namespaces": (NAMESPACE, "labels", NS_KEY, APPROVED_NAMESPACE),
    }
    persona = f"system:serviceaccount:{NAMESPACE}:{REGISTRAR}"

    def value(event, section, key_group, key):
        return (event.get(section) or {}).get("metadata", {}).get(key_group, {}).get(key)

    end = time.monotonic() + 20
    while time.monotonic() < end:
        output = subprocess.run(["docker", "exec", f"{lab.cluster}-control-plane", "cat", AUDIT_LOG],
                                capture_output=True, env=lab.env, text=True, timeout=10)
        if output.returncode:
            time.sleep(0.5)
            continue
        rows = []
        for line in output.stdout.splitlines():
            event = json.loads(line)
            if event.get("stage") != "ResponseComplete":
                continue
            ref = event.get("objectRef", {})
            resource = ref.get("resource")
            if resource not in expected or ref.get("subresource"):
                lab.block("Audit fixture recorded a resource outside its narrow filter")
            name, group, key, _ = expected[resource]
            if ref.get("name") != name or event.get("verb") != "update":
                lab.block("Audit fixture recorded an unrelated update")
            rows.append({
                "resource": resource, "named_object": name, "level": event.get("level"),
                "identity": event.get("impersonatedUser", {}).get("username"),
                "status": event.get("responseStatus", {}).get("code"),
                "requested_value": value(event, "requestObject", group, key),
                "returned_value": value(event, "responseObject", group, key),
            })
        summaries = {}
        for resource, (_, _, _, approved) in expected.items():
            selected = [row for row in rows if row["resource"] == resource
                        and row["level"] == "RequestResponse" and row["identity"] == persona]
            summaries[resource] = {
                "approved_request_and_response_recorded": any(
                    row["status"] == 200 and row["requested_value"] == row["returned_value"] == approved
                    for row in selected),
                "denied_update_recorded": any(row["status"] == 403 for row in selected),
            }
        if all(all(checks.values()) for checks in summaries.values()):
            break
        time.sleep(0.5)
    else:
        lab.block("Matching RequestResponse audit events for both test resources were not available")
    lab.check("positive", "API audit retains approved and denied outcomes for both protected attributes",
              all(all(checks.values()) for checks in summaries.values()), summaries)
    (lab.evidence / "identity-audit.raw.json").write_text(json.dumps(rows, indent=2) + "\n")


def run(lab):
    install_rbac(lab)

    identity = f"system:serviceaccount:{NAMESPACE}:{REGISTRAR}"
    ordinary = f"system:serviceaccount:{NAMESPACE}:{TARGET_SA}"

    # Red: the RBAC-authorized registrar can change arbitrary values before CEL admission.
    red_sa = change(lab, identity, "serviceaccount", TARGET_SA,
                   {"annotations": {SA_KEY: "synthetic-unapproved-v0"}})
    lab.check("red", "Registrar RBAC permits the baseline unapproved ServiceAccount annotation before admission",
              red_sa.returncode == 0, {"pre_policy_mutation_succeeded": red_sa.returncode == 0})
    red_ns = change(lab, identity, "namespace", NAMESPACE,
                   {"labels": {NS_KEY: "synthetic-unapproved-tenant-v0"}})
    lab.check("red", "Registrar RBAC permits the baseline unapproved namespace label before admission",
              red_ns.returncode == 0, {"pre_policy_mutation_succeeded": red_ns.returncode == 0})

    lab.apply(HERE / "approval-registry-crd.yaml")
    lab.kubectl("wait", "--for=condition=Established", f"crd/workloadidentityapprovals.{GROUP}", "--timeout=45s")
    lab.create(approval_registry())

    sa_expression = (
        f"(oldObject == null ? (!(has(object.metadata.annotations) && '{SA_KEY}' in object.metadata.annotations) "
        f"|| params.spec.serviceAccounts.exists(x, x.namespace == object.metadata.namespace && "
        f"x.name == object.metadata.name && x.value == object.metadata.annotations['{SA_KEY}'])) : "
        f"((has(oldObject.metadata.annotations) && '{SA_KEY}' in oldObject.metadata.annotations && "
        f"has(object.metadata.annotations) && '{SA_KEY}' in object.metadata.annotations && "
        f"oldObject.metadata.annotations['{SA_KEY}'] == object.metadata.annotations['{SA_KEY}']) || "
        f"(!(has(object.metadata.annotations) && '{SA_KEY}' in object.metadata.annotations) && "
        f"!(has(oldObject.metadata.annotations) && '{SA_KEY}' in oldObject.metadata.annotations)) || "
        f"(has(object.metadata.annotations) && '{SA_KEY}' in object.metadata.annotations && "
        f"params.spec.serviceAccounts.exists(x, x.namespace == object.metadata.namespace && "
        f"x.name == object.metadata.name && x.value == object.metadata.annotations['{SA_KEY}']))))"
    )
    ns_expression = (
        f"(oldObject == null ? (!(has(object.metadata.labels) && '{NS_KEY}' in object.metadata.labels) || "
        f"params.spec.namespaces.exists(x, x.name == object.metadata.name && x.value == object.metadata.labels['{NS_KEY}'])) : "
        f"((has(oldObject.metadata.labels) && '{NS_KEY}' in oldObject.metadata.labels && "
        f"has(object.metadata.labels) && '{NS_KEY}' in object.metadata.labels && "
        f"oldObject.metadata.labels['{NS_KEY}'] == object.metadata.labels['{NS_KEY}']) || "
        f"(!(has(object.metadata.labels) && '{NS_KEY}' in object.metadata.labels) && "
        f"!(has(oldObject.metadata.labels) && '{NS_KEY}' in oldObject.metadata.labels)) || "
        f"(has(object.metadata.labels) && '{NS_KEY}' in object.metadata.labels && "
        f"params.spec.namespaces.exists(x, x.name == object.metadata.name && x.value == object.metadata.labels['{NS_KEY}']))))"
    )
    for obj in (
        policy(SA_POLICY, "serviceaccounts", sa_expression, namespaced=True),
        policy(NS_POLICY, "namespaces", ns_expression, namespaced=False),
        binding(SA_BINDING, SA_POLICY),
        binding(NS_BINDING, NS_POLICY),
    ):
        lab.create(obj)

    # RBAC must reject the ordinary workload identity before admission is relevant.
    ordinary_sa = change(lab, ordinary, "serviceaccount", TARGET_SA,
                        {"annotations": {SA_KEY: APPROVED_SA}})
    lab.check("green", "Ordinary workload identity cannot update the case ServiceAccount",
              rbac_denial(ordinary_sa), {"denied_by_rbac": rbac_denial(ordinary_sa)})
    ordinary_ns = change(lab, ordinary, "namespace", NAMESPACE,
                        {"labels": {NS_KEY: APPROVED_NAMESPACE}})
    lab.check("green", "Ordinary workload identity cannot update the case namespace",
              rbac_denial(ordinary_ns), {"denied_by_rbac": rbac_denial(ordinary_ns)})

    # Server dry runs establish that both bindings have taken effect.
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if (policy_denial(change(lab, identity, "serviceaccount", TARGET_SA,
                                 {"annotations": {SA_KEY: DENIED_SA}}, dry_run=True), SA_POLICY)
                and policy_denial(change(lab, identity, "namespace", NAMESPACE,
                                         {"labels": {NS_KEY: DENIED_NAMESPACE}}, dry_run=True), NS_POLICY)):
            break
        time.sleep(0.5)
    else:
        lab.block("The synthetic approval policies did not activate on both resources")

    # Policy challenge: the authorized registrar must use a registry value.
    denied_sa = change(lab, identity, "serviceaccount", TARGET_SA,
                      {"annotations": {SA_KEY: DENIED_SA}})
    stored_sa = parsed(lab, "serviceaccount", TARGET_SA)
    sa_preserved = stored_sa.get("metadata", {}).get("annotations", {}).get(SA_KEY) == "synthetic-unapproved-v0"
    lab.check("green", "Admission rejects registrar's unapproved annotation and preserves the original value",
              policy_denial(denied_sa, SA_POLICY) and sa_preserved,
              {"policy_denial": policy_denial(denied_sa, SA_POLICY), "original_value_preserved": sa_preserved})

    denied_ns = change(lab, identity, "namespace", NAMESPACE,
                      {"labels": {NS_KEY: DENIED_NAMESPACE}})
    stored_ns = parsed(lab, "namespace", NAMESPACE)
    ns_preserved = stored_ns.get("metadata", {}).get("labels", {}).get(NS_KEY) == "synthetic-unapproved-tenant-v0"
    lab.check("green", "Admission rejects registrar's unapproved namespace label and preserves the original value",
              policy_denial(denied_ns, NS_POLICY) and ns_preserved,
              {"policy_denial": policy_denial(denied_ns, NS_POLICY), "original_value_preserved": ns_preserved})

    allowed_sa = change(lab, identity, "serviceaccount", TARGET_SA,
                       {"annotations": {SA_KEY: APPROVED_SA}})
    allowed_sa_data = parsed(lab, "serviceaccount", TARGET_SA)
    sa_readback = allowed_sa.returncode == 0 and allowed_sa_data.get("metadata", {}).get("annotations", {}).get(SA_KEY) == APPROVED_SA
    lab.check("positive", "Registrar can register and read back the exact approved ServiceAccount annotation",
              sa_readback, {"approved_value_read_back": sa_readback})

    allowed_ns = change(lab, identity, "namespace", NAMESPACE,
                       {"labels": {NS_KEY: APPROVED_NAMESPACE}})
    allowed_ns_data = parsed(lab, "namespace", NAMESPACE)
    ns_readback = allowed_ns.returncode == 0 and allowed_ns_data.get("metadata", {}).get("labels", {}).get(NS_KEY) == APPROVED_NAMESPACE
    lab.check("positive", "Registrar can register and read back the exact approved namespace label",
              ns_readback, {"approved_value_read_back": ns_readback})

    removed_sa = change(lab, identity, "serviceaccount", TARGET_SA, {"annotations": {SA_KEY: None}})
    removed_ns = change(lab, identity, "namespace", NAMESPACE, {"labels": {NS_KEY: None}})
    removal_denied = policy_denial(removed_sa, SA_POLICY) and policy_denial(removed_ns, NS_POLICY)
    lab.check("green", "Registrar cannot remove either protected registered attribute",
              removal_denied, {"both_removals_denied": removal_denied})
    incidental = "saf.example/review-note"
    note = change(lab, identity, "namespace", NAMESPACE, {"labels": {incidental: "reviewed"}})
    unchanged_guard = change(lab, identity, "serviceaccount", TARGET_SA,
                             {"annotations": {SA_KEY: DENIED_SA}})
    still_protected = policy_denial(unchanged_guard, SA_POLICY)
    lab.check("positive", "An ordinary namespace metadata update leaves named-object enforcement in place",
              note.returncode == 0 and still_protected,
              {"unrelated_update_allowed": note.returncode == 0,
               "named_serviceaccount_still_protected": still_protected})
    verify_audit(lab)
