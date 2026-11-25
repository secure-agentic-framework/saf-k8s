"""Validate the catalog's minimum AI workload classification labels."""
import json
from pathlib import Path
import time

from fixtures import container, pod

HERE = Path(__file__).parent
NAMESPACE = "saf-0702-005-ai"
DENIAL = "all three AI workload classification labels must be present and use governed values"
LABELS = {
    "ai.kais.io/workload-type": "inference",
    "ai.kais.io/data-sensitivity": "internal",
    "ai.kais.io/model-tier": "staging",
}
VALUES = {
    "ai.kais.io/workload-type": ["training", "inference", "preprocessing", "evaluation", "notebook"],
    "ai.kais.io/data-sensitivity": ["public", "internal", "confidential", "restricted"],
    "ai.kais.io/model-tier": ["experimental", "staging", "production"],
}
SCOPE = (
    "Kubernetes v1.36.1 ValidatingAdmissionPolicy CREATE enforcement on synthetic Pods "
    "and Job/Deployment/StatefulSet Pod templates in one enrolled namespace; template "
    "CREATE and suspended-Job/Deployment/StatefulSet template UPDATE dry-runs; an unselected namespace "
    "comparison; and actual scoped Metadata audit events containing classification annotations. The case tests native "
    "label-selector inventory and ResourceQuota scope names. External audit delivery, "
    "scheduling, NetworkPolicy traffic, external controllers, "
    "organizational governance and production coverage remain untested."
)


def pod_resource(name, labels):
    resource = pod(name, [container("probe")], automountServiceAccountToken=False)
    resource["metadata"].update(namespace=NAMESPACE, labels=labels)
    return resource


def server_create(lab, resource, namespace=NAMESPACE):
    return lab.kubectl(
        "-n", namespace, "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(resource), allow_failure=True,
    )


def template_resource(kind, name, labels, namespace=NAMESPACE):
    """Return a harmless controller with classification on the generated-Pod template."""
    restart_policy = "Never" if kind == "Job" else "Always"
    common = {
        "metadata": {"name": name, "namespace": namespace,
                     "labels": {"saf-k8s.example/case": "0702-005", "app": name}},
        "spec": {"template": {
            "metadata": {"labels": {**labels, "app": name}},
            "spec": {"restartPolicy": restart_policy, "containers": [container("probe")]},
        }},
    }
    if kind == "Job":
        return {"apiVersion": "batch/v1", "kind": kind,
                **common, "spec": {**common["spec"], "suspend": True}}
    api = "apps/v1"
    common["spec"].update({"replicas": 0, "selector": {"matchLabels": {"app": name}}})
    if kind == "StatefulSet":
        common["spec"]["serviceName"] = name
    elif kind != "Deployment":
        raise ValueError(f"unsupported controller fixture kind: {kind}")
    return {"apiVersion": api, "kind": kind, **common}


def server_replace(lab, kind, name, resource, namespace=NAMESPACE):
    return lab.kubectl("-n", namespace, "replace", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(resource), allow_failure=True)


def existing_for_replace(lab, kind, name):
    result = lab.kubectl("-n", NAMESPACE, "get", kind.lower(), name, "-o", "json")
    resource = json.loads(result.stdout)
    resource.pop("status", None)
    metadata = resource.get("metadata", {})
    for key in ("managedFields", "creationTimestamp", "generation", "selfLink"):
        metadata.pop(key, None)
    return resource


def template_policy(kind, resource, name):
    expression = "has(object.spec.template.metadata.labels)"
    for key, values in VALUES.items():
        allowed = json.dumps(values, separators=(",", ":"))
        expression += (f' && "{key}" in object.spec.template.metadata.labels'
                       f' && object.spec.template.metadata.labels["{key}"] in {allowed}')
    audit_expression = (
        f'"kind={kind};namespace=" + object.metadata.namespace + '
        '";name=" + object.metadata.name + '
        '";workload-type=" + (has(object.spec.template.metadata.labels) && '
        '"ai.kais.io/workload-type" in object.spec.template.metadata.labels ? '
        'object.spec.template.metadata.labels["ai.kais.io/workload-type"] : "missing") + '
        '";data-sensitivity=" + (has(object.spec.template.metadata.labels) && '
        '"ai.kais.io/data-sensitivity" in object.spec.template.metadata.labels ? '
        'object.spec.template.metadata.labels["ai.kais.io/data-sensitivity"] : "missing") + '
        '";model-tier=" + (has(object.spec.template.metadata.labels) && '
        '"ai.kais.io/model-tier" in object.spec.template.metadata.labels ? '
        'object.spec.template.metadata.labels["ai.kais.io/model-tier"] : "missing")'
    )
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": name},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{
                "apiGroups": ["batch"] if kind == "Job" else ["apps"],
                "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                "resources": [resource],
            }]},
            "validations": [{"expression": expression,
                             "message": DENIAL, "reason": "Forbidden"}],
            "auditAnnotations": [{"key": "classification-context",
                                  "valueExpression": audit_expression}],
        },
    }


def apply_template_policies(lab):
    policies = []
    for kind, resource in (("Job", "jobs"), ("Deployment", "deployments"),
                           ("StatefulSet", "statefulsets")):
        name = f"saf-k8s-0702-005-{kind.lower()}-template"
        lab.create(template_policy(kind, resource, name))
        lab.create({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": name},
            "spec": {"policyName": name, "validationActions": ["Deny"],
                     "matchResources": {"namespaceSelector": {"matchLabels": {
                         "saf-k8s.example/classification-enforcement": "required"}}}},
        })
        policies.append(name)
    return policies


def create_controller_bases(lab):
    for kind in ("Job", "Deployment", "StatefulSet"):
        fixture = template_resource(kind, f"template-update-{kind.lower()}", LABELS)
        lab.kubectl("create", "-n", NAMESPACE, "-f", "-", "-o", "name",
                    payload=json.dumps(fixture))


def controller_policy_audit_declared(lab, policy_names):
    observed = {}
    for name in policy_names:
        result = lab.kubectl("get", "validatingadmissionpolicy", name, "-o", "json")
        policy = json.loads(result.stdout)
        annotations = policy.get("spec", {}).get("auditAnnotations", [])
        observed[name] = any(
            row.get("key") == "classification-context"
            and "object.metadata.namespace" in row.get("valueExpression", "")
            and "object.metadata.name" in row.get("valueExpression", "")
            and all(key in row.get("valueExpression", "") for key in VALUES)
            for row in annotations
        )
    pod_policy = lab.kubectl("get", "validatingadmissionpolicy", "saf-k8s-0702-005-classification",
                             "-o", "json")
    pod_annotations = json.loads(pod_policy.stdout).get("spec", {}).get("auditAnnotations", [])
    observed["pod"] = any(
        row.get("key") == "classification-context"
        and "object.metadata.namespace" in row.get("valueExpression", "")
        and "object.metadata.name" in row.get("valueExpression", "")
        and all(key in row.get("valueExpression", "") for key in VALUES)
        for row in pod_annotations
    )
    return observed


def denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and DENIAL in result.stderr)


NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
AUDIT_LOG = "/var/log/kubernetes/saf-classification-audit.log"


def prepare_kind(_lab, temporary):
    policy = temporary / "classification-audit.json"
    policy.write_text(json.dumps({
        "apiVersion": "audit.k8s.io/v1", "kind": "Policy",
        "omitStages": ["RequestReceived"],
        "rules": [{"level": "Metadata", "verbs": ["create"], "namespaces": [NAMESPACE],
                   "resources": [{"group": "apps", "resources": ["deployments"]}]},
                  {"level": "None"}],
    }))
    config = temporary / "kind-classification.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/saf-classification-audit.json
        readOnly: true
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-classification-audit.json
        - name: audit-log-path
          value: {AUDIT_LOG}
      extraVolumes:
        - name: classification-audit-policy
          hostPath: /etc/kubernetes/saf-classification-audit.json
          mountPath: /etc/kubernetes/saf-classification-audit.json
          readOnly: true
          pathType: File
        - name: classification-audit-log
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          pathType: DirectoryOrCreate
""")
    return config


def verify_audit_events(lab):
    policy_key = "saf-k8s-0702-005-deployment-template/classification-context"
    cases = {"valid-template-deployment": (201, "internal"),
             "green-template-deployment": (403, "missing")}
    seen = {name: [] for name in cases}
    end = time.monotonic() + 30
    while time.monotonic() < end:
        response = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "cat", AUDIT_LOG,
                               allow_failure=True)
        if response.returncode == 0:
            seen = {name: [] for name in cases}
            for line in response.stdout.splitlines():
                event = json.loads(line)
                context = event.get("annotations", {}).get(policy_key, "")
                for name, (_code, sensitivity) in cases.items():
                    expected = (f"kind=Deployment;namespace={NAMESPACE};name={name};"
                                f"workload-type=inference;data-sensitivity={sensitivity};model-tier=staging")
                    if context == expected:
                        seen[name].append(event)
            if all(seen.values()):
                break
        time.sleep(1)

    matched = {}
    sanitized = []
    for name, (code, _sensitivity) in cases.items():
        events = seen[name]
        event = events[0] if len(events) == 1 else {}
        ref = event.get("objectRef", {})
        matched[name] = (event.get("stage") == "ResponseComplete" and event.get("level") == "Metadata"
                         and event.get("verb") == "create" and ref.get("namespace") == NAMESPACE
                         and ref.get("resource") == "deployments" and bool(event.get("auditID"))
                         and event.get("responseStatus", {}).get("code") == code
                         and "requestObject" not in event and "responseObject" not in event)
        if matched[name]:
            sanitized.append({"name": name, "audit_id": event["auditID"],
                              "decision_code": code, "annotation": event["annotations"][policy_key]})
    lab.check("green", "The native audit backend records metadata-only classification for the allowed and denied Deployment requests",
              all(matched.values()), matched)
    (lab.evidence / "classification-audit-observations.json").write_text(
        json.dumps(sanitized, indent=2) + "\n")


def verify_quota_mapping(lab, quota):
    priority = "saf-lab-low"
    quota_name = "mapped-classification-pod-quota"
    quota["metadata"]["name"] = quota_name
    lab.create({"apiVersion": "scheduling.k8s.io/v1", "kind": "PriorityClass",
                "metadata": {"name": priority}, "value": 10, "preemptionPolicy": "Never"})
    quota["spec"]["hard"]["pods"] = "1"
    lab.kubectl("create", "-n", NAMESPACE, "-f", "-", "-o", "name", payload=json.dumps(quota))

    def used_pods():
        result = lab.kubectl("get", "resourcequota", quota_name, "-n", NAMESPACE, "-o", "json")
        return json.loads(result.stdout).get("status", {}).get("used", {}).get("pods")

    def wait_for_usage(expected):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if used_pods() == expected:
                return True
            time.sleep(0.5)
        return False

    if not wait_for_usage("0"):
        lab.block("The exact PriorityClass quota did not report zero initial use")
    restricted = {**LABELS, "ai.kais.io/data-sensitivity": "restricted"}
    bypass = pod_resource("restricted-without-class", restricted)
    result = server_create(lab, bypass)
    lab.check("red", "Before mapping policy the restricted label does not require the quota's PriorityClass",
              result.returncode == 0, {"accepted_without_priority_class": result.returncode == 0})

    policy = "saf-k8s-0702-005-classification-quota-mapping"
    message = "restricted classification requires the governed PriorityClass"
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": policy}, "spec": {
                    "failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                        "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"],
                        "resources": ["pods"]}]},
                    "validations": [{"expression":
                        '("ai.kais.io/data-sensitivity" in object.metadata.labels && '
                        'object.metadata.labels["ai.kais.io/data-sensitivity"] == "restricted") == '
                        f'(has(object.spec.priorityClassName) && object.spec.priorityClassName == "{priority}")',
                        "message": message, "reason": "Forbidden"}]}})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": policy}, "spec": {"policyName": policy, "validationActions": ["Deny"],
                    "matchResources": {"namespaceSelector": {"matchLabels": {
                        "saf-k8s.example/classification-enforcement": "required"}}}}})
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        result = server_create(lab, bypass)
        if result.returncode and message in result.stderr:
            break
        time.sleep(0.5)
    lab.check("green", "Classification mapping policy denies the same restricted request without the quota's PriorityClass",
              result.returncode != 0 and message in result.stderr,
              {"mapping_denied": result.returncode != 0 and message in result.stderr})

    admitted = pod_resource("restricted-quota-holder", restricted)
    admitted["spec"]["priorityClassName"] = priority
    admitted["spec"]["schedulingGates"] = [{"name": "saf-k8s.example/hold-quota-fixture"}]
    result = lab.kubectl("create", "-n", NAMESPACE, "-f", "-", "-o", "json",
                         payload=json.dumps(admitted))
    effective = json.loads(result.stdout)["spec"].get("priorityClassName") == priority
    matched_usage = wait_for_usage("1")
    lab.check("green", "The classified Pod enters the supported PriorityClass quota and consumes its sole unit",
              effective and matched_usage, {"effective_priority_class": effective,
                                            "scoped_quota_used": 1 if matched_usage else None})

    overage = pod_resource("restricted-quota-overage", restricted)
    overage["spec"]["priorityClassName"] = priority
    denied_by_quota = server_create(lab, overage)
    permitted = server_create(lab, pod_resource("public-no-quota", {**LABELS,
                              "ai.kais.io/data-sensitivity": "public"}))
    quota_refusal = (denied_by_quota.returncode != 0
                     and "exceeded quota" in denied_by_quota.stderr.lower()
                     and quota_name in denied_by_quota.stderr)
    lab.check("positive", "The quota denies a second classified Pod and the public comparator remains admissible",
              quota_refusal and permitted.returncode == 0 and used_pods() == "1",
              {"scoped_quota_refused": quota_refusal, "public_allowed": permitted.returncode == 0})


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s.example/classification-enforcement=required")
    unselected_namespace = f"{NAMESPACE}-general"
    lab.kubectl("create", "namespace", unselected_namespace)
    lab.kubectl("label", "namespace", unselected_namespace,
                "saf-k8s.example/classification-enforcement=not-required")

    probes = []
    for key in LABELS:
        absent = dict(LABELS)
        del absent[key]
        probes.append((key, "absent", pod_resource(f"red-absent-{len(probes)}", absent)))
        wrong = dict(LABELS)
        wrong[key] = "unapproved"
        probes.append((key, "wrong", pod_resource(f"red-wrong-{len(probes)}", wrong)))

    red = [(key, variant, server_create(lab, resource))
           for key, variant, resource in probes]
    lab.check(
        "red", "Without the policy the API accepts each absent and wrong category probe",
        all(result.returncode == 0 for _, _, result in red),
        [{"category": key, "variant": variant, "accepted": result.returncode == 0,
          "detail": result.stderr.strip()} for key, variant, result in red],
    )

    template_create_probes = []
    for kind in ("Job", "Deployment", "StatefulSet"):
        labels = dict(LABELS)
        del labels["ai.kais.io/data-sensitivity"]
        template_create_probes.append((kind, server_create(
            lab, template_resource(kind, f"red-template-{kind.lower()}", labels))))
    lab.check("red", "Before template policies, incomplete Job/Deployment/StatefulSet templates are admitted",
              all(result.returncode == 0 for _, result in template_create_probes),
              {kind: {"accepted": result.returncode == 0, "detail": result.stderr.strip()}
               for kind, result in template_create_probes})

    create_controller_bases(lab)

    red_template_updates = []
    for kind, name in (("Job", "template-update-job"),
                       ("Deployment", "template-update-deployment"),
                       ("StatefulSet", "template-update-statefulset")):
        resource = existing_for_replace(lab, kind, name)
        resource["spec"]["template"]["metadata"]["labels"]["ai.kais.io/model-tier"] = "unapproved"
        red_template_updates.append((kind, server_replace(lab, kind, name, resource)))
    lab.check("red", "Before template policies, supported Job/Deployment/StatefulSet template updates accept classification drift",
              all(result.returncode == 0 for _, result in red_template_updates),
              {kind: {"accepted": result.returncode == 0, "detail": result.stderr.strip()}
               for kind, result in red_template_updates})

    lab.apply(HERE / "classification-policy.yaml")
    template_policy_names = apply_template_policies(lab)
    deadline = time.monotonic() + 20
    while True:
        green = [(key, variant, server_create(lab, resource))
                 for key, variant, resource in probes]
        if all(denied(result) for _, _, result in green) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check(
        "green", "The policy denies each absent and wrong category with its exact message",
        all(denied(result) for _, _, result in green),
        [{"category": key, "variant": variant, "denied_by_policy": denied(result),
          "detail": result.stderr.strip()} for key, variant, result in green],
    )

    missing_sensitivity = {key: value for key, value in LABELS.items()
                           if key != "ai.kais.io/data-sensitivity"}
    kinds = ("Job", "Deployment", "StatefulSet")
    unready = set(kinds)
    deadline = time.monotonic() + 30
    while unready and time.monotonic() < deadline:
        for kind in sorted(unready):
            witness = server_create(lab, template_resource(
                kind, f"policy-ready-{kind.lower()}", missing_sensitivity))
            if denied(witness):
                unready.remove(kind)
        if unready:
            time.sleep(0.5)
    if unready:
        lab.block("Classification admission did not propagate to " + ", ".join(sorted(unready)))

    green_templates = [(kind, server_create(
        lab, template_resource(kind, f"green-template-{kind.lower()}",
                               {key: value for key, value in LABELS.items()
                                if key != "ai.kais.io/data-sensitivity"})))
        for kind in ("Job", "Deployment", "StatefulSet")]
    lab.check("green", "Enrolled namespace template policies deny incomplete controller Pod templates",
              all(denied(result) for _, result in green_templates),
              {kind: {"denied_by_policy": denied(result), "detail": result.stderr.strip()}
               for kind, result in green_templates})

    update_probes = []
    for kind, name in (("Job", "template-update-job"),
                       ("Deployment", "template-update-deployment"),
                       ("StatefulSet", "template-update-statefulset")):
        resource = existing_for_replace(lab, kind, name)
        resource["spec"]["template"]["metadata"]["labels"]["ai.kais.io/model-tier"] = "unapproved"
        update_probes.append((kind, server_replace(lab, kind, name, resource)))
    lab.check("green", "Suspended Job, Deployment and StatefulSet template updates reject classification drift",
              all(denied(result) for _, result in update_probes),
              {kind: {"denied_by_policy": denied(result), "detail": result.stderr.strip()}
               for kind, result in update_probes})

    admitted_values = {}
    for category, values in VALUES.items():
        admitted_values[category] = []
        for value in values:
            result = server_create(lab, pod_resource("permitted-value", {**LABELS, category: value}))
            if result.returncode == 0:
                admitted_values[category].append(value)
    lab.check("positive", "Every enumerated value remains admissible in its own category",
              admitted_values == VALUES, admitted_values)

    valid_controller_creates = [(kind, server_create(
        lab, template_resource(kind, f"valid-template-{kind.lower()}", LABELS)))
        for kind in ("Job", "Deployment", "StatefulSet")]
    lab.check("positive", "Governed Job, Deployment and StatefulSet templates remain admissible",
              all(result.returncode == 0 for _, result in valid_controller_creates),
              {kind: {"accepted": result.returncode == 0, "detail": result.stderr.strip()}
               for kind, result in valid_controller_creates})

    valid_updates = []
    for kind, name in (("Deployment", "template-update-deployment"),
                       ("StatefulSet", "template-update-statefulset")):
        resource = existing_for_replace(lab, kind, name)
        resource["spec"]["template"]["metadata"].setdefault("annotations", {})[
            "saf-k8s.example/fixture-update"] = "preserve-classification"
        valid_updates.append((kind, server_replace(lab, kind, name, resource)))
    lab.check("positive", "Classification-preserving Deployment and StatefulSet template updates remain admissible",
              all(result.returncode == 0 for _, result in valid_updates),
              {kind: {"accepted": result.returncode == 0, "detail": result.stderr.strip()}
               for kind, result in valid_updates})

    unselected_probes = [(kind, server_create(
        lab, template_resource(kind, f"unselected-{kind.lower()}", {}, unselected_namespace),
        unselected_namespace)) for kind in ("Job", "Deployment", "StatefulSet")]
    lab.check("positive", "The template policy bindings leave the explicitly unselected namespace outside this fixture rule",
              all(result.returncode == 0 for _, result in unselected_probes),
              {kind: {"accepted": result.returncode == 0, "detail": result.stderr.strip()}
               for kind, result in unselected_probes})

    audit_declarations = controller_policy_audit_declared(lab, template_policy_names)
    lab.check("positive", "Pod and controller policies declare non-sensitive classification audit correlation",
              all(audit_declarations.values()), audit_declarations)
    verify_audit_events(lab)

    valid = pod_resource("permitted-inference", LABELS)
    valid["metadata"]["labels"]["saf-k8s.example/case"] = "0702-005"
    admitted = lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "json",
                           payload=json.dumps(valid), allow_failure=True)
    lab.check("positive", "A permitted governed inference Pod is admitted",
              admitted.returncode == 0,
              admitted.stderr.strip() or "created")

    other_labels = dict(LABELS)
    other_labels["ai.kais.io/workload-type"] = "training"
    other = pod_resource("permitted-training", other_labels)
    other["metadata"]["labels"]["saf-k8s.example/case"] = "0702-005"
    other_result = lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "json",
                               payload=json.dumps(other), allow_failure=True)
    lab.check("positive", "A second benign governed class is admitted",
              other_result.returncode == 0,
              other_result.stderr.strip() or "created")

    selected = lab.kubectl(
        "-n", NAMESPACE, "get", "pods", "-l", "ai.kais.io/workload-type=inference",
        "-o", "json",
    )
    selected_names = sorted(item["metadata"]["name"]
                            for item in json.loads(selected.stdout)["items"])
    lab.check(
        "positive", "A native label selector supports benign classification inventory",
        selected_names == ["permitted-inference"],
        {"selector": "ai.kais.io/workload-type=inference", "selected": selected_names},
    )

    custom_quota = {
        "apiVersion": "v1", "kind": "ResourceQuota",
        "metadata": {"name": "classification-quota", "namespace": NAMESPACE},
        "spec": {"hard": {"pods": "3"}, "scopeSelector": {"matchExpressions": [{
            "scopeName": "ai.kais.io/workload-type", "operator": "In",
            "values": ["inference"],
        }]}},
    }
    quota_result = lab.kubectl("-n", NAMESPACE, "create", "-f", "-",
                               payload=json.dumps(custom_quota), allow_failure=True)
    quota_error = quota_result.stderr.strip()
    lab.check(
        "green", "The API rejects a custom classification label as a ResourceQuota scope",
        quota_result.returncode != 0 and "ai.kais.io/workload-type" in quota_error
        and "unsupported scope" in quota_error.lower(),
        {"rejected": quota_result.returncode != 0, "detail": quota_error},
    )

    supported_quota = {
        "apiVersion": "v1", "kind": "ResourceQuota",
        "metadata": {"name": "priority-class-quota", "namespace": NAMESPACE},
        "spec": {"hard": {"pods": "3"}, "scopeSelector": {"matchExpressions": [{
            "scopeName": "PriorityClass", "operator": "In", "values": ["saf-lab-low"],
        }]}},
    }
    supported_result = lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "json",
                                   payload=json.dumps(supported_quota), allow_failure=True)
    lab.check("positive", "The same API accepts a built-in PriorityClass quota scope",
              supported_result.returncode == 0,
              supported_result.stderr.strip() or "created")

    verify_quota_mapping(lab, supported_quota)
