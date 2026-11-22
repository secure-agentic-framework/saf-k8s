"""Check native API audit coverage for synthetic authorization/admission decisions.

The case uses only local, disposable kind clusters and API objects created here.
Selected audit bodies are retained only for inert Role and SubjectAccessReview fixtures.
"""

from urllib.parse import parse_qs, urlsplit
import json
import time


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
AUDIT_DIR_IN_NODE = "/var/log/kubernetes/audit"
AUDIT_LOG = f"{AUDIT_DIR_IN_NODE}/audit.log"
NAMESPACE = "saf-test"
OMITTED_NAMESPACE = "saf-audit-omitted"
WRITER = "saf-lab:writer"
OBSERVER = "saf-lab:observer"
POLICY = "saf-lab-configmap-decision"
BINDING = "saf-lab-configmap-decision-binding"

SCOPE = (
    "Kubernetes v1.36.1 kube-apiserver file audit backend on the runner's fresh, "
    "single-control-plane kind cluster. Synthetic impersonated users issue harmless "
    "ConfigMap create requests. The audit policy selects ConfigMaps in saf-test and "
    "omits saf-audit-omitted; checks distinguish HTTP status, audit annotations, "
    "and persisted API effects. Records exact native SubjectAccessReview and Role creation at Request level. "
    "Real metrics, other privileged APIs, and production coverage require separate evidence."
)


def prepare_kind(lab, temporary):
    """Mount a selected audit policy and writable synthetic audit log directory."""
    policy_file = temporary / "audit-policy.yaml"
    audit_dir = temporary / "audit"
    audit_dir.mkdir()
    policy_file.write_text(
        "apiVersion: audit.k8s.io/v1\n"
        "kind: Policy\n"
        "omitStages: [RequestReceived]\n"
        "rules:\n"
        "  - level: Metadata\n"
        "    verbs: [create]\n"
        "    resources:\n"
        "      - group: \"\"\n"
        "        resources: [configmaps]\n"
        f"    namespaces: [{NAMESPACE}]\n"
        "  - level: Request\n"
        "    verbs: [create]\n"
        "    resources:\n"
        "      - group: authorization.k8s.io\n"
        "        resources: [subjectaccessreviews]\n"
        "      - group: rbac.authorization.k8s.io\n"
        "        resources: [roles]\n"
        "  - level: None\n"
    )
    config_file = temporary / "kind-audit.yaml"
    config_file.write_text(
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n"
        "  - role: control-plane\n"
        "    extraMounts:\n"
        f"      - hostPath: {json.dumps(str(policy_file))}\n"
        "        containerPath: /etc/kubernetes/audit-policy.yaml\n"
        "        readOnly: true\n"
        f"      - hostPath: {json.dumps(str(audit_dir))}\n"
        f"        containerPath: {AUDIT_DIR_IN_NODE}\n"
        "        readOnly: false\n"
        "kubeadmConfigPatches:\n"
        "  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    apiServer:\n"
        "      extraArgs:\n"
        "        - name: audit-policy-file\n"
        "          value: /etc/kubernetes/audit-policy.yaml\n"
        f"        - name: audit-log-path\n          value: {AUDIT_LOG}\n"
        "      extraVolumes:\n"
        "        - name: audit-policy\n"
        "          hostPath: /etc/kubernetes/audit-policy.yaml\n"
        "          mountPath: /etc/kubernetes/audit-policy.yaml\n"
        "          readOnly: true\n"
        "          pathType: File\n"
        "        - name: audit-log\n"
        f"          hostPath: {AUDIT_DIR_IN_NODE}\n"
        f"          mountPath: {AUDIT_DIR_IN_NODE}\n"
        "          readOnly: false\n"
        "          pathType: DirectoryOrCreate\n"
    )
    return config_file


def kubectl_args(lab, namespace=NAMESPACE, user=None):
    args = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", f"--namespace={namespace}", "--request-timeout=30s",
    ]
    if user:
        args.append(f"--as={user}")
    return args


def resource(name, decision):
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {"audit.saf.test/decision": decision},
        },
        "data": {"fixture": "synthetic"},
    }


def setup(lab):
    lab.kubectl("label", "namespace", NAMESPACE, "audit-saf-test=selected", "--overwrite")
    lab.kubectl("create", "namespace", OMITTED_NAMESPACE)

    # The synthetic writer can create ConfigMaps only in the selected namespace.
    for namespace in (NAMESPACE,):
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "saf-lab-configmap-writer", "namespace": namespace},
            "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}],
        }
        binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": "saf-lab-configmap-writer", "namespace": namespace},
            "subjects": [{"kind": "User", "name": WRITER, "apiGroup": "rbac.authorization.k8s.io"}],
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                        "name": "saf-lab-configmap-writer"},
        }
        lab.kubectl("create", "-f", "-", payload=json.dumps(role))
        lab.kubectl("create", "-f", "-", payload=json.dumps(binding))

    admission = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"],
                "operations": ["CREATE"], "resources": ["configmaps"],
            }]},
            "matchConditions": [{"name": "marked-fixture",
                                 "expression": "has(object.metadata.labels) && 'audit.saf.test/decision' in object.metadata.labels"}],
            "validations": [{
                "expression": "object.metadata.labels['audit.saf.test/decision'] != 'deny'",
                "message": "synthetic decision label denied by local lab policy",
                "reason": "Forbidden",
            }],
            "auditAnnotations": [{
                "key": "probe-decision",
                "valueExpression": "string(object.metadata.labels['audit.saf.test/decision'])",
            }],
        },
    }
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": BINDING},
        "spec": {
            "policyName": POLICY,
            "validationActions": ["Deny", "Audit"],
            "matchResources": {"namespaceSelector": {"matchLabels": {"audit-saf-test": "selected"}}},
        },
    }
    lab.kubectl("create", "-f", "-", payload=json.dumps(admission))
    lab.kubectl("create", "-f", "-", payload=json.dumps(binding))


def post(lab, namespace, user, obj, marker):
    return lab.command(*kubectl_args(lab, namespace, user), "create", "--validate=false", "-f", "-", "-o", "json",
                       f"--field-manager={marker}", payload=json.dumps(obj), allow_failure=True)


def observed_events(lab):
    audit = lab.kubeconfig.parent / "audit/audit.log"
    events = {}
    if not audit.is_file():
        return events
    for line in audit.read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("stage") != "ResponseComplete" or event.get("verb") != "create":
            continue
        markers = parse_qs(urlsplit(event["requestURI"]).query).get("fieldManager", [])
        for marker in markers:
            if marker.startswith("saf-proof-"):
                if marker in events:
                    lab.block(f"Unexpected duplicate audited request for {marker}")
                events[marker] = event
    return events


def wait_for_events(lab, expected):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        events = observed_events(lab)
        if expected <= events.keys():
            return events
        time.sleep(0.2)
    return observed_events(lab)


def get_fixture(lab, name):
    result = lab.kubectl("get", "configmap", name, "--ignore-not-found", "-o", "json")
    return json.loads(result.stdout) if result.stdout.strip() else None


def stable_outcome(event):
    if not event:
        return {}
    annotations = event.get("annotations", {})
    actor = event.get("impersonatedUser", event.get("user", {}))
    validation = json.loads(annotations.get("validation.policy.admission.k8s.io/validation_failure", "[]"))
    return {
        "identity": actor.get("username"),
        "http_code": event.get("responseStatus", {}).get("code"),
        "level": event.get("level"),
        "authorization": annotations.get("authorization.k8s.io/decision"),
        "authorization_reason_present": bool(annotations.get("authorization.k8s.io/reason")),
        "admission_value": annotations.get(f"{POLICY}/probe-decision"),
        "admission_policy_and_binding": any(row.get("policy") == POLICY and row.get("binding") == BINDING
                                            for row in validation),
        "body_present": "requestObject" in event,
        "response_body_present": "responseObject" in event,
    }


def run(lab):
    setup(lab)
    readiness = resource("saf-verify-policy-ready", "deny")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        ready = lab.command(*kubectl_args(lab, NAMESPACE, WRITER), "create", "--validate=false",
                            "-f", "-", "--dry-run=server", payload=json.dumps(readiness), allow_failure=True)
        if ready.returncode and "synthetic decision label denied" in ready.stderr:
            break
        time.sleep(0.4)
    else:
        lab.block("The fixture validating admission policy did not become active")

    omitted_obj = resource("saf-omitted-scope", "allow")
    omitted_obj["metadata"]["namespace"] = OMITTED_NAMESPACE
    requested = {
        "omitted": post(lab, OMITTED_NAMESPACE, OBSERVER, omitted_obj, "saf-proof-omitted"),
        "authorization": post(lab, NAMESPACE, OBSERVER, resource("saf-authz-denied", "allow"),
                              "saf-proof-authorization"),
        "admission": post(lab, NAMESPACE, WRITER, resource("saf-admission-denied", "deny"),
                          "saf-proof-admission"),
        "allowed": post(lab, NAMESPACE, WRITER, resource("saf-positive", "allow"), "saf-proof-allowed"),
    }
    probe = {
        "resourceAttributes": {"namespace": NAMESPACE, "verb": "create", "group": "", "resource": "configmaps"},
        "user": OBSERVER,
    }
    review = {"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": probe}
    requested["review"] = post(lab, NAMESPACE, None, review, "saf-proof-review")
    role_rules = [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]
    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "saf-proof-observation-role", "namespace": NAMESPACE}, "rules": role_rules}
    requested["role"] = post(lab, NAMESPACE, None, role, "saf-proof-role")

    expected = {"saf-proof-" + label for label in requested if label != "omitted"}
    events = wait_for_events(lab, expected)
    api = {label: {"returncode": result.returncode, "stderr": result.stderr,
                   "stdout": result.stdout} for label, result in requested.items()}
    (lab.evidence / "selected-audit-events.json").write_text(json.dumps(events, indent=2) + "\n")
    (lab.evidence / "synthetic-api-responses.json").write_text(json.dumps(api, indent=2) + "\n")
    absence = "saf-proof-omitted" not in events
    lab.check("red", "A denied create outside the selected audit namespace leaves no selected audit event",
              requested["omitted"].returncode == 1 and "(Forbidden)" in requested["omitted"].stderr
              and OBSERVER in requested["omitted"].stderr and absence,
              {"http_outcome": "Forbidden", "event_absent": absence})


    auth = stable_outcome(events.get("saf-proof-authorization"))
    adm = stable_outcome(events.get("saf-proof-admission"))
    allow = stable_outcome(events.get("saf-proof-allowed"))
    expected_base = {"http_code": 403, "level": "Metadata", "authorization_reason_present": True,
                     "body_present": False, "response_body_present": False}
    expected_auth = expected_base | {"identity": OBSERVER, "authorization": "forbid",
                                    "authorization_reason_present": False,
                                    "admission_value": None, "admission_policy_and_binding": False}
    expected_adm = expected_base | {"identity": WRITER, "authorization": "allow",
                                   "admission_value": "deny", "admission_policy_and_binding": True}
    no_authz_object = get_fixture(lab, "saf-authz-denied") is None
    no_admission_object = get_fixture(lab, "saf-admission-denied") is None
    lab.check("green", "Audit attributes authorization denial and admission denial to their distinct enforcement points",
              auth == expected_auth and adm == expected_adm and no_authz_object and no_admission_object
              and requested["authorization"].returncode == requested["admission"].returncode == 1
              and OBSERVER in requested["authorization"].stderr and POLICY in requested["admission"].stderr,
              {"authorization": auth, "admission": adm, "authorization_not_persisted": no_authz_object,
               "admission_not_persisted": no_admission_object})

    expected_allow = expected_base | {"identity": WRITER, "http_code": 201, "authorization": "allow",
                                     "admission_value": "allow", "admission_policy_and_binding": False}
    stored = get_fixture(lab, "saf-positive")
    lab.check("positive", "The allowed scoped create persists and records both authorization and admission",
              allow == expected_allow and requested["allowed"].returncode == 0
              and stored is not None and stored["data"] == {"fixture": "synthetic"},
              {"audit": allow, "marker_stored": stored is not None})

    reviewed = events.get("saf-proof-review", {})
    role_event = events.get("saf-proof-role", {})
    answer = json.loads(requested["review"].stdout)["status"] if requested["review"].returncode == 0 else {}
    role_accepted = requested["role"].returncode == 0
    sar_body = reviewed.get("requestObject", {}).get("spec", {})
    if "resourceAttributes" in sar_body:
        sar_body["resourceAttributes"].setdefault("group", "")
    observed_sar = {"level": reviewed.get("level"), "review_denied_subject": answer.get("allowed") is False,
                    "request_spec_matches": all(sar_body.get(key) == value for key, value in probe.items()),
                    "response_body_present": "responseObject" in reviewed}
    observed_role = {"level": role_event.get("level"), "role_accepted": role_accepted,
                     "request_rules_match": role_event.get("requestObject", {}).get("rules") == role_rules,
                     "response_body_present": "responseObject" in role_event}
    lab.check("green", "Request audit retains the exact privileged Role write and SubjectAccessReview inputs",
              observed_sar == {"level": "Request", "review_denied_subject": True,
                               "request_spec_matches": True, "response_body_present": False}
              and observed_role == {"level": "Request", "role_accepted": True,
                                    "request_rules_match": True, "response_body_present": False},
              {"subject_access_review": observed_sar, "role": observed_role})
