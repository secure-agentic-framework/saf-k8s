"""Check native audit coverage for synthetic authorization/admission and metrics decisions.

The case uses only local, disposable kind clusters and API objects created here.
Selected audit bodies are retained only for inert Role and SubjectAccessReview fixtures.
"""

from urllib.parse import parse_qs, urlsplit
import base64
import hashlib
import json
from pathlib import Path
import time


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:" "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
AUDIT_DIR_IN_NODE = "/var/log/kubernetes/audit"
AUDIT_LOG = f"{AUDIT_DIR_IN_NODE}/audit.log"
NAMESPACE = "saf-test"
OMITTED_NAMESPACE = "saf-audit-omitted"
WRITER = "saf-lab:writer"
OBSERVER = "saf-lab:observer"
POLICY = "saf-lab-configmap-decision"
BINDING = "saf-lab-configmap-decision-binding"
METRICS_URL = "https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.8.1/components.yaml"
METRICS_SHA256 = "4a672c4891902573a3ff753cece5de1bf1f55dd053403dfec39df9d1636b7ff1"
METRICS_IMAGE = "registry.k8s.io/metrics-server/metrics-server@sha256:b2d2efaf5ac3b366ed0f839d2412a2c4279d4fc2a2a733f12c52133faed36c41"
METRICS_POD = "saf-metrics-fixture"
METRICS_READER = "saf-lab:metrics-reader"
METRICS_DENIED = "saf-lab:metrics-denied"
WEBHOOK_WRITER = "saf-lab:webhook-writer"
KUBELET_CERT_DIR = "/etc/kubernetes/saf-metrics-kubelet-tls"
METRICS_NS = "kube-system"
METRICS_API = "v1beta1.metrics.k8s.io"

SCOPE = (
    "Kubernetes v1.36.1 kube-apiserver file audit backend on the runner's fresh, "
    "single-control-plane kind cluster. Synthetic impersonated users issue harmless "
    "ConfigMap create requests, a named PodMetrics resource, and a synthetic HTTPS webhook. "
    "The audit policy selects ConfigMaps and metrics.k8s.io pods in saf-test and omits "
    "saf-audit-omitted; checks distinguish HTTP status, audit annotations, and persisted API effects. "
    "Records exact native SubjectAccessReview and Role creation at Request level."
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
        '      - group: ""\n'
        "        resources: [configmaps]\n"
        f"    namespaces: [{NAMESPACE}]\n"
        "  - level: Metadata\n"
        "    verbs: [get]\n"
        "    resources:\n"
        "      - group: metrics.k8s.io\n"
        "        resources: [pods]\n"
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
    serving = temporary / "kubelet"
    serving.mkdir(mode=0o700)
    create_fixture_tls(lab, serving, f"{lab.cluster}-control-plane")
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
        f"      - hostPath: {json.dumps(str(serving))}\n"
        f"        containerPath: {KUBELET_CERT_DIR}\n"
        "        readOnly: true\n"
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
        "  - |\n"
        "    apiVersion: kubelet.config.k8s.io/v1beta1\n"
        "    kind: KubeletConfiguration\n"
        "    serverTLSBootstrap: false\n"
        f"    tlsCertFile: {KUBELET_CERT_DIR}/tls.crt\n"
        f"    tlsPrivateKeyFile: {KUBELET_CERT_DIR}/tls.key\n"
    )
    return config_file


def kubectl_args(lab, namespace=NAMESPACE, user=None):
    args = [
        "kubectl",
        "--kubeconfig",
        str(lab.kubeconfig),
        "--context",
        f"kind-{lab.cluster}",
        f"--namespace={namespace}",
        "--request-timeout=30s",
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
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "saf-lab-configmap-writer", "namespace": namespace},
            "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}],
        }
        binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "saf-lab-configmap-writer", "namespace": namespace},
            "subjects": [{"kind": "User", "name": WRITER, "apiGroup": "rbac.authorization.k8s.io"}],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "saf-lab-configmap-writer",
            },
        }
        lab.kubectl("create", "-f", "-", payload=json.dumps(role))
        lab.kubectl("create", "-f", "-", payload=json.dumps(binding))

    admission = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [
                    {
                        "apiGroups": [""],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE"],
                        "resources": ["configmaps"],
                    }
                ]
            },
            "matchConditions": [
                {
                    "name": "marked-fixture",
                    "expression": "has(object.metadata.labels) && 'audit.saf.test/decision' in object.metadata.labels",
                }
            ],
            "validations": [
                {
                    "expression": "object.metadata.labels['audit.saf.test/decision'] != 'deny'",
                    "message": "synthetic decision label denied by local lab policy",
                    "reason": "Forbidden",
                }
            ],
            "auditAnnotations": [
                {
                    "key": "probe-decision",
                    "valueExpression": "string(object.metadata.labels['audit.saf.test/decision'])",
                }
            ],
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
    return lab.command(
        *kubectl_args(lab, namespace, user),
        "create",
        "--validate=false",
        "-f",
        "-",
        "-o",
        "json",
        f"--field-manager={marker}",
        payload=json.dumps(obj),
        allow_failure=True,
    )


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
    validation = json.loads(
        annotations.get("validation.policy.admission.k8s.io/validation_failure", "[]")
    )
    return {
        "identity": actor.get("username"),
        "http_code": event.get("responseStatus", {}).get("code"),
        "level": event.get("level"),
        "authorization": annotations.get("authorization.k8s.io/decision"),
        "authorization_reason_present": bool(annotations.get("authorization.k8s.io/reason")),
        "admission_value": annotations.get(f"{POLICY}/probe-decision"),
        "admission_policy_and_binding": any(
            row.get("policy") == POLICY and row.get("binding") == BINDING for row in validation
        ),
        "body_present": "requestObject" in event,
        "response_body_present": "responseObject" in event,
    }


def run(lab):
    setup(lab)
    readiness = resource("saf-verify-policy-ready", "deny")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        ready = lab.command(
            *kubectl_args(lab, NAMESPACE, WRITER),
            "create",
            "--validate=false",
            "-f",
            "-",
            "--dry-run=server",
            payload=json.dumps(readiness),
            allow_failure=True,
        )
        if ready.returncode and "synthetic decision label denied" in ready.stderr:
            break
        time.sleep(0.4)
    else:
        lab.block("The fixture validating admission policy did not become active")

    omitted_obj = resource("saf-omitted-scope", "allow")
    omitted_obj["metadata"]["namespace"] = OMITTED_NAMESPACE
    requested = {
        "omitted": post(lab, OMITTED_NAMESPACE, OBSERVER, omitted_obj, "saf-proof-omitted"),
        "authorization": post(
            lab, NAMESPACE, OBSERVER, resource("saf-authz-denied", "allow"), "saf-proof-authorization"
        ),
        "admission": post(
            lab, NAMESPACE, WRITER, resource("saf-admission-denied", "deny"), "saf-proof-admission"
        ),
        "allowed": post(lab, NAMESPACE, WRITER, resource("saf-positive", "allow"), "saf-proof-allowed"),
    }
    probe = {
        "resourceAttributes": {
            "namespace": NAMESPACE,
            "verb": "create",
            "group": "",
            "resource": "configmaps",
        },
        "user": OBSERVER,
    }
    review = {"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": probe}
    requested["review"] = post(lab, NAMESPACE, None, review, "saf-proof-review")
    role_rules = [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "saf-proof-observation-role", "namespace": NAMESPACE},
        "rules": role_rules,
    }
    requested["role"] = post(lab, NAMESPACE, None, role, "saf-proof-role")

    expected = {"saf-proof-" + label for label in requested if label != "omitted"}
    events = wait_for_events(lab, expected)
    api = {
        label: {"returncode": result.returncode, "stderr": result.stderr, "stdout": result.stdout}
        for label, result in requested.items()
    }
    (lab.evidence / "selected-audit-events.json").write_text(json.dumps(events, indent=2) + "\n")
    (lab.evidence / "synthetic-api-responses.json").write_text(json.dumps(api, indent=2) + "\n")
    absence = "saf-proof-omitted" not in events
    lab.check(
        "red",
        "A denied create outside the selected audit namespace leaves no selected audit event",
        requested["omitted"].returncode == 1
        and "(Forbidden)" in requested["omitted"].stderr
        and OBSERVER in requested["omitted"].stderr
        and absence,
        {"http_outcome": "Forbidden", "event_absent": absence},
    )

    auth = stable_outcome(events.get("saf-proof-authorization"))
    adm = stable_outcome(events.get("saf-proof-admission"))
    allow = stable_outcome(events.get("saf-proof-allowed"))
    expected_base = {
        "http_code": 403,
        "level": "Metadata",
        "authorization_reason_present": True,
        "body_present": False,
        "response_body_present": False,
    }
    expected_auth = expected_base | {
        "identity": OBSERVER,
        "authorization": "forbid",
        "authorization_reason_present": False,
        "admission_value": None,
        "admission_policy_and_binding": False,
    }
    expected_adm = expected_base | {
        "identity": WRITER,
        "authorization": "allow",
        "admission_value": "deny",
        "admission_policy_and_binding": True,
    }
    no_authz_object = get_fixture(lab, "saf-authz-denied") is None
    no_admission_object = get_fixture(lab, "saf-admission-denied") is None
    lab.check(
        "green",
        "Audit attributes authorization denial and admission denial to their distinct enforcement points",
        auth == expected_auth
        and adm == expected_adm
        and no_authz_object
        and no_admission_object
        and requested["authorization"].returncode == requested["admission"].returncode == 1
        and OBSERVER in requested["authorization"].stderr
        and POLICY in requested["admission"].stderr,
        {
            "authorization": auth,
            "admission": adm,
            "authorization_not_persisted": no_authz_object,
            "admission_not_persisted": no_admission_object,
        },
    )

    expected_allow = expected_base | {
        "identity": WRITER,
        "http_code": 201,
        "authorization": "allow",
        "admission_value": "allow",
        "admission_policy_and_binding": False,
    }
    stored = get_fixture(lab, "saf-positive")
    lab.check(
        "positive",
        "The allowed scoped create persists and records both authorization and admission",
        allow == expected_allow
        and requested["allowed"].returncode == 0
        and stored is not None
        and stored["data"] == {"fixture": "synthetic"},
        {"audit": allow, "marker_stored": stored is not None},
    )

    reviewed = events.get("saf-proof-review", {})
    role_event = events.get("saf-proof-role", {})
    answer = (
        json.loads(requested["review"].stdout)["status"] if requested["review"].returncode == 0 else {}
    )
    role_accepted = requested["role"].returncode == 0
    sar_body = reviewed.get("requestObject", {}).get("spec", {})
    if "resourceAttributes" in sar_body:
        sar_body["resourceAttributes"].setdefault("group", "")
    observed_sar = {
        "level": reviewed.get("level"),
        "review_denied_subject": answer.get("allowed") is False,
        "request_spec_matches": all(sar_body.get(key) == value for key, value in probe.items()),
        "response_body_present": "responseObject" in reviewed,
    }
    observed_role = {
        "level": role_event.get("level"),
        "role_accepted": role_accepted,
        "request_rules_match": role_event.get("requestObject", {}).get("rules") == role_rules,
        "response_body_present": "responseObject" in role_event,
    }
    lab.check(
        "green",
        "Request audit retains the exact privileged Role write and SubjectAccessReview inputs",
        observed_sar
        == {
            "level": "Request",
            "review_denied_subject": True,
            "request_spec_matches": True,
            "response_body_present": False,
        }
        and observed_role
        == {
            "level": "Request",
            "role_accepted": True,
            "request_rules_match": True,
            "response_body_present": False,
        },
        {"subject_access_review": observed_sar, "role": observed_role},
    )

    run_metrics_and_webhook(lab)


def _record(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def create_fixture_tls(lab, directory, service):
    directory.mkdir(mode=0o700, exist_ok=True)
    root_key, root_crt = directory / "ca.key", directory / "ca.crt"
    leaf_key, leaf_crt = directory / "tls.key", directory / "tls.crt"
    request, config = directory / "leaf.csr", directory / "openssl.conf"
    config.write_text(
        "[req]\ndistinguished_name=dn\n[dn]\n"
        "[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
        "[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{service}\n"
    )
    lab.command(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-sha256",
        "-config",
        str(config),
        "-extensions",
        "ca",
        "-subj",
        f"/CN=SAF fixture CA for {service}",
        "-keyout",
        str(root_key),
        "-out",
        str(root_crt),
    )
    root_key.chmod(0o600)
    try:
        lab.command(
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-config",
            str(config),
            "-subj",
            f"/CN={service}",
            "-keyout",
            str(leaf_key),
            "-out",
            str(request),
        )
        leaf_key.chmod(0o600)
        lab.command(
            "openssl",
            "x509",
            "-req",
            "-in",
            str(request),
            "-CA",
            str(root_crt),
            "-CAkey",
            str(root_key),
            "-set_serial",
            "1",
            "-days",
            "1",
            "-sha256",
            "-extfile",
            str(config),
            "-extensions",
            "leaf",
            "-out",
            str(leaf_crt),
        )
    finally:
        root_key.unlink()


def _install_metrics_server(lab, temporary):
    path = temporary / "metrics-server-components.yaml"
    lab.command(
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        METRICS_URL,
        "-o",
        str(path),
        timeout=85,
    )
    manifest = path.read_bytes()
    digest = hashlib.sha256(manifest).hexdigest()
    old_image = "registry.k8s.io/metrics-server/metrics-server:v0.8.1"
    text = manifest.decode("utf-8")
    if digest != METRICS_SHA256 or text.count(old_image) != 1:
        lab.block("Metrics Server installer differs from the reviewed v0.8.1 release")
    path.write_text(text.replace(old_image, METRICS_IMAGE))
    _record(
        lab, "metrics-server-source.json", {"url": METRICS_URL, "sha256": digest, "image": METRICS_IMAGE}
    )
    node = f"{lab.cluster}-control-plane"
    node_obj = json.loads(lab.kubectl("get", "node", node, "-o", "json").stdout)
    ipv4 = next(
        address["address"]
        for address in node_obj["status"]["addresses"]
        if address["type"] == "InternalIP" and ":" not in address["address"]
    )
    kubelet_ca = temporary / "kubelet" / "ca.crt"
    metrics_tls = temporary / "metrics-api"
    create_fixture_tls(lab, metrics_tls, f"metrics-server.{METRICS_NS}.svc")
    lab.kubectl(
        "-n",
        METRICS_NS,
        "create",
        "configmap",
        "saf-metrics-kubelet-ca",
        f"--from-file=ca.crt={kubelet_ca}",
    )
    lab.kubectl(
        "-n",
        METRICS_NS,
        "create",
        "secret",
        "tls",
        "saf-metrics-api-tls",
        "--cert",
        str(metrics_tls / "tls.crt"),
        "--key",
        str(metrics_tls / "tls.key"),
    )
    lab.command(
        "kubectl",
        "--kubeconfig",
        str(lab.kubeconfig),
        "--context",
        f"kind-{lab.cluster}",
        "apply",
        "--server-side",
        "-f",
        str(path),
        timeout=90,
    )
    deployment = json.loads(
        lab.kubectl("-n", METRICS_NS, "get", "deployment", "metrics-server", "-o", "json").stdout
    )
    container = next(
        item
        for item in deployment["spec"]["template"]["spec"]["containers"]
        if item["name"] == "metrics-server"
    )
    args = [arg for arg in container["args"] if not arg.startswith("--kubelet-preferred-address-types")]
    args.extend(
        (
            "--kubelet-preferred-address-types=Hostname",
            "--kubelet-certificate-authority=/saf-kubelet-ca/ca.crt",
            "--tls-cert-file=/saf-metrics-api/tls.crt",
            "--tls-private-key-file=/saf-metrics-api/tls.key",
        )
    )
    patch = {
        "spec": {
            "template": {
                "spec": {
                    "hostAliases": [{"ip": ipv4, "hostnames": [node]}],
                    "volumes": [
                        {"name": "saf-kubelet-ca", "configMap": {"name": "saf-metrics-kubelet-ca"}},
                        {"name": "saf-metrics-api", "secret": {"secretName": "saf-metrics-api-tls"}},
                    ],
                    "containers": [
                        {
                            "name": "metrics-server",
                            "args": args,
                            "volumeMounts": [
                                {
                                    "name": "saf-kubelet-ca",
                                    "mountPath": "/saf-kubelet-ca",
                                    "readOnly": True,
                                },
                                {
                                    "name": "saf-metrics-api",
                                    "mountPath": "/saf-metrics-api",
                                    "readOnly": True,
                                },
                            ],
                        }
                    ],
                }
            }
        }
    }
    lab.kubectl(
        "-n",
        METRICS_NS,
        "patch",
        "deployment",
        "metrics-server",
        "--type=strategic",
        "-p",
        json.dumps(patch),
    )
    ca_bundle = base64.b64encode((metrics_tls / "ca.crt").read_bytes()).decode()
    trust = {"spec": {"insecureSkipTLSVerify": False, "caBundle": ca_bundle}}
    lab.kubectl("patch", "apiservice", METRICS_API, "--type=merge", "-p", json.dumps(trust))
    lab.kubectl(
        "-n", METRICS_NS, "rollout", "status", "deployment/metrics-server", "--timeout=100s", timeout=110
    )
    lab.kubectl(
        "wait", "--for=condition=Available", "apiservice/" + METRICS_API, "--timeout=50s", timeout=60
    )
    service = json.loads(lab.kubectl("get", "apiservice", METRICS_API, "-o", "json").stdout)
    _record(lab, "metrics-api-service.json", service)
    lab.check(
        "positive",
        "The exact pinned Metrics Server provides the registered TLS-verified APIService",
        service["spec"].get("insecureSkipTLSVerify", False) is False
        and service["spec"]["caBundle"] == ca_bundle
        and service["spec"]["service"]["name"] == "metrics-server"
        and service["spec"]["service"]["namespace"] == METRICS_NS,
        {"api": METRICS_API, "image": METRICS_IMAGE, "aggregation_tls_verified": True},
    )


def run_metrics_and_webhook(lab):
    temporary = lab.kubeconfig.parent
    _install_metrics_server(lab, temporary)
    webhook_tls = temporary / "webhook"
    create_fixture_tls(lab, webhook_tls, f"saf-lab-webhook.{NAMESPACE}.svc")
    ca_crt = webhook_tls / "ca.crt"
    lab.kubectl(
        "create",
        "secret",
        "tls",
        "saf-lab-webhook-tls",
        "--cert",
        str(webhook_tls / "tls.crt"),
        "--key",
        str(webhook_tls / "tls.key"),
    )
    code_path = Path(__file__).with_name("webhook_fixture.py")
    lab.kubectl("create", "configmap", "saf-lab-webhook-code", f"--from-file=webhook.py={code_path}")
    server = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "saf-lab-webhook"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "saf-lab-webhook"}},
            "template": {
                "metadata": {"labels": {"app": "saf-lab-webhook"}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [
                        {
                            "name": "webhook",
                            "image": "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
                            "command": ["python", "/fixture/webhook.py"],
                            "env": [
                                {"name": "TLS_CERT", "value": "/tls/tls.crt"},
                                {"name": "TLS_KEY", "value": "/tls/tls.key"},
                            ],
                            "ports": [{"containerPort": 8443}],
                            "readinessProbe": {"tcpSocket": {"port": 8443}},
                            "resources": {
                                "requests": {"cpu": "10m", "memory": "24Mi"},
                                "limits": {"cpu": "100m", "memory": "64Mi"},
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "runAsNonRoot": True,
                                "runAsUser": 10001,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            "volumeMounts": [
                                {"name": "code", "mountPath": "/fixture", "readOnly": True},
                                {"name": "tls", "mountPath": "/tls", "readOnly": True},
                            ],
                        }
                    ],
                    "volumes": [
                        {"name": "code", "configMap": {"name": "saf-lab-webhook-code"}},
                        {"name": "tls", "secret": {"secretName": "saf-lab-webhook-tls"}},
                    ],
                },
            },
        },
    }
    lab.kubectl("apply", "-f", "-", payload=json.dumps(server))
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "saf-lab-webhook"},
        "spec": {"selector": {"app": "saf-lab-webhook"}, "ports": [{"port": 443, "targetPort": 8443}]},
    }
    lab.kubectl("create", "-f", "-", payload=json.dumps(service))
    lab.kubectl("rollout", "status", "deployment/saf-lab-webhook", "--timeout=90s", timeout=100)
    webhook = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingWebhookConfiguration",
        "metadata": {"name": "saf-lab-webhook.example.test"},
        "webhooks": [
            {
                "name": "saf-lab-webhook.example.test",
                "admissionReviewVersions": ["v1"],
                "sideEffects": "None",
                "failurePolicy": "Fail",
                "timeoutSeconds": 3,
                "clientConfig": {
                    "service": {
                        "namespace": NAMESPACE,
                        "name": "saf-lab-webhook",
                        "path": "/validate",
                        "port": 443,
                    },
                    "caBundle": base64.b64encode(ca_crt.read_bytes()).decode(),
                },
                "namespaceSelector": {"matchLabels": {"saf-lab.audit/enabled": "true"}},
                "objectSelector": {"matchLabels": {"saf-lab.audit/fixture": "true"}},
                "rules": [
                    {
                        "apiGroups": [""],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE"],
                        "resources": ["configmaps"],
                        "scope": "Namespaced",
                    }
                ],
            }
        ],
    }
    writer_role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "saf-lab-webhook-writer"},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}],
    }
    writer_bind = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "saf-lab-webhook-writer"},
        "subjects": [{"kind": "User", "name": WEBHOOK_WRITER, "apiGroup": "rbac.authorization.k8s.io"}],
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "saf-lab-webhook-writer",
        },
    }
    lab.kubectl(
        "create",
        "-f",
        "-",
        payload=json.dumps({"apiVersion": "v1", "kind": "List", "items": [writer_role, writer_bind]}),
    )

    def configmap(name, decision):
        return {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "labels": {"saf-lab.audit/fixture": "true", "saf-lab.audit/decision": decision},
            },
            "data": {"fixture": "synthetic"},
        }

    def create_as(user, obj, *, dry_run=False):
        marker = "--field-manager=" + obj["metadata"]["name"]
        flags = ["--dry-run=server"] if dry_run else []
        return lab.command(
            *kubectl_args(lab, NAMESPACE, user),
            "create",
            "-f",
            "-",
            "-o",
            "json",
            marker,
            *flags,
            payload=json.dumps(obj),
            allow_failure=True,
        )

    deny_fixture = configmap("saf-webhook-denied", "deny")
    baseline_hook = create_as(WEBHOOK_WRITER, deny_fixture, dry_run=True)
    lab.check(
        "red",
        "The same fixture writer and denied declaration are admitted before webhook registration",
        baseline_hook.returncode == 0,
        {"returncode": baseline_hook.returncode},
    )
    lab.kubectl("create", "-f", "-", payload=json.dumps(webhook))
    lab.kubectl("label", "namespace", NAMESPACE, "saf-lab.audit/enabled=true", "--overwrite")

    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        ready = create_as(WEBHOOK_WRITER, configmap("saf-webhook-readiness", "deny"), dry_run=True)
        if ready.returncode == 1 and "synthetic fixture decision denied" in ready.stderr:
            break
        time.sleep(0.4)
    else:
        lab.block(
            "The scoped validating webhook did not return its named denial to the readiness request"
        )
    denied_hook = create_as(WEBHOOK_WRITER, deny_fixture)
    allowed_hook = create_as(WEBHOOK_WRITER, configmap("saf-webhook-allowed", "allow"))
    # metrics fixture and resource-scoped RBAC
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": METRICS_POD},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [
                {
                    "name": "idle",
                    "image": "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec",
                    "command": ["sh", "-c", "sleep 3600"],
                    "resources": {
                        "requests": {"cpu": "10m", "memory": "16Mi"},
                        "limits": {"cpu": "50m", "memory": "32Mi"},
                    },
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "runAsNonRoot": True,
                        "runAsUser": 65534,
                        "capabilities": {"drop": ["ALL"]},
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                }
            ],
        },
    }
    lab.kubectl("create", "-f", "-", payload=json.dumps(pod))
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{METRICS_POD}", "--timeout=90s", timeout=95)
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "saf-lab-metrics-reader"},
        "rules": [
            {
                "apiGroups": ["metrics.k8s.io"],
                "resources": ["pods"],
                "resourceNames": [METRICS_POD],
                "verbs": ["get"],
            }
        ],
    }
    bind = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "saf-lab-metrics-reader"},
        "subjects": [{"kind": "User", "name": METRICS_READER, "apiGroup": "rbac.authorization.k8s.io"}],
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "saf-lab-metrics-reader",
        },
    }
    lab.kubectl(
        "create",
        "-f",
        "-",
        payload=json.dumps({"apiVersion": "v1", "kind": "List", "items": [role, bind]}),
    )

    def metrics_get(user):
        return lab.command(
            *kubectl_args(lab, NAMESPACE, user),
            "get",
            "--raw",
            f"/apis/metrics.k8s.io/v1beta1/namespaces/{NAMESPACE}/pods/{METRICS_POD}",
            allow_failure=True,
            timeout=50,
        )

    good = None
    for _ in range(40):
        good = metrics_get(METRICS_READER)
        if good.returncode == 0:
            try:
                body = json.loads(good.stdout)
                if (
                    body.get("kind") == "PodMetrics"
                    and body.get("metadata", {}).get("name") == METRICS_POD
                ):
                    break
            except json.JSONDecodeError:
                pass
        time.sleep(3)
    else:
        lab.block(
            "Exact missing dependency: Metrics Server did not return the named fixture PodMetrics sample"
        )
    bad = metrics_get(METRICS_DENIED)
    all_events = _read_audit(lab)

    def find(user, resource_name, group=None):
        return next(
            (
                event
                for event in reversed(all_events)
                if event.get("stage") == "ResponseComplete"
                and event.get("verb") == ("get" if group else "create")
                and (event.get("impersonatedUser") or event.get("user", {})).get("username") == user
                and event.get("objectRef", {}).get("namespace") == NAMESPACE
                and (
                    group is None
                    or (
                        event.get("objectRef", {}).get("apiGroup") == group
                        and event.get("objectRef", {}).get("name") == resource_name
                    )
                )
                and (
                    group is not None
                    or parse_qs(urlsplit(event.get("requestURI", "")).query).get("fieldManager")
                    == [resource_name]
                )
                and "dryRun=" not in event.get("requestURI", "")
            ),
            {},
        )

    selected = [
        find(METRICS_DENIED, METRICS_POD, "metrics.k8s.io"),
        find(METRICS_READER, METRICS_POD, "metrics.k8s.io"),
        find(WEBHOOK_WRITER, "saf-webhook-denied"),
        find(WEBHOOK_WRITER, "saf-webhook-allowed"),
    ]
    _record(lab, "metrics-webhook-audit-events.json", selected)
    ev_bad, ev_good = find(METRICS_DENIED, METRICS_POD, "metrics.k8s.io"), find(
        METRICS_READER, METRICS_POD, "metrics.k8s.io"
    )
    bad_obs = {
        "code": ev_bad.get("responseStatus", {}).get("code"),
        "level": ev_bad.get("level"),
        "decision": ev_bad.get("annotations", {}).get("authorization.k8s.io/decision"),
    }
    good_obs = {
        "code": ev_good.get("responseStatus", {}).get("code"),
        "level": ev_good.get("level"),
        "identity": (ev_good.get("impersonatedUser") or ev_good.get("user", {})).get("username"),
        "group": ev_good.get("objectRef", {}).get("apiGroup"),
        "resource": ev_good.get("objectRef", {}).get("resource"),
        "namespace": ev_good.get("objectRef", {}).get("namespace"),
        "name": ev_good.get("objectRef", {}).get("name"),
    }
    body = json.loads(good.stdout)
    pod_shape = {
        "kind": body.get("kind"),
        "apiVersion": body.get("apiVersion"),
        "name": body.get("metadata", {}).get("name"),
        "namespace": body.get("metadata", {}).get("namespace"),
        "has_usage": bool(body.get("containers"))
        and all("usage" in c for c in body.get("containers", [])),
    }
    _record(lab, "named-podmetrics-response.json", body)
    lab.check(
        "red",
        "Authenticated fixture identity without RBAC permission is denied for exact fixture PodMetrics with Metadata audit",
        bad.returncode == 1
        and "Forbidden" in bad.stderr
        and bad_obs == {"code": 403, "level": "Metadata", "decision": "forbid"},
        {"audit": bad_obs, "stderr": bad.stderr},
    )
    lab.check(
        "green",
        "Authorized metrics read returns genuine named PodMetrics and exact 200 Metadata audit",
        good.returncode == 0
        and good_obs
        == {
            "code": 200,
            "level": "Metadata",
            "identity": METRICS_READER,
            "group": "metrics.k8s.io",
            "resource": "pods",
            "namespace": NAMESPACE,
            "name": METRICS_POD,
        }
        and pod_shape
        == {
            "kind": "PodMetrics",
            "apiVersion": "metrics.k8s.io/v1beta1",
            "name": METRICS_POD,
            "namespace": NAMESPACE,
            "has_usage": True,
        },
        {"audit": good_obs, "response": pod_shape},
    )

    def webhook_event(name):
        return find(WEBHOOK_WRITER, name)

    denied_event, allowed_event = webhook_event("saf-webhook-denied"), webhook_event(
        "saf-webhook-allowed"
    )

    def hook_obs(event):
        return {
            "code": event.get("responseStatus", {}).get("code"),
            "level": event.get("level"),
            "decision": event.get("annotations", {}).get("saf-lab-webhook.example.test/decision"),
        }

    denied_obj = lab.kubectl(
        "get", "configmap", "saf-webhook-denied", "--ignore-not-found", "-o", "json"
    ).stdout
    allowed_obj = lab.kubectl(
        "get", "configmap", "saf-webhook-allowed", "--ignore-not-found", "-o", "json"
    ).stdout
    lab.check(
        "positive",
        "Scoped HTTPS webhook audits exact deny/allow decisions and persists only allowed fixture",
        denied_hook.returncode == 1
        and "synthetic fixture decision denied" in denied_hook.stderr
        and allowed_hook.returncode == 0
        and hook_obs(denied_event) == {"code": 403, "level": "Metadata", "decision": "deny"}
        and hook_obs(allowed_event) == {"code": 201, "level": "Metadata", "decision": "allow"}
        and not denied_obj
        and bool(allowed_obj),
        {
            "deny": hook_obs(denied_event),
            "allow": hook_obs(allowed_event),
            "denied_absent": not bool(denied_obj),
            "allowed_present": bool(allowed_obj),
        },
    )


def _read_audit(lab):
    result = lab.command(
        "docker", "exec", f"{lab.cluster}-control-plane", "cat", AUDIT_LOG, allow_failure=True, timeout=10
    )
    rows = []
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows
