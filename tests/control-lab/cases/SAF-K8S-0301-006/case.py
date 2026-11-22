"""Review native PSA exemptions with an exact synthetic compensating policy."""
import json
from pathlib import Path
import subprocess
import time

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).parent
VERSION = "v1.36"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
POLICY_CONFIG = "/etc/kubernetes/saf-0301-006-pod-security.yaml"
AUDIT_POLICY = "/etc/kubernetes/saf-0301-006-audit.yaml"
AUDIT_LOG = "/var/log/kubernetes/saf-0301-006-audit.jsonl"
NAMESPACE = "saf-0301-006-namespace-exempt"
RUNTIME_NAMESPACE = "saf-0301-006-runtime-exempt"
RESTRICTED_NAMESPACE = "saf-0301-006-restricted"
SERVICE_ACCOUNT = "saf-0301-006-device-agent"
APPROVED_REQUESTER = "approved-requester"
ORDINARY_REQUESTER = "ordinary-requester"
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
RUNTIME_CLASS = "saf-0301-006-device-runtime"
POLICY = "saf-k8s-0301-006-exact-psa-exception"
SCOPE = (
    "Kubernetes v1.36.1 Pod CREATE admission in three synthetic namespaces. "
    "Uses server-side dry-run only for harmless Pods missing only the Restricted "
    "allowPrivilegeEscalation=false and capabilities.drop=[ALL] settings. Confirms "
    "native namespace and RuntimeClass exemptions, then checks a synthetic "
    "ValidatingAdmissionPolicy allows only the exact named Pod, ServiceAccount, "
    "label, namespace and (for the RuntimeClass arm) class. Two authenticated requester "
    "identities test username scoping with the same harmless dry-run. Real infrastructure "
    "workloads, runtime execution and controller-created Pods require additional evidence. "
    "The real audit backend records the selected workload write and Metadata for empty Secret creation. "
    "Updates, production RBAC/namespace governance, and compensating-control "
    "effectiveness beyond this exact identity check are out of scope."
)


def prepare_kind(lab, temporary: Path) -> Path:
    psa = temporary / "pod-security.yaml"
    psa.write_text(
        """apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: privileged
      enforce-version: v1.36
      audit: privileged
      audit-version: v1.36
      warn: privileged
      warn-version: v1.36
    exemptions:
      usernames:
      - system:serviceaccount:saf-0301-006-restricted:approved-requester
      runtimeClasses:
      - saf-0301-006-device-runtime
      namespaces:
      - saf-0301-006-namespace-exempt
"""
    )
    audit = temporary / "audit.yaml"
    audit.write_text(f"""apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
- level: Metadata
  resources:
  - group: ""
    resources: [secrets]
- level: RequestResponse
  verbs: [create]
  namespaces: [{NAMESPACE}]
  resources:
  - group: ""
    resources: [pods]
- level: Metadata
  namespaces: [{NAMESPACE}]
- level: None
""")
    config = temporary / "kind.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(psa))}
    containerPath: {POLICY_CONFIG}
    readOnly: true
  - hostPath: {json.dumps(str(audit))}
    containerPath: {AUDIT_POLICY}
    readOnly: true
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta4
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
    - name: admission-control-config-file
      value: {POLICY_CONFIG}
    - name: audit-policy-file
      value: {AUDIT_POLICY}
    - name: audit-log-path
      value: {AUDIT_LOG}
    extraVolumes:
    - name: saf-psa-config
      hostPath: {POLICY_CONFIG}
      mountPath: {POLICY_CONFIG}
      readOnly: true
      pathType: File
    - name: saf-exemption-audit-policy
      hostPath: {AUDIT_POLICY}
      mountPath: {AUDIT_POLICY}
      readOnly: true
      pathType: File
    - name: saf-exemption-audit-log
      hostPath: /var/log/kubernetes
      mountPath: /var/log/kubernetes
      readOnly: false
      pathType: DirectoryOrCreate
""")
    return config


def namespace(name, *, exception=False):
    labels = {}
    for mode in ("enforce", "audit", "warn"):
        labels[f"pod-security.kubernetes.io/{mode}"] = "restricted"
        labels[f"pod-security.kubernetes.io/{mode}-version"] = VERSION
    if exception:
        labels["saf-k8s.example/psa-exception-case"] = "0301-006"
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, "labels": labels}}


def challenge(name, *, namespace_name, target=False, runtime_class=None):
    labels = {"app.kubernetes.io/name": "saf-0301-006-fixture"}
    service_account = "default"
    if target:
        labels["saf-k8s.example/exception-workload"] = "0301-006"
        service_account = SERVICE_ACCOUNT
    spec = {
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,
        "serviceAccountName": service_account,
        "containers": [{
            "name": "fixture",
            "image": BUSYBOX_IMAGE,
            "command": ["sh", "-c", "printf synthetic"],
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 65534,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
        }],
    }
    if runtime_class:
        spec["runtimeClassName"] = runtime_class
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": namespace_name, "labels": labels},
            "spec": spec}


def submit(lab, obj):
    return lab.kubectl(
        "-n", obj["metadata"]["namespace"], "create", "-f", "-",
        "--dry-run=server", "-o", "json", payload=json.dumps(obj), allow_failure=True,
    )


def psa_denied(result):
    message = result.stderr.lower()
    return (result.returncode != 0 and "(forbidden)" in message and
            "violates podsecurity" in message and "restricted:v1.36" in message and
            ("allowprivilegeescalation" in message or "capabilities" in message))


def policy_denied(result):
    message = result.stderr.lower()
    return (result.returncode != 0 and "(forbidden)" in message and
            POLICY in message and "exact synthetic device-agent pod identity" in message)


def admitted(result, name="saf-0301-006-device-agent"):
    if result.returncode:
        return False
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    return response.get("kind") == "Pod" and response.get("metadata", {}).get("name") == name


def variant(resource, *, name=None, service_account=None, workload_label=None,
            runtime_class=None):
    obj = json.loads(json.dumps(resource))
    if name is not None:
        obj["metadata"]["name"] = name
    if service_account is not None:
        obj["spec"]["serviceAccountName"] = service_account
    if workload_label is not None:
        obj["metadata"]["labels"]["saf-k8s.example/exception-workload"] = workload_label
    if runtime_class is not None:
        obj["spec"]["runtimeClassName"] = runtime_class
    return obj


def run(lab):
    # The three namespaces, service account and RuntimeClass are synthetic API
    # fixtures. No submitted Pod is persisted or scheduled.
    for obj in (namespace(RESTRICTED_NAMESPACE), namespace(NAMESPACE, exception=True),
                namespace(RUNTIME_NAMESPACE, exception=True)):
        lab.kubectl("create", "-f", "-", payload=json.dumps(obj))
    for name in (NAMESPACE, RUNTIME_NAMESPACE, RESTRICTED_NAMESPACE):
        lab.kubectl("create", "serviceaccount", SERVICE_ACCOUNT, "-n", name)
    for name in (RUNTIME_CLASS, "saf-0301-006-near-runtime"):
        runtime = {"apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass",
                   "metadata": {"name": name}, "handler": "saf-synthetic-runtime"}
        lab.kubectl("create", "-f", "-", payload=json.dumps(runtime))

    ordinary = challenge("saf-0301-006-device-agent", namespace_name=RESTRICTED_NAMESPACE,
                         target=True)
    exact_namespace = challenge("saf-0301-006-device-agent", namespace_name=NAMESPACE,
                                target=True)
    unrelated_namespace = challenge("saf-0301-006-unrelated", namespace_name=NAMESPACE)
    exact_runtime = challenge("saf-0301-006-device-agent", namespace_name=RUNTIME_NAMESPACE,
                              target=True, runtime_class=RUNTIME_CLASS)
    unrelated_runtime = challenge("saf-0301-006-unrelated", namespace_name=RUNTIME_NAMESPACE,
                                  runtime_class=RUNTIME_CLASS)

    ordinary_result = submit(lab, ordinary)
    lab.check("green", "Restricted namespace rejects the harmless missing-fields fixture",
              psa_denied(ordinary_result), ordinary_result.stderr.strip())

    # Before the compensating policy, native namespace exemption admits both
    # the intended identity and an unrelated harmless fixture. This is the gap.
    before_exact = submit(lab, exact_namespace)
    before_unrelated = submit(lab, unrelated_namespace)
    lab.check("red", "Native namespace exemption admits the intended synthetic fixture",
              admitted(before_exact), before_exact.stderr.strip() or "server dry-run admitted")
    lab.check("red", "Native namespace exemption also admits an unrelated fixture before compensation",
              admitted(before_unrelated, "saf-0301-006-unrelated"),
              before_unrelated.stderr.strip() or "server dry-run admitted")

    # The exact RuntimeClass exemption is also exercised against a namespace
    # still set to Restricted. A near-miss class must remain subject to PSA.
    exact_runtime_before = submit(lab, exact_runtime)
    near_runtime = challenge("saf-0301-006-near-runtime", namespace_name=RUNTIME_NAMESPACE,
                             target=True, runtime_class="saf-0301-006-near-runtime")
    near_runtime_before = submit(lab, near_runtime)
    lab.check("green", "Configured RuntimeClass exemption bypasses Restricted for the exact class",
              admitted(exact_runtime_before),
              exact_runtime_before.stderr.strip() or "server dry-run admitted")
    lab.check("green", "Unconfigured RuntimeClass remains subject to Restricted",
              psa_denied(near_runtime_before), near_runtime_before.stderr.strip())

    lab.apply(HERE / "admission-policy.yaml")
    after_exact = submit(lab, exact_namespace)
    namespace_near_misses = {
        "name": variant(exact_namespace, name="saf-0301-006-near-name"),
        "ServiceAccount": variant(exact_namespace, service_account="default"),
        "label": variant(exact_namespace, workload_label="0301-006-near-label"),
    }
    after_unrelated = submit(lab, unrelated_namespace)
    deadline = time.monotonic() + 20
    while not policy_denied(after_unrelated) and time.monotonic() < deadline:
        time.sleep(0.3)
        after_unrelated = submit(lab, unrelated_namespace)
    after_runtime = submit(lab, exact_runtime)
    after_runtime_unrelated = submit(lab, unrelated_runtime)
    lab.check("positive", "Compensating policy preserves the exact namespace-scoped fixture",
              admitted(after_exact), after_exact.stderr.strip() or "server dry-run admitted")
    lab.check("green", "Compensating policy denies a different Pod identity in the exempt namespace",
              policy_denied(after_unrelated), after_unrelated.stderr.strip())
    for dimension, fixture in namespace_near_misses.items():
        result = submit(lab, fixture)
        lab.check("green", f"Compensating policy rejects a namespace exception with a different {dimension}",
                  policy_denied(result), result.stderr.strip())
    lab.check("positive", "Compensating policy preserves the exact RuntimeClass-scoped fixture",
              admitted(after_runtime), after_runtime.stderr.strip() or "server dry-run admitted")
    lab.check("green", "Compensating policy denies a different identity using the exempt RuntimeClass",
              policy_denied(after_runtime_unrelated), after_runtime_unrelated.stderr.strip())
    runtime_near_misses = {
        "name": variant(exact_runtime, name="saf-0301-006-near-name"),
        "ServiceAccount": variant(exact_runtime, service_account="default"),
        "label": variant(exact_runtime, workload_label="0301-006-near-label"),
    }
    for dimension, fixture in runtime_near_misses.items():
        result = submit(lab, fixture)
        lab.check("green", f"Compensating policy rejects a RuntimeClass exception with a different {dimension}",
                  policy_denied(result), result.stderr.strip())
    switched_class = submit(lab, variant(exact_runtime, runtime_class="saf-0301-006-near-runtime"))
    lab.check("green", "The exact workload with an excluded runtime class remains subject to PSA",
              psa_denied(switched_class), switched_class.stderr.strip())

    check_requester_identity(lab)
    check_workload_audit(lab)


def check_requester_identity(lab):
    names = (APPROVED_REQUESTER, ORDINARY_REQUESTER)
    namespace = RESTRICTED_NAMESPACE
    users = [f"system:serviceaccount:{namespace}:{name}" for name in names]
    guard = {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": "saf-psa-probe-dry-run"},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"],
            }]},
            "matchConditions": [{"name": "owned-requesters", "expression": "request.userInfo.username in " + json.dumps(users)}],
            "validations": [{"expression": "request.dryRun == true", "message": "fixture requests must be dry-run"}],
        },
    }
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": "saf-psa-probe-dry-run"},
        "spec": {"policyName": guard["metadata"]["name"], "validationActions": ["Deny"]},
    }
    for obj in (guard, binding):
        lab.kubectl("create", "-f", "-", payload=json.dumps(obj))
    lab.kubectl("-n", namespace, "create", "role", "fixture-requester", "--verb=create", "--resource=pods")
    for name in names:
        lab.kubectl("-n", namespace, "create", "serviceaccount", name)
        lab.kubectl("-n", namespace, "create", "rolebinding", name, "--role=fixture-requester",
                    "--serviceaccount=" + namespace + ":" + name)
    request = challenge("saf-0301-006-requester-fixture", namespace_name=namespace, target=True)
    request["spec"]["serviceAccountName"] = APPROVED_REQUESTER
    fixture = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "requester-fixtures", "namespace": namespace},
        "data": {"probe.py": (HERE / "requester_probe.py").read_text(),
                 "pod.json": json.dumps(request)},
    }
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(fixture))
    results = {}
    for name in names:
        workload = challenge(name, namespace_name=namespace)
        spec = workload["spec"]
        spec["serviceAccountName"] = name
        spec["automountServiceAccountToken"] = True
        spec["volumes"] = [{"name": "fixture", "configMap": {"name": "requester-fixtures"}}]
        container = spec["containers"][0]
        container["image"] = PYTHON_IMAGE
        container["command"] = ["python", "-c", "import time; time.sleep(240)"]
        container["volumeMounts"] = [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]
        container["securityContext"].update({"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}})
        lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(workload))
        lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=95s", timeout=105)
        result = lab.kubectl("-n", namespace, "exec", f"pod/{name}", "--", "python", "/fixture/probe.py")
        results[name] = json.loads(result.stdout)
    expected = {
        APPROVED_REQUESTER: {"status": 201, "restricted_violation": False},
        ORDINARY_REQUESTER: {"status": 403, "restricted_violation": True},
    }
    lab.check("green", "The configured authenticated requester alone receives the username exemption",
              results == expected, results)



def check_workload_audit(lab):
    empty_secret = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                    "metadata": {"name": "saf-empty-audit-fixture", "namespace": NAMESPACE}}
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "name", payload=json.dumps(empty_secret))
    deadline = time.monotonic() + 12
    reports = {}
    while time.monotonic() < deadline:
        result = subprocess.run(["docker", "exec", f"{lab.cluster}-control-plane", "cat", AUDIT_LOG],
                                capture_output=True, env=lab.env, text=True, timeout=8)
        if result.returncode == 0:
            for row in result.stdout.splitlines():
                event = json.loads(row)
                ref = event.get("objectRef", {})
                if (event.get("stage") != "ResponseComplete" or event.get("verb") != "create"
                        or ref.get("namespace") != NAMESPACE or event.get("responseStatus", {}).get("code") != 201):
                    continue
                if ref.get("resource") == "pods" and "dryRun=All" in event.get("requestURI", ""):
                    if event.get("requestObject", {}).get("metadata", {}).get("name") == "saf-0301-006-device-agent":
                        reports["workload"] = event
                elif ref.get("resource") == "secrets":
                    reports["empty_secret"] = event
        if set(reports) == {"workload", "empty_secret"}:
            break
        time.sleep(0.25)
    if set(reports) != {"workload", "empty_secret"}:
        lab.block("Expected exact successful workload dry-run and empty Secret audit events")
    workload, secret = reports["workload"], reports["empty_secret"]
    expected = (workload["level"] == "RequestResponse"
                and workload.get("responseObject", {}).get("metadata", {}).get("name") == "saf-0301-006-device-agent")
    lab.check("positive", "The approved workload dry-run retains the selected audit request and response",
              expected, {"selected_workload_bodies_retained": expected})
    filtered = secret["level"] == "Metadata" and not {"requestObject", "responseObject"}.intersection(secret)
    lab.check("green", "The empty Secret in the same exempt namespace retains metadata without bodies",
              filtered, {"credential_resource_metadata_only": filtered})
