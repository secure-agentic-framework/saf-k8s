"""Check namespace-scoped Pod Security Admission for synthetic AI namespaces."""
import json
from pathlib import Path
import subprocess
import time


HERE = Path(__file__).parent
AI_NAMESPACE = "saf-0605-006-ai"
CONTROL_NAMESPACE = "saf-0605-006-control"
AI_CLASS = "saf-k8s.example/workload-class=ai"
PSA_LABELS = {
    "pod-security.kubernetes.io/enforce": "restricted",
    "pod-security.kubernetes.io/enforce-version": "v1.36",
    "pod-security.kubernetes.io/audit": "restricted",
    "pod-security.kubernetes.io/audit-version": "v1.36",
    "pod-security.kubernetes.io/warn": "restricted",
    "pod-security.kubernetes.io/warn-version": "v1.36",
}
PSA_DENIAL = (
    'violates PodSecurity "restricted:v1.36": runAsNonRoot != true '
    '(container "probe" must not set securityContext.runAsNonRoot=false)'
)
NAMESPACE_GUARD = "saf-k8s-0605-006-ai-namespace-psa"
NAMESPACE_DENIAL = (
    "AI namespaces require restricted Pod Security Admission labels pinned to v1.36"
)
SCOPE = (
    "One fresh Kubernetes v1.36.1 kind cluster. Server-side dry-run compares the same "
    "schema-valid, inert pause Pod with only runAsNonRoot changed, before and after "
    "Restricted PSA labels are applied to one typed synthetic AI namespace. A "
    "ValidatingAdmissionPolicy requires immutable AI classification and Restricted "
    "enforce/audit/warn labels pinned to v1.36. A separate ordinary namespace checks "
    "namespace matching. Native metadata audit events record the proposed Baseline AI namespace "
    "and its Pod-level Restricted violation. All Pod requests are server-side dry-run. "
    "Production coverage and central audit delivery require deployment evidence."
)


AUDIT_NAMESPACE = "saf-0605-006-baseline"
AUDIT_POLICY = "/etc/kubernetes/saf-0605-006-audit.yaml"
AUDIT_LOG = "/var/log/kubernetes/saf-0605-006-audit.jsonl"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PSA_AUDIT_KEY = "pod-security.kubernetes.io/audit-violations"


def prepare_kind(_lab, temporary):
    policy = temporary / "audit-policy.yaml"
    policy.write_text(f"""apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
- level: Metadata
  verbs: [create]
  namespaces: [{AUDIT_NAMESPACE}]
  resources:
  - group: ""
    resources: [pods]
- level: Metadata
  verbs: [create]
  resources:
  - group: ""
    resources: [namespaces]
- level: None
""")
    config = temporary / "kind.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(policy))}
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
    - name: audit-log-mode
      value: blocking
    extraVolumes:
    - name: saf-admission-audit-policy
      hostPath: {AUDIT_POLICY}
      mountPath: {AUDIT_POLICY}
      readOnly: true
      pathType: File
    - name: saf-admission-audit-log
      hostPath: /var/log/kubernetes
      mountPath: /var/log/kubernetes
      pathType: DirectoryOrCreate
""")
    return config


def audit_rows(lab):
    result = subprocess.run(
        ["docker", "exec", f"{lab.cluster}-control-plane", "cat", AUDIT_LOG],
        capture_output=True, text=True, env=lab.env, timeout=8,
    )
    if result.returncode != 0:
        return []
    return [json.loads(row) for row in result.stdout.splitlines() if row.strip()]


def find_audit_event(lab, resource, name, *, namespace=None, annotation=None):
    for event in reversed(audit_rows(lab)):
        ref = event.get("objectRef", {})
        if (event.get("stage") != "ResponseComplete" or event.get("verb") != "create"
                or ref.get("resource") != resource or (ref.get("namespace") or None) != namespace
                or ref.get("name") != name or "dryRun=All" not in event.get("requestURI", "")
                or event.get("responseStatus", {}).get("code") != 201
                or (annotation and annotation not in event.get("annotations", {}))):
            continue
        return event

def audit_event(lab, resource, name, *, namespace=None, annotation=None):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        event = find_audit_event(lab, resource, name, namespace=namespace, annotation=annotation)
        if event:
            return event
        time.sleep(0.3)
    lab.block(f"No matching metadata audit event for {resource}/{name}")


def observe_baseline_pod_audit(lab, baseline, deviation):
    labels = {
        "saf-k8s.example/workload-class": "ai",
        **PSA_LABELS,
        "pod-security.kubernetes.io/enforce": "baseline",
    }
    candidate = _namespace(AUDIT_NAMESPACE, labels)
    key = "validation.policy.admission.k8s.io/validation_failure"
    deadline = time.monotonic() + 20
    annotated = None
    while time.monotonic() < deadline:
        lab.create(candidate, dry_run=True)
        event = find_audit_event(lab, "namespaces", AUDIT_NAMESPACE, annotation=key)
        if event:
            annotated = json.loads(event["annotations"][key])
            break
        time.sleep(0.5)
    match = any(row.get("policy") == NAMESPACE_GUARD and row.get("binding") == NAMESPACE_GUARD
                and NAMESPACE_DENIAL in row.get("message", "") and row.get("validationActions") == ["Audit"]
                for row in (annotated or []))
    lab.check("positive", "The metadata audit log identifies the AI namespace proposed below Restricted",
              match, {"exact_policy_binding_and_reason": match, "namespace_dry_run_admitted": True})
    lab.create(candidate)
    skipped = _dry_run(lab, AUDIT_NAMESPACE, deviation)
    warned = "would violate PodSecurity" in skipped.stderr and "restricted:v1.36" in skipped.stderr
    event = audit_event(lab, "pods", deviation["metadata"]["name"], namespace=AUDIT_NAMESPACE,
                        annotation=PSA_AUDIT_KEY)
    violation = event["annotations"][PSA_AUDIT_KEY]
    expected = "restricted:v1.36" in violation and "runAsNonRoot" in violation
    lab.check("positive", "Baseline policy admits the inert Pod while Restricted audit and warning identify the deviation",
              skipped.returncode == 0 and warned and expected and "requestObject" not in event,
              {"dry_run_admitted": skipped.returncode == 0, "restricted_warning_observed": warned,
               "restricted_audit_violation_observed": expected, "metadata_only": "requestObject" not in event})
    allowed = _dry_run(lab, AUDIT_NAMESPACE, baseline)
    clean = audit_event(lab, "pods", baseline["metadata"]["name"], namespace=AUDIT_NAMESPACE)
    clean_audit = PSA_AUDIT_KEY not in clean.get("annotations", {})
    lab.check("positive", "Restricted-compatible comparison has no PSA violation audit entry",
              allowed.returncode == 0 and clean_audit,
              {"dry_run_admitted": allowed.returncode == 0, "violation_annotation_absent": clean_audit})


def _pod_templates():
    baseline, deviation = json.loads(
        (HERE / "fixtures.json").read_text(encoding="utf-8")
    )
    baseline = json.loads(json.dumps(baseline))
    deviation = json.loads(json.dumps(deviation))
    return baseline, deviation


def _dry_run(lab, namespace, obj):
    candidate = json.loads(json.dumps(obj))
    candidate["metadata"]["namespace"] = namespace
    return lab.kubectl(
        "-n", namespace, "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(candidate), allow_failure=True,
    )


def _is_psa_denial(result):
    exact_reason = (
        'pods "saf-0605-006-restricted-deviation" is forbidden: ' + PSA_DENIAL
    )
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and exact_reason in result.stderr)


def _namespace(namespace, labels=None):
    metadata = {"name": namespace}
    if labels:
        metadata["labels"] = labels
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": metadata}


def namespace_denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and NAMESPACE_GUARD in result.stderr and NAMESPACE_DENIAL in result.stderr)


def run(lab):
    version = json.loads(lab.kubectl("get", "--raw=/version").stdout)
    lab.check("positive", "Disposable API server is Kubernetes v1.36.1",
              version.get("gitVersion") == "v1.36.1", {"server": version.get("gitVersion")})

    lab.kubectl("create", "namespace", AI_NAMESPACE)
    lab.kubectl("label", "namespace", AI_NAMESPACE, AI_CLASS)
    lab.kubectl("create", "namespace", CONTROL_NAMESPACE)
    baseline, deviation = _pod_templates()

    before_bad = _dry_run(lab, AI_NAMESPACE, deviation)
    before_good = _dry_run(lab, AI_NAMESPACE, baseline)
    lab.check(
        "red", "Same Restricted-only deviation is admitted before namespace policy",
        before_bad.returncode == 0,
        before_bad.stderr.strip() or "server-side dry-run admitted; no Pod persisted",
    )
    lab.check(
        "positive", "Restricted-compatible baseline is admitted before namespace policy",
        before_good.returncode == 0,
        before_good.stderr.strip() or "server-side dry-run admitted; no Pod persisted",
    )

    labels = {"saf-k8s.example/workload-class": "ai", **PSA_LABELS}
    configured = _namespace(AI_NAMESPACE, labels)
    lab.kubectl("apply", "-f", "-", payload=json.dumps(configured))
    lab.apply(HERE / "namespace-guard.yaml")
    observe_baseline_pod_audit(lab, baseline, deviation)
    lab.kubectl("patch", "validatingadmissionpolicybinding", NAMESPACE_GUARD,
                "--type=merge", "-p", '{"spec":{"validationActions":["Deny","Audit"]}}')

    # Wait until the native namespace policy is active; challenge it with a dry-run update.
    deadline = time.monotonic() + 20
    while True:
        downgrade = lab.kubectl(
            "label", "namespace", AI_NAMESPACE,
            "pod-security.kubernetes.io/enforce=baseline", "--overwrite",
            "--dry-run=server", allow_failure=True,
        )
        if NAMESPACE_DENIAL in downgrade.stderr or time.monotonic() >= deadline:
            break
        time.sleep(0.25)
    lab.check(
        "green", "Namespace policy denies a dry-run downgrade with its exact reason",
        namespace_denied(downgrade),
        downgrade.stderr.strip(),
    )

    removal = lab.kubectl("label", "namespace", AI_NAMESPACE, "saf-k8s.example/workload-class-",
                          "--dry-run=server", allow_failure=True)
    lab.check("green", "Namespace policy denies removal of an existing AI classification",
              namespace_denied(removal), {"expected_policy_denial": namespace_denied(removal)})
    weak_new = lab.create(_namespace("saf-0605-006-new-ai", {"saf-k8s.example/workload-class": "ai"}),
                          dry_run=True, allow_failure=True)
    lab.check("green", "Namespace policy denies a new AI namespace without pinned PSA labels",
              namespace_denied(weak_new), {"expected_policy_denial": namespace_denied(weak_new)})
    valid_new = lab.create(_namespace("saf-0605-006-new-ai", labels), dry_run=True, allow_failure=True)
    ordinary_new = lab.create(_namespace("saf-0605-006-new-other"), dry_run=True, allow_failure=True)
    lab.check("positive", "A complete AI namespace and an independent unclassified namespace are admitted",
              valid_new.returncode == ordinary_new.returncode == 0,
              {"complete_ai_namespace_admitted": valid_new.returncode == 0,
               "ordinary_namespace_admitted": ordinary_new.returncode == 0})
    after_bad = _dry_run(lab, AI_NAMESPACE, deviation)
    lab.check(
        "green", "Same Restricted-only deviation is rejected by PSA with the exact message",
        _is_psa_denial(after_bad), after_bad.stderr.strip(),
    )
    after_good = _dry_run(lab, AI_NAMESPACE, baseline)
    lab.check(
        "positive", "Restricted-compatible baseline remains admitted in the AI namespace",
        after_good.returncode == 0,
        after_good.stderr.strip() or "server-side dry-run admitted; no Pod persisted",
    )

    # Matching comparison: the identical Restricted-only deviation is accepted in an
    # independent namespace with no AI classification and no PSA labels.
    control = _dry_run(lab, CONTROL_NAMESPACE, deviation)
    lab.check(
        "positive", "Identical schema-valid probe is outside the AI namespace policy scope",
        control.returncode == 0,
        control.stderr.strip() or "server-side dry-run admitted; no Pod persisted",
    )

    observed = json.loads(lab.kubectl("get", "namespace", AI_NAMESPACE, "-o", "json").stdout)
    actual = observed.get("metadata", {}).get("labels", {})
    lab.check("positive", "AI namespace retains all six Restricted PSA labels pinned to v1.36",
              all(actual.get(key) == value for key, value in PSA_LABELS.items()),
              {key: actual.get(key) for key in PSA_LABELS})
