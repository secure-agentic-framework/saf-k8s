"""Probe a harmless PSP-to-PSA migration path on an isolated kind cluster."""
import json
from pathlib import Path
import subprocess
import time

from fixtures import BUSYBOX_IMAGE

NAMESPACE = "saf-0301-003-migration"
VERSION = "v1.36"
MODES = ("enforce", "audit", "warn")
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
AUDIT_POLICY = "/etc/kubernetes/saf-psa-audit.yaml"
AUDIT_LOG = "/var/log/kubernetes/saf-psa-audit.jsonl"
VIOLATION = "pod-security.kubernetes.io/audit-violations"
SCOPE = (
    "Synthetic namespace migration from a Baseline-compatible admission state "
    "through Restricted audit/warn to Restricted enforcement, using server "
    "dry-run probes, matching audit annotations and one benign compliant live Pod. "
    "Legacy inventory and disablement, system scope, custom PSP features, namespace "
    "permission governance and the actual workload upgrade require deployment evidence."
)


def prepare_kind(lab, temporary: Path) -> Path:
    policy = temporary / "audit-policy.yaml"
    policy.write_text(f"""apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
- level: Metadata
  verbs: [create]
  namespaces: [{NAMESPACE}]
  resources:
  - group: ""
    resources: [pods]
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
    extraVolumes:
    - name: saf-psa-audit-policy
      hostPath: {AUDIT_POLICY}
      mountPath: {AUDIT_POLICY}
      readOnly: true
      pathType: File
    - name: saf-psa-audit-log
      hostPath: /var/log/kubernetes
      mountPath: /var/log/kubernetes
      readOnly: false
      pathType: DirectoryOrCreate
""")
    return config


def audit_observation(lab, *, expected_count):
    until = time.monotonic() + 12
    node = f"{lab.cluster}-control-plane"
    matching = []
    while time.monotonic() < until:
        result = subprocess.run(["docker", "exec", node, "cat", AUDIT_LOG], capture_output=True,
                                env=lab.env, text=True, timeout=8)
        if result.returncode == 0:
            events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            matching = [event for event in events
                        if event.get("stage") == "ResponseComplete" and event.get("verb") == "create"
                        and event.get("objectRef", {}).get("resource") == "pods"
                        and event.get("objectRef", {}).get("namespace") == NAMESPACE
                        and "dryRun=All" in event.get("requestURI", "")
                        and event.get("responseStatus", {}).get("code") == 201]
            if len(matching) == expected_count:
                event = matching[-1]
                annotations = event.get("annotations", {})
                violation = annotations.get(VIOLATION, "")
                return {"audit_event_observed": True,
                        "restricted_violation": "restricted:v1.36" in violation,
                        "request_body_recorded": "requestObject" in event}
        time.sleep(0.3)
    lab.block(f"Expected {expected_count} scoped audit events, got {len(matching)}")


def namespace(levels):
    labels = {}
    for mode in MODES:
        labels[f"pod-security.kubernetes.io/{mode}"] = levels[mode]
        labels[f"pod-security.kubernetes.io/{mode}-version"] = VERSION
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": NAMESPACE, "labels": labels},
    }


def pod(name, *, restricted):
    security_context = {
        "runAsNonRoot": True,
        "runAsUser": 65534,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    if restricted:
        security_context.update({
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
        })
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [{
                "name": "probe",
                "image": BUSYBOX_IMAGE,
                "command": ["sh", "-c", "sleep 3600"],
                "securityContext": security_context,
            }],
        },
    }


def server_dry_run(lab, resource):
    return lab.kubectl(
        "-n", NAMESPACE, "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(resource), allow_failure=True,
    )


def forbidden_for_restricted(result):
    text = result.stderr.lower()
    return (
        result.returncode != 0
        and "(forbidden)" in text
        and "restricted:v1.36" in text
        and "podsecurity" in text
        and ("allowprivilegeescalation" in text or "capabilities" in text)
    )


def has_restricted_warning(result):
    text = result.stderr.lower()
    return (
        result.returncode == 0
        and "warning: would violate podsecurity" in text
        and "restricted:v1.36" in text
    )


def run(lab):
    # A modern API server should not serve or discover the removed PSP API.
    discovered = lab.kubectl("api-resources", "--api-group=policy", "-o", "name")
    legacy_lookup = lab.kubectl(
        "get", "podsecuritypolicies.policy", "-o", "name", allow_failure=True,
    )
    legacy_unavailable = (
        legacy_lookup.returncode != 0
        and "doesn't have a resource type" in legacy_lookup.stderr.lower()
        and "podsecuritypolicies" in legacy_lookup.stderr.lower()
    )
    lab.check(
        "green",
        "Kubernetes v1.36 discovery and direct lookup confirm PSP is not served",
        {"podsecuritypolicies", "podsecuritypolicies.policy"}.isdisjoint(
            discovered.stdout.splitlines()
        )
        and legacy_unavailable,
        {
            "policy_group_resources": discovered.stdout.splitlines(),
            "direct_lookup": legacy_lookup.stderr.strip(),
        },
    )

    # The single negative object omits only Restricted-specific fields. It is
    # never persisted or launched; the same request is used at each phase.
    challenge = pod("saf-0301-003-restricted-dry-run", restricted=False)
    compliant = pod("saf-0301-003-compliant", restricted=True)

    initial = namespace({"enforce": "baseline", "audit": "privileged", "warn": "privileged"})
    lab.kubectl("create", "-f", "-", payload=json.dumps(initial))
    lab.kubectl("wait", "--for=create", f"namespace/{NAMESPACE}", "--timeout=20s")

    baseline = server_dry_run(lab, challenge)
    baseline_audit = audit_observation(lab, expected_count=1)
    lab.check(
        "red",
        "Baseline admits the harmless Pod that omits Restricted-only settings",
        baseline.returncode == 0 and baseline_audit == {"audit_event_observed": True,
                                                         "restricted_violation": False,
                                                         "request_body_recorded": False},
        {"admitted": baseline.returncode == 0, **baseline_audit},
    )

    lab.kubectl(
        "label", "namespace", NAMESPACE,
        "pod-security.kubernetes.io/audit=restricted",
        "pod-security.kubernetes.io/warn=restricted",
        "--overwrite",
    )
    staged = server_dry_run(lab, challenge)
    staged_audit = audit_observation(lab, expected_count=2)
    observed_namespace = json.loads(
        lab.kubectl("get", "namespace", NAMESPACE, "-o", "json").stdout
    )
    labels = observed_namespace["metadata"].get("labels", {})
    migration_modes = {
        mode: labels.get(f"pod-security.kubernetes.io/{mode}")
        for mode in MODES
    }
    migration_versions = {
        mode: labels.get(f"pod-security.kubernetes.io/{mode}-version")
        for mode in MODES
    }
    lab.check(
        "green",
        "Restricted audit/warn stage admits the same request and returns a Restricted warning",
        has_restricted_warning(staged)
        and staged_audit == {"audit_event_observed": True, "restricted_violation": True,
                             "request_body_recorded": False}
        and migration_modes == {"enforce": "baseline", "audit": "restricted", "warn": "restricted"}
        and migration_versions == {mode: VERSION for mode in MODES},
        {
            "admitted": staged.returncode == 0,
            "warning": staged.stderr.strip(),
            **staged_audit,
            "modes": migration_modes,
            "versions": migration_versions,
        },
    )

    lab.kubectl(
        "label", "namespace", NAMESPACE,
        "pod-security.kubernetes.io/enforce=restricted",
        "--overwrite",
    )
    denied = server_dry_run(lab, challenge)
    lab.check(
        "green",
        "Restricted enforcement denies the identical request with a PSA reason",
        forbidden_for_restricted(denied),
        denied.stderr.strip(),
    )

    allowed = server_dry_run(lab, compliant)
    lab.check(
        "positive",
        "Compliant Restricted Pod is admitted without a Restricted violation warning",
        allowed.returncode == 0 and not has_restricted_warning(allowed),
        allowed.stderr.strip() or "server dry-run accepted without PSA warning",
    )
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(compliant))
    lab.kubectl(
        "-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{compliant['metadata']['name']}",
        "--timeout=95s", timeout=105,
    )
    lab.check(
        "positive",
        "Compliant Restricted Pod reaches Ready",
        True,
        "Ready",
    )
