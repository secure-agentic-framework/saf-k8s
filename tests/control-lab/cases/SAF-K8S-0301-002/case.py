"""Require explicit PSA mode versions on managed production-like Namespaces."""
from pathlib import Path
import json
import time

from fixtures import container, pod

SCOPE = (
    "Admission of managed production-like Namespace PSA labels and local Pod Security "
    "Admission behavior, including an independently observed audit annotation, for pinned policy versions."
)

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NAMESPACE = "saf-0301-002-production"
LOG = "/var/log/kubernetes/saf-pin-audit.ndjson"
ANNOTATION = "pod-security.kubernetes.io/audit-violations"
CLASSIFICATION = "saf-k8s.example/managed-production-like"
VERSION = "v1.36"
MODES = ("enforce", "audit", "warn")


def prepare_kind(_lab, temporary):
    policy = temporary / "saf-pin-audit.json"
    policy.write_text(json.dumps({
        "apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
        "rules": [{"level": "Metadata", "verbs": ["create"], "namespaces": [NAMESPACE],
                   "resources": [{"group": "", "resources": ["pods"]}]}, {"level": "None"}],
    }))
    config = temporary / "kind-pin-audit.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/saf-pin-audit.json
        readOnly: true
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-pin-audit.json
        - name: audit-log-path
          value: {LOG}
      extraVolumes:
        - name: saf-pin-audit-policy
          hostPath: /etc/kubernetes/saf-pin-audit.json
          mountPath: /etc/kubernetes/saf-pin-audit.json
          readOnly: true
          pathType: File
        - name: saf-pin-audit-log
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          pathType: DirectoryOrCreate
""")
    return config



def namespace(name, *, versions=True):
    labels = {
        "saf-k8s.example/managed-production-like": "true",
        **{f"pod-security.kubernetes.io/{mode}": "restricted" for mode in MODES},
    }
    if versions:
        labels.update({f"pod-security.kubernetes.io/{mode}-version": VERSION
                       for mode in MODES})
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, "labels": labels}}


def server_create(lab, resource):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(resource), allow_failure=True)


def benign_pod():
    return pod("saf-0301-002-benign", [container("probe")])


def violating_dry_run_pod(name):
    # Deliberately submitted only as a server dry-run: no noncompliant Pod is persisted.
    obj = pod(name, [container(
        "probe", securityContext={"runAsNonRoot": True, "runAsUser": 65534,
                                  "seccompProfile": {"type": "RuntimeDefault"}})])
    obj["metadata"]["namespace"] = NAMESPACE
    return obj


def policy_denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and "explicit Kubernetes minor version pins" in result.stderr)


def run(lab):
    case_dir = Path(__file__).parent
    missing = namespace("saf-0301-002-missing", versions=False)
    floating = namespace("saf-0301-002-latest")
    for mode in MODES:
        floating["metadata"]["labels"][f"pod-security.kubernetes.io/{mode}-version"] = "latest"
    unclassified = namespace("saf-0301-002-staging-unclassified")
    del unclassified["metadata"]["labels"][CLASSIFICATION]
    for label, example in (("missing", missing), ("floating", floating), ("unclassified staging", unclassified)):
        before = server_create(lab, example)
        lab.check("red", f"The API accepts {label} pins before the namespace policy",
                  before.returncode == 0, before.stderr.strip() or "server dry-run accepted")
    lab.apply(case_dir / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        absent_result = server_create(lab, missing)
        if policy_denied(absent_result) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    latest = server_create(lab, floating)
    absent_membership = server_create(lab, unclassified)
    for label, result in (("missing", absent_result), ("floating", latest),
                          ("unclassified staging", absent_membership)):
        lab.check("green", f"The policy denies {label} pins on Namespace CREATE",
                  policy_denied(result), result.stderr.strip())

    outside = namespace("saf-0301-002-outside-fixture", versions=False)
    del outside["metadata"]["labels"][CLASSIFICATION]
    outside_ok = server_create(lab, outside).returncode == 0
    approved_privileged = namespace("saf-0301-002-staging-explicit-profile")
    approved_privileged["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] = "privileged"
    profile_ok = server_create(lab, approved_privileged).returncode == 0
    lab.check("positive", "Explicit supported profiles are accepted while an unrelated fixture namespace is out of scope",
              outside_ok and profile_ok, {"outside_fixture_unchallenged": outside_ok, "explicit_privileged_profile_accepted": profile_ok})

    # CREATE a fixture that will be mutated with server-side UPDATE dry-runs.
    lab.kubectl("create", "-f", "-", payload=json.dumps(namespace(NAMESPACE)))
    live = json.loads(lab.kubectl("get", "namespace", NAMESPACE, "-o", "json").stdout)
    variants = [(f"missing {mode} version", f"pod-security.kubernetes.io/{mode}-version", None)
                for mode in MODES]
    variants.extend((f"missing {mode} level", f"pod-security.kubernetes.io/{mode}", None)
                    for mode in MODES)
    variants.extend((f"floating {mode} version", f"pod-security.kubernetes.io/{mode}-version", "latest")
                    for mode in MODES)
    variants.extend([
        ("unsupported future version", "pod-security.kubernetes.io/enforce-version", "v1.99"),
        ("removed governance label", "saf-k8s.example/managed-production-like", None),
    ])
    for label, key, value in variants:
        update = json.loads(json.dumps(live))
        if value is None:
            del update["metadata"]["labels"][key]
        else:
            update["metadata"]["labels"][key] = value
        result = lab.kubectl("replace", "-f", "-", "--dry-run=server", "-o", "json",
                             payload=json.dumps(update), allow_failure=True)
        lab.check("green", f"The policy denies {label} on Namespace UPDATE",
                  policy_denied(result), result.stderr.strip())

    # A persisted, pinned production-like Namespace and a compliant workload establish
    # the accepted path. The second Pod is submitted only as dry-run to observe PSA.
    valid = lab.kubectl("get", "namespace", NAMESPACE, "-o", "json").stdout
    valid_obj = json.loads(valid)
    lab.check("positive", "Managed Namespace has explicit pins for enforce, audit, and warn",
              all(valid_obj["metadata"]["labels"].get(
                  f"pod-security.kubernetes.io/{mode}-version") == VERSION for mode in MODES),
              {mode: valid_obj["metadata"]["labels"].get(
                  f"pod-security.kubernetes.io/{mode}-version") for mode in MODES})
    lab.kubectl("-n", NAMESPACE, "wait", "--for=create", "serviceaccount/default", "--timeout=20s")
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(benign_pod()))
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", "pod/saf-0301-002-benign",
                "--timeout=95s", timeout=105)
    lab.check("positive", "Pinned Restricted namespace runs a benign workload", True, "Ready")
    args = ("-n", NAMESPACE, "create", "-f", "-", "--dry-run=server", "-o", "name")
    payload = json.dumps(violating_dry_run_pod("saf-enforce-pin"))
    rejected = lab.kubectl(*args, payload=payload, allow_failure=True)
    lab.check("green", "Pinned Restricted enforcement denies the test Pod",
              rejected.returncode != 0 and "restricted:v1.36" in rejected.stderr,
              rejected.stderr.strip())
    lab.kubectl("label", "namespace", NAMESPACE,
                "pod-security.kubernetes.io/enforce=baseline", "--overwrite")
    warning = lab.kubectl(*args, payload=json.dumps(violating_dry_run_pod("saf-warn-pin")), allow_failure=True)
    lab.check("positive", "Separately pinned Restricted warning reports the admitted Baseline probe",
              warning.returncode == 0 and "restricted:v1.36" in warning.stderr
              and "Warning: would violate PodSecurity" in warning.stderr, warning.stderr.strip())
    lab.kubectl("label", "namespace", NAMESPACE, "pod-security.kubernetes.io/warn=baseline", "--overwrite")
    audit_only = lab.kubectl(*args, payload=json.dumps(violating_dry_run_pod("saf-audit-pin")), allow_failure=True)
    benign = benign_pod()
    benign["metadata"].update(name="saf-audit-compliant", namespace=NAMESPACE)
    approved = lab.kubectl(*args, payload=json.dumps(benign), allow_failure=True)
    audit = audit_events(lab, {"saf-audit-pin", "saf-audit-compliant"})
    violation = audit["saf-audit-pin"]
    clean = audit["saf-audit-compliant"]
    recorded = ("restricted:v1.36" in violation.get("annotations", {}).get(ANNOTATION, "")
                and ANNOTATION not in clean.get("annotations", {}))
    lab.check("positive", "The pinned audit profile independently records a violation without warning or denying the request",
              audit_only.returncode == approved.returncode == 0 and not audit_only.stderr.strip() and recorded,
              {"audit_log_violation": recorded, "no_client_warning": not audit_only.stderr.strip(),
               "audit_and_compliant_allowed": audit_only.returncode == approved.returncode == 0})
    (lab.evidence / "psa-pins-observations.json").write_text(json.dumps({
        "namespace": NAMESPACE, "version_pins": {mode: valid_obj["metadata"]["labels"][
            f"pod-security.kubernetes.io/{mode}-version"] for mode in MODES},
        "unclassified_staging_denied": policy_denied(absent_membership),
        "out_of_scope_admitted": outside_ok, "explicit_supported_profile_admitted": profile_ok,
        "enforce_denied": rejected.stderr.strip(), "warn_reported": warning.stderr.strip(),
        "audit_only_events": audit, "annotation_key": ANNOTATION,
    }, indent=2) + "\n")


def audit_events(lab, names):
    node = lab.cluster + "-control-plane"
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        data = lab.command("docker", "exec", node, "cat", LOG, allow_failure=True)
        events = {}
        if not data.returncode:
            for line in data.stdout.splitlines():
                event = json.loads(line)
                obj = event.get("objectRef") or {}
                if (obj.get("name") in names and obj.get("namespace") == NAMESPACE and obj.get("resource") == "pods"
                        and event["stage"] == "ResponseComplete" and event["verb"] == "create"
                        and event["responseStatus"]["code"] == 201):
                    events[obj["name"]] = {key: event[key] for key in
                                           ("auditID", "objectRef", "stageTimestamp", "responseStatus", "annotations")}
        if events.keys() == names:
            return events
        time.sleep(0.3)
    lab.block("The distinct successful dry-run Pod events were not available in the fixture audit backend")
