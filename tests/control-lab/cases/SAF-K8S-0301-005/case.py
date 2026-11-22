"""Validate a synthetic PSA exception register record through live admission."""
import json
from pathlib import Path
import subprocess
import time

HERE = Path(__file__).parent
NAMESPACE = "saf-0301-005-register"
GROUP = "security.saf-lab.example"
VERSION = "v1alpha1"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
AUDIT_POLICY = "/etc/kubernetes/saf-register-audit.yaml"
AUDIT_LOG = "/var/log/kubernetes/saf-register-audit.jsonl"
DENIAL = (
    "PSA exception register requires exact privileges, justification, risk owner, "
    "and compensating controls"
)
SCOPE = (
    "Live Kubernetes API admission for one case-owned, namespaced synthetic "
    "PSAExceptionRecord CRD. Compares one incomplete record before and after a "
    "ValidatingAdmissionPolicy, checks each required declaration independently, "
    "and creates and updates one complete synthetic record. Real API audit observes "
    "the targeted write bodies and Metadata-only reads and empty Secret creation. "
    "Deployed exception enforcement, approved policy choices, and audit retention "
    "require environment-specific evidence."
)


def prepare_kind(lab, temporary: Path) -> Path:
    policy = temporary / "audit-policy.yaml"
    policy.write_text(f"""apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
- level: Metadata
  resources:
  - group: ""
    resources: [secrets]
- level: RequestResponse
  verbs: [create, update, patch]
  namespaces: [{NAMESPACE}]
  resources:
  - group: "{GROUP}"
    resources: [psaexceptionrecords]
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


def record(name, spec):
    return {
        "apiVersion": f"{GROUP}/{VERSION}",
        "kind": "PSAExceptionRecord",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": spec,
    }


INCOMPLETE = record("synthetic-incomplete", {
    "workloadRef": {
        "kind": "DaemonSet",
        "namespace": "synthetic-system",
        "name": "synthetic-device-agent",
    },
})

COMPLETE_SPEC = {
    "workloadRef": {
        "kind": "DaemonSet",
        "namespace": "synthetic-system",
        "name": "synthetic-device-agent",
    },
    "privileges": ["synthetic:device-access"],
    "justification": "Synthetic fixture requires the named device access for its declared function.",
    "riskOwner": "synthetic-risk-owner@example.invalid",
    "compensatingControls": ["synthetic:network-isolation-review"],
}


def submit(lab, obj, *, dry_run=True):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl(
        "-n", NAMESPACE, "create", "-f", "-", "-o", "json", *flags,
        payload=json.dumps(obj), allow_failure=True,
    )


def policy_denied(result):
    return (
        result.returncode != 0
        and "(Forbidden)" in result.stderr
        and DENIAL in result.stderr
        and "saf-k8s-0301-005-complete-exception-register" in result.stderr
    )


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("label", "namespace", NAMESPACE, "saf-k8s.example/case=0301-005")
    lab.apply(HERE / "exception-record-crd.yaml")
    lab.kubectl(
        "wait", "--for=condition=Established",
        "crd/psaexceptionrecords.security.saf-lab.example", "--timeout=45s",
    )

    # Red baseline: the same typed but incomplete object is valid to the API
    # schema and is accepted by real server admission before the register policy.
    before = submit(lab, INCOMPLETE)
    lab.check(
        "red",
        "API accepts the incomplete typed register record before policy",
        before.returncode == 0,
        before.stderr.strip() or "server-side dry-run admitted",
    )

    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 20
    after = submit(lab, INCOMPLETE)
    while not policy_denied(after) and time.monotonic() < deadline:
        time.sleep(0.5)
        after = submit(lab, INCOMPLETE)
    lab.check(
        "green",
        "The same incomplete record is rejected by the active admission policy",
        policy_denied(after),
        after.stderr.strip(),
    )

    # Isolate each required declaration to make the reason for rejection
    # reviewable; all these are inert server-side dry-runs of synthetic records.
    for field in ("privileges", "justification", "riskOwner", "compensatingControls"):
        partial_spec = dict(COMPLETE_SPEC)
        del partial_spec[field]
        result = submit(lab, record(f"synthetic-missing-{field.lower()}", partial_spec))
        lab.check(
            "green",
            f"Admission rejects a record missing {field}",
            policy_denied(result),
            result.stderr.strip(),
        )

    for field, empty_value in (("privileges", [" "]), ("justification", "  "),
                               ("riskOwner", "  "), ("compensatingControls", [""])):
        empty_spec = dict(COMPLETE_SPEC)
        empty_spec[field] = empty_value
        result = submit(lab, record(f"synthetic-empty-{field.lower()}", empty_spec))
        lab.check(
            "green",
            f"Admission rejects a blank {field} declaration",
            policy_denied(result),
            result.stderr.strip(),
        )

    # The only persisted object is a complete synthetic register record.
    complete = record("synthetic-complete", COMPLETE_SPEC)
    created = submit(lab, complete, dry_run=False)
    persisted = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "psaexceptionrecord", "synthetic-complete", "-o", "json",
    ).stdout)
    lab.check(
        "positive",
        "Admission accepts and stores the explicitly complete synthetic record",
        created.returncode == 0 and persisted.get("spec") == COMPLETE_SPEC,
        persisted.get("spec"),
    )

    update = ("-n", NAMESPACE, "patch", "psaexceptionrecord", "synthetic-complete",
              "--type=merge", "-p")
    incomplete_change = lab.kubectl(*update, json.dumps({"spec": {"riskOwner": " "}}), allow_failure=True)
    stored = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "psaexceptionrecord", "synthetic-complete", "-o", "json",
    ).stdout)["spec"]
    lab.check("green", "Removing the risk owner from an existing record is denied and preserves it",
              policy_denied(incomplete_change) and stored == COMPLETE_SPEC,
              {"forbidden_by_policy": policy_denied(incomplete_change), "original_record_preserved": stored == COMPLETE_SPEC})

    new_owner = "synthetic-next-owner@example.invalid"
    repaired = json.loads(lab.kubectl(
        *update, json.dumps({"spec": {"riskOwner": new_owner}}), "-o", "json",
    ).stdout)["spec"]
    lab.check("positive", "A complete update to the evidence record persists",
              repaired == {**COMPLETE_SPEC, "riskOwner": new_owner},
              {"expected_complete_update_persisted": repaired == {**COMPLETE_SPEC, "riskOwner": new_owner}})


    empty_secret = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                    "metadata": {"name": "saf-empty-audit-fixture", "namespace": NAMESPACE}}
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "name",
                payload=json.dumps(empty_secret))
    check_audit_scope(lab, new_owner)


def check_audit_scope(lab, owner):
    node = f"{lab.cluster}-control-plane"
    deadline = time.monotonic() + 12
    matched = {}
    while time.monotonic() < deadline:
        result = subprocess.run(["docker", "exec", node, "cat", AUDIT_LOG], capture_output=True,
                                env=lab.env, text=True, timeout=8)
        if result.returncode != 0:
            time.sleep(0.3)
            continue
        for line in result.stdout.splitlines():
            event = json.loads(line)
            ref = event.get("objectRef", {})
            code = event.get("responseStatus", {}).get("code")
            if event.get("stage") != "ResponseComplete" or ref.get("namespace") != NAMESPACE:
                continue
            resource, verb = ref.get("resource"), event.get("verb")
            if resource == "psaexceptionrecords" and ref.get("name") == "synthetic-complete" and code == 200:
                if verb == "patch":
                    matched["write"] = event
                elif verb == "get":
                    matched["read"] = event
            elif resource == "secrets" and verb == "create" and code == 201:
                matched["secret"] = event
        if set(matched) == {"write", "read", "secret"}:
            break
        time.sleep(0.3)
    if set(matched) != {"write", "read", "secret"}:
        lab.block("Expected exact successful register write/read and empty Secret audit events")
    write, read, secret = (matched[key] for key in ("write", "read", "secret"))
    selected_bodies = (write["level"] == "RequestResponse"
                       and write.get("requestObject", {}).get("spec", {}).get("riskOwner") == owner
                       and write.get("responseObject", {}).get("spec", {}).get("riskOwner") == owner)
    lab.check("positive", "The selected register write has the intended request and response evidence",
              selected_bodies, {"request_response_for_exact_register_write": selected_bodies})
    metadata_only = all(event["level"] == "Metadata"
                        and not {"requestObject", "responseObject"}.intersection(event)
                        for event in (read, secret))
    lab.check("green", "The same namespace retains register reads and empty Secret creation at Metadata",
              metadata_only, {"register_read_and_empty_secret": metadata_only, "body_fields_absent": metadata_only})
