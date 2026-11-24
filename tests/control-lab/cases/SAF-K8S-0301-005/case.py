"""Validate a synthetic PSA exception register record through live admission."""
import json
from pathlib import Path
import subprocess
import time
from urllib.parse import urlencode

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
    "and creates and updates one complete synthetic record. Fixture-created roles "
    "and impersonated identities verify exact-record writer and read-only access. "
    "A bounded snapshot reconciles one synthetic workload reference. Real API audit observes "
    "the targeted write bodies and Metadata-only reads and empty Secret creation. "
    "Deployed exception enforcement, approved policy choices, and audit retention "
    "require environment-specific evidence."
)
WRITER = f"system:serviceaccount:{NAMESPACE}:synthetic-register-writer"
READER = f"system:serviceaccount:{NAMESPACE}:synthetic-register-reader"
INVENTORY_LIMIT = 50


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
        "metadata": {"name": name, "namespace": NAMESPACE,
                      "labels": {"saf-k8s.example/case": "0301-005"}},
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


def submit(lab, obj, *, dry_run=True, actor=None):
    flags = ["--dry-run=server"] if dry_run else []
    if actor:
        flags.append("--as=" + actor)
    return lab.kubectl(
        "-n", NAMESPACE, "create", "-f", "-", "-o", "json", *flags,
        payload=json.dumps(obj), allow_failure=True,
    )


def install_fixture_roles(lab):
    """Create narrow fixture roles and bind them to auditable fixture identities."""
    writer = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "synthetic-register-writer", "namespace": NAMESPACE},
        "rules": [{"apiGroups": [GROUP], "resources": ["psaexceptionrecords"],
                   "resourceNames": ["synthetic-complete"], "verbs": ["get", "patch"]},
                  {"apiGroups": [GROUP], "resources": ["psaexceptionrecords"], "verbs": ["create"]}],
    }
    reader = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "synthetic-register-reader", "namespace": NAMESPACE},
        "rules": [{"apiGroups": [GROUP], "resources": ["psaexceptionrecords"],
                   "resourceNames": ["synthetic-complete"], "verbs": ["get"]}],
    }
    objects = [writer, reader]
    for name, role in (("synthetic-register-writer", "synthetic-register-writer"),
                       ("synthetic-register-reader", "synthetic-register-reader")):
        objects.extend([
            {"apiVersion": "v1", "kind": "ServiceAccount",
             "metadata": {"name": name, "namespace": NAMESPACE}},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
             "metadata": {"name": name, "namespace": NAMESPACE},
             "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role},
             "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": NAMESPACE}]},
        ])
    for obj in objects:
        lab.kubectl("-n", NAMESPACE, "apply", "-f", "-", payload=json.dumps(obj))


def bounded_inventory(lab):
    query = urlencode({"labelSelector": "saf-k8s.example/case=0301-005", "limit": INVENTORY_LIMIT})
    path = f"/apis/{GROUP}/{VERSION}/namespaces/{NAMESPACE}/psaexceptionrecords?{query}"
    snapshot = json.loads(lab.kubectl("get", "--raw", path).stdout)
    if snapshot["metadata"].get("continue"):
        lab.block("The fixture inventory exceeded its verification bound")
    return snapshot.get("items") or []


def reconcile_synthetic_workload(lab):
    expected = {"kind": "DaemonSet", "namespace": "synthetic-system", "name": "synthetic-inventory-agent"}

    def present():
        return any(item.get("spec", {}).get("workloadRef") == expected
                   and item.get("metadata", {}).get("annotations", {}).get(
                       "saf-k8s.example/fixture-approval") == "approved-synthetic-record"
                   for item in bounded_inventory(lab))

    missing = not present()
    lab.check("positive", "Bounded latest register inventory detects the missing owned synthetic workload record",
              missing, {"inventory_limit": INVENTORY_LIMIT, "owned_workload_record_missing": missing})
    approved = record("synthetic-inventory-agent", {
        "workloadRef": expected,
        "privileges": ["synthetic:device-access"],
        "justification": "Synthetic inventory fixture exercises bounded record reconciliation.",
        "riskOwner": "synthetic-inventory-owner@example.invalid",
        "compensatingControls": ["synthetic:network-isolation-review"],
    })
    approved["metadata"]["annotations"] = {
        "saf-k8s.example/fixture-approval": "approved-synthetic-record"
    }
    result = submit(lab, approved, dry_run=False, actor=WRITER)
    resolved = result.returncode == 0 and present()
    lab.check("positive", "Adding an approved record resolves the bounded inventory gap",
              resolved, {"approved_record_added": result.returncode == 0,
                         "owned_workload_record_present": resolved})
    return {"inventory_limit": INVENTORY_LIMIT, "owned_workload": expected,
            "missing_detected": missing, "approved_record_added": result.returncode == 0,
            "resolved": resolved}


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

    install_fixture_roles(lab)
    update = ("-n", NAMESPACE, "patch", "psaexceptionrecord", "synthetic-complete",
              "--type=merge", "-p")
    incomplete_change = lab.kubectl("--as=" + WRITER, *update,
                                    json.dumps({"spec": {"riskOwner": " "}}), allow_failure=True)
    stored = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "psaexceptionrecord", "synthetic-complete", "-o", "json",
    ).stdout)["spec"]
    lab.check("green", "Removing the risk owner from an existing record is denied and preserves it",
              policy_denied(incomplete_change) and stored == COMPLETE_SPEC,
              {"forbidden_by_policy": policy_denied(incomplete_change), "original_record_preserved": stored == COMPLETE_SPEC})

    new_owner = "synthetic-next-owner@example.invalid"
    repaired = json.loads(lab.kubectl(
        "--as=" + WRITER, *update, json.dumps({"spec": {"riskOwner": new_owner}}), "-o", "json",
    ).stdout)["spec"]
    lab.check("positive", "A complete update to the evidence record persists",
              repaired == {**COMPLETE_SPEC, "riskOwner": new_owner},
              {"expected_complete_update_persisted": repaired == {**COMPLETE_SPEC, "riskOwner": new_owner}})

    read_as_reader = lab.kubectl("--as=" + READER, "-n", NAMESPACE, "get",
                                 "psaexceptionrecord", "synthetic-complete", "-o", "json")
    reader_patch = lab.kubectl("--as=" + READER, *update,
                               json.dumps({"spec": {"riskOwner": "synthetic-unapproved@example.invalid"}}),
                               allow_failure=True)
    lab.check("positive", "Fixture reader role can read the exact record but cannot patch it",
              read_as_reader.returncode == 0 and reader_patch.returncode != 0
              and "(Forbidden)" in reader_patch.stderr,
              {"reader_get_allowed": read_as_reader.returncode == 0,
               "reader_patch_denied": reader_patch.returncode != 0 and "(Forbidden)" in reader_patch.stderr})


    empty_secret = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                    "metadata": {"name": "saf-empty-audit-fixture", "namespace": NAMESPACE}}
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "name",
                payload=json.dumps(empty_secret))
    audit_observations = check_audit_scope(lab, new_owner)
    inventory_observations = reconcile_synthetic_workload(lab)
    (lab.evidence / "psa-register-observations.json").write_text(json.dumps({
        "scope": "synthetic fixture only",
        "rbac": audit_observations["rbac"],
        "audit_records": audit_observations["events"],
        "audit": audit_observations["audit"],
        "inventory": inventory_observations,
    }, indent=2, sort_keys=True) + "\n")


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
            if resource == "psaexceptionrecords" and ref.get("name") == "synthetic-complete":
                actor = (event.get("impersonatedUser") or event.get("user", {})).get("username")
                if verb == "patch" and actor == WRITER and code == 200:
                    matched["write"] = event
                elif verb == "get" and actor == READER and code == 200:
                    matched["read"] = event
                elif verb == "patch" and actor == READER and code == 403:
                    matched["denied"] = event
            elif resource == "secrets" and verb == "create" and code == 201:
                matched["secret"] = event
        if set(matched) == {"write", "read", "denied", "secret"}:
            break
        time.sleep(0.3)
    if set(matched) != {"write", "read", "denied", "secret"}:
        lab.block("Expected exact approved writer, read-only reader, denied reader write, and empty Secret audit events")
    write, read, denied, secret = (matched[key] for key in ("write", "read", "denied", "secret"))
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
    rbac_audit = {
        "approved_writer": {"actor": write["impersonatedUser"]["username"], "verb": write.get("verb"),
                            "resource": write.get("objectRef", {}).get("resource"),
                            "name": write.get("objectRef", {}).get("name"),
                            "outcome": write.get("responseStatus", {}).get("code")},
        "read_only_reader": {"actor": read["impersonatedUser"]["username"], "verb": read.get("verb"),
                              "resource": read.get("objectRef", {}).get("resource"),
                              "name": read.get("objectRef", {}).get("name"),
                              "outcome": read.get("responseStatus", {}).get("code")},
        "reader_write_denied": {"actor": denied["impersonatedUser"]["username"], "verb": denied.get("verb"),
                                "resource": denied.get("objectRef", {}).get("resource"),
                                "name": denied.get("objectRef", {}).get("name"),
                                "outcome": denied.get("responseStatus", {}).get("code")},
    }
    role_checks = (rbac_audit["approved_writer"]["actor"] == WRITER
                   and rbac_audit["approved_writer"]["verb"] == "patch"
                   and rbac_audit["approved_writer"]["resource"] == "psaexceptionrecords"
                   and rbac_audit["approved_writer"]["name"] == "synthetic-complete"
                   and rbac_audit["approved_writer"]["outcome"] == 200
                   and rbac_audit["read_only_reader"]["actor"] == READER
                   and rbac_audit["read_only_reader"]["verb"] == "get"
                   and rbac_audit["read_only_reader"]["resource"] == "psaexceptionrecords"
                   and rbac_audit["read_only_reader"]["name"] == "synthetic-complete"
                   and rbac_audit["read_only_reader"]["outcome"] == 200
                   and rbac_audit["reader_write_denied"]["actor"] == READER
                   and rbac_audit["reader_write_denied"]["verb"] == "patch"
                   and rbac_audit["reader_write_denied"]["resource"] == "psaexceptionrecords"
                   and rbac_audit["reader_write_denied"]["name"] == "synthetic-complete"
                   and rbac_audit["reader_write_denied"]["outcome"] == 403)
    lab.check("positive", "Independent API audit events attribute exact writer and reader outcomes",
              role_checks, rbac_audit)
    records = {key: {name: event[name] for name in ("auditID", "stageTimestamp", "level", "responseStatus")}
               for key, event in matched.items()}
    return {"rbac": rbac_audit, "events": records, "audit": {
        "writer_request_response": selected_bodies,
        "reader_get_metadata": read["level"] == "Metadata",
        "reader_denied_patch_request_response": denied["level"] == "RequestResponse",
        "read_and_empty_secret_metadata_only": metadata_only,
    }}
