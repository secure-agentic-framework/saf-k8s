"""Exercise Kubernetes API append, immutability, and authorization boundaries."""
import hashlib
import json
import time
from pathlib import Path

from lab import NODE_IMAGE

HERE = Path(__file__).resolve().parent
FIXTURE_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-1001-024-source"
ARCHIVE_NS = "saf-test"
AUDIT_DIR_IN_NODE = "/var/log/kubernetes/audit"
AUDIT_LOG = f"{AUDIT_DIR_IN_NODE}/audit.log"
POLICY = "saf-1001-024-immutable-append"
MAINTAINER = "saf-1001-024-maintainer"
SCOPE = (
    "Kubernetes v1.36.1 Kind with three actual native audit records from synthetic ConfigMap creates. "
    "The fixture appender's ServiceAccount can create immutable named ConfigMaps and read the ordered "
    "archive. Native admission denies mutable appends, RBAC denies ordinary update and deletion, "
    "identity reuse conflicts, and the underlying immutable data rejects an authorized maintenance "
    "patch. Production source completeness, SIEM storage, and privileged boundaries need separate evidence."
)

def prepare_kind(lab, temporary):
    """Expose the real kube-apiserver file backend under the runner temp directory."""
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


WRITER = r'''import hashlib, json, os, ssl, urllib.error, urllib.parse, urllib.request
from pathlib import Path

namespace = os.environ["FIXTURE_NAMESPACE"]
label = os.environ["FIXTURE_LABEL"]
fixtures = json.loads(os.environ["FIXTURE_RECORDS"])
base = "https://kubernetes.default.svc"
token_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
context = ssl.create_default_context(cafile=ca_path)
token = token_path.read_text().strip()
headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
collection = "/api/v1/namespaces/" + namespace + "/configmaps"

def call(method, path, obj=None):
    data = None if obj is None else json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers=dict(headers, **({"Content-Type": "application/json"} if data else {})))
    try:
        with urllib.request.urlopen(req, context=context, timeout=10) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        raw = error.read()
        try: parsed = json.loads(raw)
        except (ValueError, json.JSONDecodeError): parsed = None
        return error.code, parsed, raw.decode("utf-8", "replace")

def record_object(item):
    record_bytes = (item["raw_event"].encode() if "raw_event" in item
                    else json.dumps(item["record"], sort_keys=True, separators=(",", ":")).encode())
    return ({"apiVersion": "v1", "kind": "ConfigMap",
             "metadata": {"name": item["name"], "namespace": namespace,
                          "labels": {"saf-k8s.example/control-1001-024": "record"},
                          "annotations": {"saf-k8s.example/sequence": str(item["sequence"])}},
             "immutable": True, "data": {"record.json": record_bytes.decode()}}, record_bytes)

def read_record(name):
    status, obj, raw = call("GET", collection + "/" + name)
    if status != 200: raise RuntimeError("record GET returned " + str(status) + ": " + raw)
    value = obj["data"]["record.json"].encode()
    return {"name": name, "bytes": value.decode(), "sha256": hashlib.sha256(value).hexdigest(),
            "uid": obj["metadata"].get("uid"), "resource_version": obj["metadata"].get("resourceVersion"),
            "immutable": obj.get("immutable") is True}

def listed_records():
    selector = urllib.parse.urlencode({"labelSelector": label + "=record"})
    status, obj, raw = call("GET", collection + "?" + selector)
    if status != 200: raise RuntimeError("record LIST returned " + str(status) + ": " + raw)
    rows = []
    for item in obj["items"]:
        content = item["data"]["record.json"].encode()
        sequence = int(item["metadata"]["annotations"]["saf-k8s.example/sequence"])
        rows.append({"name": item["metadata"]["name"], "bytes": content.decode(), "sequence": sequence,
                     "sha256": hashlib.sha256(content).hexdigest(),
                     "uid": item["metadata"].get("uid"),
                     "resource_version": item["metadata"].get("resourceVersion"),
                     "immutable": item.get("immutable") is True})
    return sorted(rows, key=lambda row: row["name"])

mode = os.environ["MODE"]
if mode == "probe":
    obj, _ = record_object({"name": "saf-1001-024-unbound-probe", "sequence": 0,
                            "record": {"record_id": "probe", "sequence": 0, "synthetic": True}})
    status, body, raw = call("POST", collection, obj)
    print(json.dumps({"phase": "unbound-create", "status": status,
                      "reason": (body or {}).get("reason"), "message": (body or {}).get("message", raw)}))
    raise SystemExit(0)

# Confirm the API server's authenticated identity from the same projected token.
review_status, review, review_raw = call("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews",
                                         {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"})
if review_status != 201:
    raise SystemExit("SelfSubjectReview failed: " + str(review_status) + " " + review_raw)
username = review["status"]["userInfo"]["username"]

mutable, _ = record_object(fixtures[0])
mutable["metadata"]["name"] = "saf-1001-024-nonimmutable"
mutable["immutable"] = False
mutable_status, mutable_response, mutable_raw = call("POST", collection, mutable)

created = []
snapshots = {}
for item in fixtures:
    obj, expected_bytes = record_object(item)
    status, response, raw = call("POST", collection, obj)
    if status != 201:
        raise SystemExit("authorized create failed for " + item["name"] + ": " + str(status) + " " + raw)
    current = read_record(item["name"])
    if current["bytes"].encode() != expected_bytes or not current["immutable"]:
        raise SystemExit("created record bytes/immutability mismatch for " + item["name"])
    created.append({"name": item["name"], "sequence": item["sequence"], "status": status})
    snapshots[item["name"]] = current

# Capture the first record again after later appends: bytes and digest must match.
after_appends = {item["name"]: read_record(item["name"]) for item in fixtures}
continuity = {item["name"]: (snapshots[item["name"]]["bytes"] == after_appends[item["name"]]["bytes"]
                               and snapshots[item["name"]]["sha256"] == after_appends[item["name"]]["sha256"])
              for item in fixtures}

first = fixtures[0]
first_obj, _ = record_object(first)
existing = read_record(first["name"])
get_status, full_obj, get_raw = call("GET", collection + "/" + first["name"])
mutated = dict(full_obj)
mutated["data"] = dict(full_obj["data"], **{"record.json": "{\"record_id\":\"tampered\"}"})
update_status, update_body, update_raw = call("PUT", collection + "/" + first["name"], mutated)
delete_status, delete_body, delete_raw = call("DELETE", collection + "/" + first["name"])
first_obj["data"]["record.json"] = '{"fixture":"different bytes with the same record identity"}'
duplicate_status, duplicate_body, duplicate_raw = call("POST", collection, first_obj)

final_rows = listed_records()
expected_names = [item["name"] for item in fixtures]
expected_bytes = {item["name"]: snapshots[item["name"]]["bytes"] for item in fixtures}
readback_ok = ([row["name"] for row in final_rows] == expected_names
               and all(row["bytes"] == expected_bytes[row["name"]] and row["immutable"]
                       and row["uid"] == snapshots[row["name"]]["uid"] for row in final_rows))
sequence = [row["sequence"] for row in final_rows]
sequence_ok = sequence == [1, 2, 3]
output = {
    "identity": username,
    "created": created,
    "snapshots_after_create": snapshots,
    "snapshots_after_later_appends": after_appends,
    "continuity": continuity,
    "attempts": {
        "mutable_create": {"status": mutable_status, "reason": (mutable_response or {}).get("reason"),
                           "body": mutable_raw},
        "update": {"status": update_status, "reason": (update_body or {}).get("reason"), "body": update_raw},
        "delete": {"status": delete_status, "reason": (delete_body or {}).get("reason"), "body": delete_raw},
        "duplicate_create": {"status": duplicate_status, "reason": (duplicate_body or {}).get("reason"), "body": duplicate_raw}
    },
    "final_records": final_rows,
    "sequence": sequence,
    "readback_ok": readback_ok,
    "sequence_ok": sequence_ok
}
print(json.dumps(output, sort_keys=True))
'''


def fixtures():
    return json.loads((HERE / "fixtures.json").read_text())


def api_object(kind, name, **fields):
    return {"apiVersion": "v1", "kind": kind,
            "metadata": {"name": name, "namespace": "saf-test"}, **fields}


def writer_pod(fixture, mode, name):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": fixture["namespace"],
                     "labels": {"saf-k8s.example/control-1001-024": "writer"}},
        "spec": {
            "restartPolicy": "Never", "serviceAccountName": fixture["service_account"],
            "automountServiceAccountToken": True,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "writer", "image": FIXTURE_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-u", "-c", WRITER],
                "env": [
                    {"name": "MODE", "value": mode},
                    {"name": "FIXTURE_NAMESPACE", "value": fixture["namespace"]},
                    {"name": "FIXTURE_LABEL", "value": fixture["fixture_label"]},
                    {"name": "FIXTURE_RECORDS", "value": json.dumps(fixture["records"], sort_keys=True,
                                                                           separators=(",", ":"))},
                ],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "100m", "memory": "128Mi"}},
            }],
        },
    }


def wait_succeeded(lab, name):
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/" + name,
                "--timeout=90s", timeout=100)
    return lab.kubectl("logs", "pod/" + name).stdout.strip()


def native_inputs(lab, records):
    lab.kubectl("create", "namespace", NAMESPACE)
    names = {f"source-{row['sequence']}" for row in records}
    for name in sorted(names):
        lab.kubectl("-n", NAMESPACE, "create", "configmap", name, "--from-literal=content=owned-synthetic")
    deadline = time.monotonic() + 20
    audit_file = lab.kubeconfig.parent / "audit" / "audit.log"
    while time.monotonic() < deadline:
        found = {}
        for line in audit_file.read_bytes().splitlines(keepends=True) if audit_file.exists() else ():
            if not line.endswith(b"\n"):
                continue
            event = json.loads(line)
            ref = event.get("objectRef", {})
            if (ref.get("namespace") == NAMESPACE and ref.get("resource") == "configmaps"
                    and ref.get("name") in names and event.get("stage") == "ResponseComplete"
                    and event.get("level") == "Metadata" and event.get("verb") == "create"
                    and event.get("responseStatus", {}).get("code") == 201):
                if ref["name"] in found:
                    lab.block("Duplicate native audit response for a case-owned source")
                found[ref["name"]] = line
        if set(found) == names:
            ordered = [found[f"source-{row['sequence']}"] for row in records]
            (lab.evidence / "native-append-inputs.jsonl").write_bytes(b"".join(ordered))
            return [{"name": row["name"], "sequence": row["sequence"], "raw_event": line.decode()}
                    for row, line in zip(records, ordered)]
        time.sleep(.25)
    lab.block("The three exact native audit entries were not present")


def patch_record(lab, name, username):
    return lab.kubectl("--as=" + username, "patch", "configmap", name, "--type=merge", "-p",
                       '{"data":{"record.json":"maintenance fixture content"}}', allow_failure=True)


def install_immutable_gate(lab, username):
    api = "admissionregistration.k8s.io/v1"
    rules = [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["configmaps"], "operations": ["CREATE"]}]
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": rules},
                         "matchConditions": [{"name": "owned-writer",
                                              "expression": f"request.namespace == '{ARCHIVE_NS}' && request.userInfo.username == '{username}'"}],
                         "validations": [{"expression": "has(object.immutable) && object.immutable",
                                          "reason": "Forbidden", "message": "audit appends must be immutable"}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"]}})
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        readiness = lab.kubectl("--as=" + username, "create", "configmap", "saf-append-gate-readiness",
                                "--from-literal=fixture=synthetic", "--dry-run=server", allow_failure=True)
        if readiness.returncode == 1 and "audit appends must be immutable" in readiness.stderr:
            return
        time.sleep(.4)
    lab.block("The immutable append guard was not enforcing on the fixture identity")


def run(lab):
    f = fixtures()
    namespace = f["namespace"]
    f["records"] = native_inputs(lab, f["records"])
    writer_name = "system:serviceaccount:" + namespace + ":" + f["service_account"]
    maintenance_user = f"system:serviceaccount:{namespace}:{MAINTAINER}"
    mutable_control = "saf-1001-024-mutable-comparator"
    protected = f["records"][0]["name"]
    lab.create(api_object("ServiceAccount", MAINTAINER))
    lab.create(api_object("ConfigMap", mutable_control, data={"record.json": "initial synthetic bytes"}))
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": MAINTAINER}, "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                    "resourceNames": [mutable_control, protected], "verbs": ["get", "patch"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": MAINTAINER}, "subjects": [
                    {"kind": "ServiceAccount", "name": MAINTAINER, "namespace": namespace}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": MAINTAINER}})
    mutable = patch_record(lab, mutable_control, maintenance_user)
    lab.check("red", "The scoped maintenance role can patch a named mutable comparator",
              mutable.returncode == 0, {"maintenance_patch_allowed": mutable.returncode == 0})
    # An unbound identity can authenticate but cannot append a record.
    lab.create(api_object("ServiceAccount", f["service_account"]))
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": f["role"], "namespace": namespace},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                           "verbs": ["create", "get", "list"]}]})
    lab.create(writer_pod(f, "probe", f["probe_pod"]))
    probe = json.loads(wait_succeeded(lab, f["probe_pod"]))
    (lab.evidence / "append-integrity-observations.json").write_text(
        json.dumps({"unbound_probe": probe}, indent=2, sort_keys=True) + "\n")
    red_ok = probe.get("status") == 403 and probe.get("reason") == "Forbidden"
    lab.check("red", "The fixture identity cannot append before its scoped RoleBinding",
              red_ok, {"unbound_create_denied": red_ok})

    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": f["role_binding"], "namespace": namespace},
                "subjects": [{"kind": "ServiceAccount", "name": f["service_account"],
                              "namespace": namespace}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": f["role"]}})
    install_immutable_gate(lab, writer_name)
    lab.create(writer_pod(f, "exercise", f["writer_pod"]))
    observed = json.loads(wait_succeeded(lab, f["writer_pod"]))
    (lab.evidence / "append-integrity-observations.json").write_text(
        json.dumps({"unbound_probe": probe, "writer_observations": observed},
                   indent=2, sort_keys=True) + "\n")
    expected_identity = "system:serviceaccount:" + namespace + ":" + f["service_account"]
    positive_ok = (observed.get("identity") == expected_identity
                   and len(observed.get("created", [])) == len(f["records"])
                   and all(row.get("status") == 201 for row in observed.get("created", [])))
    lab.check("positive", "The named fixture ServiceAccount appends all three immutable records",
              positive_ok, {"fixture_identity_confirmed": positive_ok,
                            "authorized_appends": len(observed.get("created", []))})

    attempts = observed.get("attempts", {})
    deny_mutable = attempts["mutable_create"]
    maintenance = patch_record(lab, protected, maintenance_user)
    record = json.loads(lab.kubectl("get", "configmap", protected, "-o", "json").stdout)
    retained_bytes = record["data"]["record.json"] == f["records"][0]["raw_event"]
    lab.check("green", "Admission requires immutability and the API rejects mutation even for the named maintenance role",
              deny_mutable["status"] == 403 and "audit appends must be immutable" in deny_mutable["body"]
              and maintenance.returncode == 1 and "field is immutable" in maintenance.stderr
              and retained_bytes, {"mutable_create_http": deny_mutable["status"],
                                  "native_immutability_denial": "field is immutable" in maintenance.stderr,
                                  "native_audit_bytes_preserved": retained_bytes})
    update_denied = attempts.get("update", {}).get("status") == 403 and attempts.get("update", {}).get("reason") == "Forbidden"
    delete_denied = attempts.get("delete", {}).get("status") == 403 and attempts.get("delete", {}).get("reason") == "Forbidden"
    duplicate_refused = (attempts.get("duplicate_create", {}).get("status") == 409
                         and attempts.get("duplicate_create", {}).get("reason") == "AlreadyExists")
    stable = all(observed.get("continuity", {}).values()) and len(observed.get("continuity", {})) == 3
    sequence_ok = observed.get("readback_ok") is True and observed.get("sequence_ok") is True
    green_ok = update_denied and delete_denied and duplicate_refused and stable and sequence_ok
    lab.check("green", "RBAC refuses update/delete, duplicate identity is rejected, and later appends preserve the full readable sequence",
              green_ok, {"update_denied": update_denied, "delete_denied": delete_denied,
                         "duplicate_identity_refused": duplicate_refused, "bytes_and_digests_stable": stable,
                         "complete_sequence_readable": sequence_ok, "sequence": [1, 2, 3]})


    maintenance_state = {
        "mutable_comparator": {"returncode": mutable.returncode, "stdout": mutable.stdout},
        "immutable_attempt": {"returncode": maintenance.returncode, "stderr": maintenance.stderr},
        "original_digest": hashlib.sha256(f["records"][0]["raw_event"].encode()).hexdigest(),
        "retained_digest": hashlib.sha256(record["data"]["record.json"].encode()).hexdigest(),
    }
    (lab.evidence / "maintenance-observations.json").write_text(json.dumps(maintenance_state, indent=2) + "\n")
