"""Exercise privacy classification, scoped file and API reads, and log access on Kind."""
from datetime import datetime
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
PVC = "fixture-privacy-data"
CODE = "fixture-privacy-code"
INDEX = "fixture-approved-data-index"
OTHER = "fixture-other-data-index"
NS = "saf-test"
GROUP = 20100
PROCESSOR = "fixture-data-processor"
ALLOWED = "fixture-data-reader"
DENIED = "fixture-other-reader"
AUDITOR = "fixture-data-auditor"
RBAC = "rbac.authorization.k8s.io/v1"
DATASET = "fixture-training-approved-v1"
SCOPE = (
    "On local Kind, an unchecked baseline publishes invented identifiers and an unapproved data "
    "version. A governed processor minimizes the approved version and creates only a hold receipt "
    "for the second. Distinct read-only UIDs with different supplemental groups exercise actual file "
    "reads. Kubernetes separately enforces exact ConfigMap and Pod log read permissions. Pod logs "
    "are application data-access evidence, not API-server or provider-level auditing."
)


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def grant(lab, name, resources, account):
    create(lab, "Role", name, RBAC, rules=resources)
    create(lab, "RoleBinding", name, RBAC,
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name},
           subjects=[{"kind": "ServiceAccount", "name": account, "namespace": NS}])


def pod(lab, image, name, account, command, uid, groups, *, read_only=False, root=False):
    security = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                "readOnlyRootFilesystem": True}
    if root:
        security["capabilities"]["add"] = ["CHOWN"]
    lab.create({
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
        "spec": {"restartPolicy": "Never", "serviceAccountName": account,
                 "automountServiceAccountToken": False,
                 "securityContext": {"runAsUser": uid, "runAsGroup": GROUP if uid == 10001 else 10000,
                                     "supplementalGroups": groups, "runAsNonRoot": not root,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": PVC}},
                             {"name": "code", "configMap": {"name": CODE}}],
                 "containers": [{
                     "name": "fixture", "image": image, "imagePullPolicy": "Never", "command": command,
                     "volumeMounts": [{"name": "data", "mountPath": "/store", "readOnly": read_only},
                                      {"name": "code", "mountPath": "/fixture", "readOnly": True}],
                     "securityContext": security,
                     "env": [{"name": env, "valueFrom": {"fieldRef": {"fieldPath": field}}}
                             for env, field in (("POD_NAMESPACE", "metadata.namespace"),
                                                ("POD_ACCOUNT", "spec.serviceAccountName"))],
                 }]}})
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                "--timeout=75s", timeout=85)


def principal(account):
    return f"system:serviceaccount:{NS}:{account}"


def observed(lab, name, account=None):
    if account is None:
        return json.loads(lab.kubectl("logs", f"pod/{name}").stdout)
    line = lab.kubectl("logs", f"pod/{name}", "--timestamps", f"--as={principal(account)}").stdout.strip()
    timestamp, event = line.split(" ", 1)
    valid = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d{1,9})?Z",
                         timestamp)
    if valid:
        datetime.fromisoformat(valid[1])
    return json.loads(event), bool(valid)


def run(lab):
    path = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_0907_002_runtime", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    image = runtime.load_runtime(lab)

    for account in (PROCESSOR, ALLOWED, DENIED, AUDITOR):
        create(lab, "ServiceAccount", account, automountServiceAccountToken=False)
    create(lab, "ConfigMap", CODE, immutable=True, data={
        name: (HERE / name).read_text() for name in ("privacy_worker.py", "data_fixture.py")
    })
    for index, classification in ((INDEX, "internal-synthetic"), (OTHER, "restricted-synthetic")):
        create(lab, "ConfigMap", index, immutable=True, data={"classification": classification})
    create(lab, "PersistentVolumeClaim", PVC, spec={
        "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "64Mi"}}
    })

    seed = ["sh", "-ec", "mkdir /store/approved /store/held /store/baseline; "
            "chmod 2750 /store/approved; chmod 2700 /store/held /store/baseline; "
            "chown 10001:20100 /store/approved /store/held /store/baseline"]
    pod(lab, image, "fixture-data-seed", PROCESSOR, seed, 0, [], root=True)
    worker = ["python", "/fixture/privacy_worker.py"]
    pod(lab, image, "fixture-unchecked-data", PROCESSOR, [*worker, "baseline"], 10001, [GROUP])
    pod(lab, image, "fixture-governed-data", PROCESSOR, [*worker, "process"], 10001, [GROUP])
    pod(lab, image, "fixture-audit-data", PROCESSOR, [*worker, "inspect"],
        10001, [GROUP], read_only=True)
    inspection = observed(lab, "fixture-audit-data")
    processor = observed(lab, "fixture-governed-data")
    red = {
        "direct_identifiers_reached_unchecked_storage": inspection["unrestricted_baseline_retained_direct_identifiers"],
        "unapproved_version_reached_unchecked_storage": inspection["unrestricted_baseline_published_held_version"],
    }
    lab.check("red", "Unchecked intake publishes identifiers and an unapproved version",
              all(red.values()), red)

    grant(lab, "fixture-data-index-grant", [{
        "apiGroups": [""], "resources": ["configmaps"], "resourceNames": [INDEX], "verbs": ["get"]
    }], ALLOWED)
    read_pods = ["fixture-approved-data-read", "fixture-denied-data-read"]
    grant(lab, "fixture-data-audit-grant", [{
        "apiGroups": [""], "resources": ["pods", "pods/log"], "resourceNames": read_pods, "verbs": ["get"]
    }], AUDITOR)
    for name, account, uid, groups in ((read_pods[0], ALLOWED, 10002, [GROUP]),
                                       (read_pods[1], DENIED, 10003, [])):
        pod(lab, image, name, account, [*worker, "read"], uid, groups, read_only=True)
    allowed_event, allowed_timestamp = observed(lab, read_pods[0], AUDITOR)
    denied_event, denied_timestamp = observed(lab, read_pods[1], AUDITOR)

    api = {}
    for key, resource, account in (("named_index", INDEX, ALLOWED),
                                    ("other_index", OTHER, ALLOWED), ("wrong_reader", INDEX, DENIED)):
        result = lab.kubectl("get", "configmap", resource, "-o", "json",
                             f"--as={principal(account)}", allow_failure=True)
        if result.returncode == 0:
            api[key] = json.loads(result.stdout)["data"]["classification"]
        else:
            api[key] = "forbidden" if "Forbidden" in result.stderr else "unexpected-error"
    audit_denial = lab.kubectl("logs", f"pod/{read_pods[0]}", f"--as={principal(DENIED)}",
                               allow_failure=True)
    green = {
        "held_file_absent": inspection["held_dataset_has_disposition_only"],
        "invented_direct_identifier_fields_and_values_removed":
            inspection["approved_durable_output_matches_minimized_contract"],
        "unapproved_uid_denied_at_file_boundary": denied_event == {
            "event": "training-data-read", "dataset_id": DATASET, "principal": principal(DENIED),
            "uid": 10003, "decision": "denied", "reason": "permission-denied",
        },
        "named_kubernetes_api_scope_enforced": api == {
            "named_index": "internal-synthetic", "other_index": "forbidden", "wrong_reader": "forbidden",
        },
        "unapproved_reader_cannot_read_someone_elses_audit_log":
            audit_denial.returncode != 0 and "Forbidden" in audit_denial.stderr,
    }
    lab.check("green", "Governed intake holds unapproved data and denies out-of-scope reads",
              all(green.values()), green)
    positive = {
        "approved_uid_reads_exact_minimized_bytes": allowed_event == {
            "event": "training-data-read", "dataset_id": DATASET, "principal": principal(ALLOWED),
            "uid": 10002, "decision": "allowed", "output_sha256": inspection["approved_sha256"], "row_count": 2,
        } and inspection["approved_sha256"] == processor["approved"]["output_sha256"],
        "scoped_auditor_queries_both_timestamped_events": allowed_timestamp and denied_timestamp,
    }
    lab.check("positive", "Authorized reader and scoped auditor can use the minimized data path",
              all(positive.values()), positive)
    (lab.evidence / "privacy-classification-observations.json").write_text(json.dumps({
        "processor": processor, "durable_observation": inspection, "api_reads": api,
        "access_events": [allowed_event, denied_event],
        "timestamped_log_records_verified": [allowed_timestamp, denied_timestamp],
        "checks": {"red": red, "green": green, "positive": positive},
    }, indent=2, sort_keys=True) + "\n")
