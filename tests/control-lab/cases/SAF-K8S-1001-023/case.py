"""Exercise retrieval of previously archived synthetic kube-apiserver audit events."""
import base64
import gzip
import hashlib
import json
from pathlib import Path
import re
import time

from lab import NODE_IMAGE

HERE = Path(__file__).resolve().parent
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
AUDIT_DIR = "/var/log/kubernetes/audit"
NAMESPACE = "saf-1001-023"
CRONJOB = "verify-historical-audit-retrieval"
PRIMARY_ID = "saf-1001-023-primary"
COMPARISON_ID = "saf-1001-023-comparison"
SCOPE = (
    "One case-owned Kind v1.36.1 cluster with Metadata-level kube-apiserver audit logging; "
    "three exact synthetic ConfigMap create operations; captured ResponseComplete audit JSONL "
    "archived as gzip JSONL in immutable ConfigMaps; and in-cluster Jobs that independently "
    "resolve an index target, verify the exact compressed-object SHA-256, decompress, parse, and "
    "select historical event IDs. Two independently scheduled Jobs retrieve the same primary record across a "
    "workload restart, while a distinct comparator retrieves a different record. This is a "
    "small local fixture, not evidence of production archive redundancy or policy compliance."
)

READER = r'''import gzip, hashlib, json, os, pathlib
mode = os.environ["MODE"]
event_id = os.environ["EVENT_ID"]
index_path = pathlib.Path("/index") / (mode + ".json")
index = json.loads(index_path.read_text())
entry = index.get(event_id)
if entry is None:
    print(json.dumps({"status": "index-entry-missing", "event_id": event_id}))
    raise SystemExit(0)
target = pathlib.Path("/archive") / entry["target"]
if not target.is_file():
    print(json.dumps({"status": "object-unavailable", "event_id": event_id,
                      "target": entry["target"]}))
    raise SystemExit(0)
payload = target.read_bytes()
actual = hashlib.sha256(payload).hexdigest()
if actual != entry["sha256"]:
    print(json.dumps({"status": "digest-mismatch", "event_id": event_id,
                      "target": entry["target"], "expected_sha256": entry["sha256"],
                      "actual_sha256": actual}))
    raise SystemExit(0)
try:
    records = [json.loads(line) for line in gzip.decompress(payload).splitlines() if line]
except Exception as exc:
    print(json.dumps({"status": "parse-error", "event_id": event_id,
                      "error": type(exc).__name__}))
    raise SystemExit(0)
matches = [record for record in records
           if record.get("objectRef", {}).get("name") == event_id
           and record.get("apiVersion") == "audit.k8s.io/v1"
           and record.get("stage") == "ResponseComplete"]
if len(matches) != 1:
    print(json.dumps({"status": "record-missing-or-ambiguous", "event_id": event_id,
                      "parsed_records": len(records), "matches": len(matches)}))
    raise SystemExit(0)
print(json.dumps({"status": "retrieved", "event_id": event_id,
                  "target": entry["target"], "sha256": actual,
                  "parsed_records": len(records), "record": matches[0]}, sort_keys=True))
'''

NAIVE_READER = r'''import gzip, json, os, pathlib
event_id = os.environ["EVENT_ID"]
index = json.loads((pathlib.Path("/index") / "wrong-index.json").read_text())
entry = index[event_id]
records = [json.loads(line) for line in gzip.decompress(
    (pathlib.Path("/archive") / entry["target"]).read_bytes()).splitlines() if line]
print(json.dumps({"requested_event_id": event_id,
                  "returned_event_id": records[0].get("objectRef", {}).get("name"),
                  "parsed_records": len(records)}, sort_keys=True))
'''


def prepare_kind(_lab, temporary: Path) -> Path:
    audit_dir = temporary / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    policy = HERE / "audit-policy.yaml"
    config = temporary / "kind.yaml"
    config.write_text(f'''kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/audit-policy.yaml
        readOnly: true
      - hostPath: {json.dumps(str(audit_dir))}
        containerPath: {AUDIT_DIR}
        readOnly: false
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/audit-policy.yaml
        - name: audit-log-path
          value: {AUDIT_DIR}/audit.log
        - name: audit-log-mode
          value: blocking
      extraVolumes:
        - name: audit-policy
          hostPath: /etc/kubernetes/audit-policy.yaml
          mountPath: /etc/kubernetes/audit-policy.yaml
          readOnly: true
          pathType: File
        - name: audit-log
          hostPath: {AUDIT_DIR}
          mountPath: {AUDIT_DIR}
          readOnly: false
          pathType: DirectoryOrCreate
''')
    return config


def audit_id(stderr):
    ids = set(re.findall(r"(?i)\baudit-id\s*:\s*([a-f0-9-]{36})", stderr))
    if len(ids) != 1:
        raise RuntimeError(f"expected one API response Audit-Id, found {len(ids)}")
    return ids.pop()


def wait_audit(audit_file, expected_id):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if audit_file.exists():
            for line in audit_file.read_bytes().splitlines(keepends=True):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (line.endswith(b"\n") and record.get("auditID") == expected_id
                        and record.get("stage") == "ResponseComplete"):
                    return line, record
        time.sleep(.2)
    raise RuntimeError(f"ResponseComplete audit record {expected_id} did not appear")


def marker_event(lab, audit_file, event_id):
    marker = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        "name": event_id, "namespace": NAMESPACE, "labels": {"saf.synthetic": "true"}},
        "data": {"marker": event_id}}
    response = lab.kubectl("create", "--raw", f"/api/v1/namespaces/{NAMESPACE}/configmaps",
                           "-f", "-", "--v=8", payload=json.dumps(marker), timeout=25)
    line, record = wait_audit(audit_file, audit_id(response.stderr))
    ref = record.get("objectRef") or {}
    if (record.get("verb") != "create" or ref.get("resource") != "configmaps"
            or ref.get("namespace") != NAMESPACE or ref.get("name") != event_id
            or record.get("level") != "Metadata" or record.get("responseStatus", {}).get("code") != 201):
        lab.block("Matched audit event does not describe the exact successful fixture operation")
    return line, record


def archive_config(lab, name, binary_data, immutable=True):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "immutable": immutable,
                "metadata": {"name": name}, "binaryData": binary_data})


def index_config(lab, name, index):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
                "metadata": {"name": name},
                "data": {"healthy.json": json.dumps(index["healthy"], sort_keys=True),
                         "wrong-index.json": json.dumps(index["wrong-index"], sort_keys=True),
                         "missing-object.json": json.dumps(index["missing-object"], sort_keys=True)}})


def reader_template(mode, event_id, code=READER):
    container = {
        "name": "reader", "image": PYTHON_IMAGE, "command": ["python", "-c", code],
        "env": [{"name": "MODE", "value": mode}, {"name": "EVENT_ID", "value": event_id}],
        "volumeMounts": [{"name": name, "mountPath": f"/{name}", "readOnly": True}
                         for name in ("archive", "index")],
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}},
    }
    return {"backoffLimit": 0, "activeDeadlineSeconds": 75, "template": {"spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False, "containers": [container],
        "volumes": [{"name": name, "configMap": {"name": f"saf-audit-{name}"}}
                    for name in ("archive", "index")],
    }}}


def reader_result(lab, name):
    return json.loads(lab.kubectl("logs", f"job/{name}").stdout)


def reader_job(lab, name, mode, event_id, code=READER):
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": reader_template(mode, event_id, code)})
    wait = lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=85s",
                       timeout=95, allow_failure=True)
    if wait.returncode:
        logs = lab.kubectl("logs", f"job/{name}", allow_failure=True).stdout
        lab.block(f"Reader Job {name} did not complete: {logs}")
    return reader_result(lab, name)


def start_schedule(lab):
    return lab.create({"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": CRONJOB},
                       "spec": {"schedule": "* * * * *", "timeZone": "Etc/UTC",
                                "concurrencyPolicy": "Forbid", "successfulJobsHistoryLimit": 3,
                                "jobTemplate": {"spec": reader_template("healthy", PRIMARY_ID)}}})


def scheduled_results(lab, owner_uid):
    deadline = time.monotonic() + 145
    while time.monotonic() < deadline:
        listing = json.loads(lab.kubectl("get", "jobs", "-o", "json").stdout)
        jobs = [row for row in listing["items"] if any(
            ref["kind"] == "CronJob" and ref["uid"] == owner_uid
            for ref in row["metadata"].get("ownerReferences", []))]
        completed = [row for row in jobs if row["status"].get("succeeded") == 1]
        if len(completed) >= 2:
            break
        if any(row["status"].get("failed", 0) for row in jobs):
            lab.block("A scheduled retrieval Job failed")
        time.sleep(3)
    else:
        lab.block("The retrieval schedule produced fewer than two completed Jobs")
    lab.kubectl("patch", "cronjob", CRONJOB, "--type=merge", "-p", '{"spec":{"suspend":true}}')
    key = "batch.kubernetes.io/cronjob-scheduled-timestamp"
    result = []
    for row in sorted(completed, key=lambda item: item["metadata"]["annotations"][key])[:2]:
        meta = row["metadata"]
        pods = json.loads(lab.kubectl("get", "pods", "-l", f"batch.kubernetes.io/job-name={meta['name']}",
                                      "-o", "json").stdout)["items"]
        if len(pods) != 1:
            lab.block(f"Expected one scheduled reader Pod for {meta['name']}, saw {len(pods)}")
        result.append({"job_uid": meta["uid"], "pod_uid": pods[0]["metadata"]["uid"],
                       "scheduled_at": meta["annotations"][key], "owner_uid": owner_uid,
                       "result": reader_result(lab, meta["name"])})
    return result


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    audit_file = lab.kubeconfig.parent / "audit" / "audit.log"
    native = [marker_event(lab, audit_file, event_id)
              for event_id in (PRIMARY_ID, "saf-1001-023-primary-2", COMPARISON_ID)]
    records = [event for _, event in native]
    primary_raw = native[0][0] + native[1][0]
    comparator_raw = native[2][0]
    primary_gz = gzip.compress(primary_raw, mtime=0)
    comparator_gz = gzip.compress(comparator_raw, mtime=0)
    archive = {"primary.jsonl.gz": base64.b64encode(primary_gz).decode(),
               "comparison.jsonl.gz": base64.b64encode(comparator_gz).decode()}
    primary_entry = {"target": "primary.jsonl.gz", "sha256": hashlib.sha256(primary_gz).hexdigest()}
    comparison_entry = {"target": "comparison.jsonl.gz", "sha256": hashlib.sha256(comparator_gz).hexdigest()}
    healthy = {PRIMARY_ID: primary_entry, COMPARISON_ID: comparison_entry}
    wrong = {PRIMARY_ID: {"target": comparison_entry["target"], "sha256": primary_entry["sha256"]}}
    missing = {PRIMARY_ID: {"target": "unavailable.jsonl.gz", "sha256": primary_entry["sha256"]}}
    archive_config(lab, "saf-audit-archive", archive)
    index_config(lab, "saf-audit-index", {"healthy": healthy, "wrong-index": wrong,
                                           "missing-object": missing})

    cronjob = start_schedule(lab)
    naive = reader_job(lab, "unchecked-index-read", "wrong-index", PRIMARY_ID, code=NAIVE_READER)
    lab.check("red", "An unchecked readable index target returns the wrong historical audit event",
              naive["requested_event_id"] == PRIMARY_ID and naive["returned_event_id"] == COMPARISON_ID,
              naive)

    wrong_result = reader_job(lab, "detect-wrong-index", "wrong-index", PRIMARY_ID)
    missing_result = reader_job(lab, "detect-missing-object", "missing-object", PRIMARY_ID)
    lab.check("green", "Historical retrieval detects a wrong digest and an unavailable object",
              wrong_result["status"] == "digest-mismatch" and missing_result["status"] == "object-unavailable",
              {"wrong_index": wrong_result["status"], "missing_object": missing_result["status"]})

    comparator = reader_job(lab, "retrieve-healthy-comparator", "healthy", COMPARISON_ID)
    schedule = scheduled_results(lab, cronjob["metadata"]["uid"])
    first, second = schedule
    distinct = first["job_uid"] != second["job_uid"] and first["pod_uid"] != second["pod_uid"]
    separate_ticks = first["scheduled_at"] < second["scheduled_at"]
    primary_matches = all(
        item["result"].get("status") == "retrieved" and item["result"].get("record") == records[0]
        and item["result"].get("sha256") == primary_entry["sha256"] for item in schedule
    )
    comparator_matches = (comparator["status"] == "retrieved" and comparator["record"] == records[2]
                          and comparator["sha256"] == comparison_entry["sha256"])
    lab.check("positive", "Distinct CronJob runs recover the same native history and the comparator resolves separately",
              first["result"] == second["result"] and distinct and separate_ticks
              and primary_matches and comparator_matches,
              {"distinct_jobs_and_pods": distinct, "separate_schedule_ticks": separate_ticks,
               "same_primary_record": primary_matches, "comparator_exact": comparator_matches})

    (lab.evidence / "durable-retrieval-observations.json").write_text(json.dumps({
        "native_audit_records": records, "archive_objects_base64": archive, "independent_index": healthy,
        "negative_indexes": {"wrong-index": wrong, "missing-object": missing},
        "reader_results": {"unvalidated": naive, "wrong-index": wrong_result,
                           "missing-object": missing_result, "scheduled": schedule, "comparator": comparator},
    }, indent=2, sort_keys=True) + "\n")
