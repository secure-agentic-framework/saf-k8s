"""Reusable SAF-K8S-0601-011 scheduled-retention fixture draft.

Call ``run(lab)`` from the matching case's normal ``run(lab)`` after its
policy-only checks. This helper owns all cluster objects and registry data.
It deliberately performs no GC: deleting OCI manifests is the controller
action under test; storage is discarded with the Lab-owned Kind cluster.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import time
import uuid


REGISTRY = "docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"


# This code is mounted read-only into short-lived fixture Jobs. It uses only
# Python's standard library and the registry's in-cluster Service address.
WORKER = r'''import datetime
import hashlib
import http.client
import json
import sys
import urllib.parse

BASE = "http://retention-registry:5000"
MEDIA = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"
ARTIFACT = "application/vnd.oci.image.manifest.v1+json"
EMPTY = b"{}"
POLICY = json.load(open("/fixture/policy.json", encoding="utf-8"))

def sha(b): return "sha256:" + hashlib.sha256(b).hexdigest()
def canon(v): return json.dumps(v, sort_keys=True, separators=(",", ":")).encode()

def request(path, method="GET", body=None, ctype=None, accept=None, expected=(200,)):
    headers = {}
    if ctype: headers["Content-Type"] = ctype
    if accept: headers["Accept"] = accept
    connection = http.client.HTTPConnection("retention-registry", 5000, timeout=8)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        status, data, headers = response.status, response.read(), dict(response.getheaders())
    finally:
        connection.close()
    if status not in expected:
        raise RuntimeError(f"{method} {path}: HTTP {status}, expected {expected}")
    return status, data, headers

def put_blob(repo, raw):
    _, _, h = request(f"/v2/{repo}/blobs/uploads/", "POST", b"", expected=(202,))
    loc = urllib.parse.urlsplit(urllib.parse.urljoin(BASE, h.get("Location", "")))
    if (loc.scheme != "http" or loc.netloc != "retention-registry:5000"
            or not loc.path.startswith(f"/v2/{repo}/blobs/uploads/")):
        raise RuntimeError("upload Location escaped fixture registry Service")
    query = loc.query + "&" if loc.query else ""
    path = loc.path + "?" + query + urllib.parse.urlencode({"digest": sha(raw)})
    request(path, "PUT", raw, "application/octet-stream", expected=(201,))
    return {"mediaType": "application/octet-stream", "digest": sha(raw), "size": len(raw)}

def put_manifest(repo, raw, media=MEDIA):
    d = sha(raw)
    request(f"/v2/{repo}/manifests/{d}", "PUT", raw, media, expected=(201,))
    return d

def fetch(repo, digest):
    status, raw, _ = request(f"/v2/{repo}/manifests/{digest}", accept=f"{MEDIA}, {INDEX}, {ARTIFACT}", expected=(200, 404))
    if status == 200 and sha(raw) != digest: raise RuntimeError("manifest digest mismatch")
    return status, raw

def ref_tag(d):
    alg, encoded = d.split(":", 1)
    return alg[:32] + "-" + encoded[:64]

def seed():
    result = {}
    for row in POLICY:
        repo = "retention/" + row["id"]
        layer_bytes = b"SAF-K8S-0601-011 benign static fixture payload\n"
        layer = put_blob(repo, layer_bytes)
        config = put_blob(repo, EMPTY)
        subject = {"schemaVersion": 2, "mediaType": MEDIA,
                   "config": {**config, "mediaType": "application/vnd.oci.empty.v1+json"},
                   "layers": [layer]}
        subject_raw = canon(subject)
        sd = put_manifest(repo, subject_raw)
        artifact_bytes = b"SAF-K8S-0601-011 benign static referrer payload\n"
        blob = put_blob(repo, artifact_bytes)
        artifact = {"schemaVersion": 2, "mediaType": ARTIFACT,
                    "artifactType": "application/vnd.saf.fixture.retention.v1",
                    "config": {**config, "mediaType": "application/vnd.oci.empty.v1+json"},
                    "layers": [blob], "subject": {"mediaType": MEDIA, "digest": sd, "size": len(subject_raw)}}
        artifact_raw = canon(artifact)
        rd = put_manifest(repo, artifact_raw, ARTIFACT)
        ref_index = {"schemaVersion": 2, "mediaType": INDEX,
                     "manifests": [{"mediaType": ARTIFACT, "digest": rd, "size": len(artifact_raw),
                                    "artifactType": "application/vnd.saf.fixture.retention.v1"}]}
        tag = ref_tag(sd)
        request(f"/v2/{repo}/manifests/{tag}", "PUT", canon(ref_index), INDEX, expected=(201,))
        result[row["id"]] = {"repo": repo, "subject": sd, "referrer": rd,
                              "referrers_tag": tag, "payload_digest": layer["digest"],
                              "created_at": row["created_at"]}
    print(json.dumps({"event": "seeded", "objects": result}, sort_keys=True))

def decide(row, now):
    created = datetime.datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))
    retain = datetime.datetime.fromisoformat(row["retain_until"].replace("Z", "+00:00"))
    age = max(0, (now - created).total_seconds())
    reasons = []
    if row["hold"]: reasons.append("hold")
    if now < retain: reasons.append("retention_active")
    if row["subject_retained"]: reasons.append("subject_retained")
    if age < row["minimum_age_seconds"]: reasons.append("minimum_age")
    return not reasons, {"age_seconds": int(age), "reasons": reasons}

def retire():
    now = datetime.datetime.now(datetime.timezone.utc)
    decisions, deleted = {}, []
    for row in POLICY:
        eligible, why = decide(row, now)
        repo = "retention/" + row["id"]
        # Independently require the subject and its real OCI referrer to exist,
        # and require the referrer to be discoverable through Distribution's
        # OCI referrers-tag fallback before authorizing a deletion.
        s_status, _ = fetch(repo, row["subject"])
        r_status, referrer = fetch(repo, row["referrer"])
        _, index_raw, _ = request(f"/v2/{repo}/manifests/{row['referrers_tag']}", accept=INDEX)
        entries = json.loads(index_raw).get("manifests", [])
        if (s_status != 200 or r_status != 200
                or json.loads(referrer).get("subject", {}).get("digest") != row["subject"]
                or not any(x.get("digest") == row["referrer"] for x in entries)):
            raise RuntimeError("OCI subject/referrer precondition failed for " + row["id"])
        decisions[row["id"]] = {"eligible": eligible, **why}
        if eligible:
            index = json.loads(index_raw)
            index["manifests"] = [x for x in entries if x.get("digest") != row["referrer"]]
            request(f"/v2/{repo}/manifests/{row['referrers_tag']}", "PUT", json.dumps(index, sort_keys=True, separators=(",", ":")).encode(), INDEX, expected=(201,))
            for digest in (row["referrer"], row["subject"]):
                request(f"/v2/{repo}/manifests/{digest}", "DELETE", expected=(202,))
                deleted.append({"id": row["id"], "digest": digest})
    print(json.dumps({"event": "retired", "evaluated_at": now.isoformat(),
                      "decisions": decisions, "deleted": deleted}, sort_keys=True))

def observe():
    observed = {}
    for row in POLICY:
        repo = "retention/" + row["id"]
        observed[row["id"]] = {}
        for key in ("subject", "referrer"):
            status, raw = fetch(repo, row[key])
            observed[row["id"]][key] = status
            if status == 200:
                manifest = json.loads(raw)
                for layer in manifest["layers"]:
                    payload_status, payload, _ = request(f"/v2/{repo}/blobs/{layer['digest']}")
                    if payload_status != 200 or sha(payload) != layer["digest"]:
                        raise RuntimeError("retrieved payload digest does not match its manifest")
        status, raw, _ = request(f"/v2/{repo}/manifests/{row['referrers_tag']}", accept=INDEX, expected=(200, 404))
        observed[row["id"]]["referrers_index"] = status
        observed[row["id"]]["referrer_listed"] = (
            status == 200 and any(x.get("digest") == row["referrer"] for x in json.loads(raw).get("manifests", [])))
    print(json.dumps({"event": "observed", "objects": observed}, sort_keys=True))

{"seed": seed, "retire": retire, "observe": observe}[sys.argv[1]]()
'''


def _rfc3339(value: str) -> datetime:
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", value):
        raise ValueError("scheduled timestamp is not RFC3339")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks timezone")
    return parsed


def _policy() -> list[dict]:
    now = datetime.now(timezone.utc)
    stamp = lambda delta: (now + delta).isoformat(timespec="seconds").replace("+00:00", "Z")
    base = {"age_seconds": 30 * 86400, "minimum_age_seconds": 7 * 86400,
            "retain_until": stamp(timedelta(days=-1)), "hold": False,
            "subject_retained": False}
    rows = [
        {**base, "id": "eligible", "hold": False, "subject_retained": False},
        {**base, "id": "equivalent-held", "hold": True},
        {**base, "id": "negative-young", "age_seconds": 86400},
        {**base, "id": "negative-retain-until", "retain_until": stamp(timedelta(days=1))},
        {**base, "id": "negative-subject-retained", "subject_retained": True},
    ]
    for row in rows:
        row["created_at"] = stamp(timedelta(seconds=-row["age_seconds"]))
    return rows


def _resources(run_id: str, policy: list[dict]) -> list[dict]:
    labels = {"app.kubernetes.io/name": "saf-retention-fixture", "saf-fixture-run": run_id}
    worker_volume = [{"name": "fixture", "configMap": {"name": "retention-worker"}}]
    worker_mount = [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]
    config = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "retention-worker"},
              "immutable": True, "data": {"worker.py": WORKER, "policy.json": json.dumps(policy, sort_keys=True)}}
    registry_cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "retention-registry-config"},
                   "data": {"config.yml": "version: 0.1\nstorage:\n  filesystem:\n    rootdirectory: /var/lib/registry\n  delete:\n    enabled: true\nhttp:\n  addr: :5000\n  relativeurls: true\n"}}
    registry = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "retention-registry"},
                "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "retention-registry"}},
                         "template": {"metadata": {"labels": {"app": "retention-registry"}},
                                      "spec": {"automountServiceAccountToken": False,
                                               "containers": [{"name": "registry", "image": REGISTRY,
                                                  "imagePullPolicy": "IfNotPresent",
                                                  "ports": [{"name": "http", "containerPort": 5000}],
                                                  "env": [{"name": "REGISTRY_CONFIGURATION_PATH", "value": "/etc/distribution/config.yml"}],
                                                  "readinessProbe": {"httpGet": {"path": "/v2/", "port": "http"},
                                                                     "periodSeconds": 2, "failureThreshold": 15},
                                                  "volumeMounts": [{"name": "config", "mountPath": "/etc/distribution", "readOnly": True}]}],
                                               "volumes": [{"name": "config", "configMap": {"name": "retention-registry-config"}}]}}}}
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "retention-registry"},
               "spec": {"type": "ClusterIP", "selector": {"app": "retention-registry"},
                        "ports": [{"name": "http", "port": 5000, "targetPort": 5000}]}}

    def job(name: str, mode: str) -> dict:
        return {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name, "labels": labels},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 45,
                         "template": {"metadata": {"labels": labels}, "spec": {
                             "restartPolicy": "Never", "automountServiceAccountToken": False,
                             "containers": [{"name": "worker", "image": PYTHON, "imagePullPolicy": "IfNotPresent",
                                             "command": ["python", "/fixture/worker.py", mode],
                                             "volumeMounts": worker_mount}], "volumes": worker_volume}}}}

    cron = {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": "retention-scheduler", "labels": labels},
            "spec": {"schedule": "* * * * *", "timeZone": "Etc/UTC", "suspend": False,
                     "concurrencyPolicy": "Forbid", "startingDeadlineSeconds": 20,
                     "successfulJobsHistoryLimit": 1, "failedJobsHistoryLimit": 1,
                     "jobTemplate": {"metadata": {"labels": labels},
                         "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 45,
                                  "template": {"metadata": {"labels": labels}, "spec": {
                                      "restartPolicy": "Never", "automountServiceAccountToken": False,
                                      "containers": [{"name": "retention-controller", "image": PYTHON,
                                                      "imagePullPolicy": "IfNotPresent",
                                                      "command": ["python", "/fixture/worker.py", "retire"],
                                                      "volumeMounts": worker_mount}], "volumes": worker_volume}}}}}}
    return [config, registry_cm, registry, service, job("retention-seed", "seed"), cron]


def _json(lab, *args) -> dict:
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def _wait_job(lab, name: str, timeout: int = 90) -> dict:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        obj = _json(lab, "get", "job", name)
        if obj.get("status", {}).get("succeeded", 0) == 1:
            return obj
        if obj.get("status", {}).get("failed", 0):
            logs = lab.kubectl("logs", "job/" + name, allow_failure=True, timeout=20)
            lab.block(f"Fixture Job {name} failed: {logs.stdout[-1500:]} {logs.stderr[-500:]}")
        time.sleep(1)
    lab.kubectl("get", "pods", "-l", "job-name=" + name, "-o", "json", allow_failure=True, timeout=15)
    lab.block(f"Timed out waiting for registry fixture Job {name}")


def _log(lab, job_name: str) -> tuple[str, dict]:
    raw = lab.kubectl("logs", "job/" + job_name).stdout.strip()
    try:
        return raw, json.loads(raw.splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        raise RuntimeError(f"fixture Job {job_name} emitted no JSON evidence") from error


def run(lab) -> None:
    """Run the cluster-owned scheduler fixture through the normal Lab API."""
    run_id = uuid.uuid4().hex[:10]
    policy = _policy()
    resources = _resources(run_id, policy)
    # Create the CronJob only after fixture content and its independent
    # pre-schedule baseline exist, so there is no unconditional delete path.
    payload = json.dumps({"apiVersion": "v1", "kind": "List", "items": resources[:-2]})
    lab.kubectl("apply", "-f", "-", payload=payload, timeout=45)
    lab.kubectl("rollout", "status", "deployment/retention-registry", "--timeout=60s", timeout=70)
    lab.create(resources[-2])
    _wait_job(lab, "retention-seed")
    seed_raw, seeded = _log(lab, "retention-seed")
    if seeded.get("event") != "seeded" or len(seeded.get("objects", {})) != len(policy):
        raise RuntimeError("seed Job did not create every subject/referrer cohort")
    seeded_rows = list(seeded["objects"].values())
    equivalent = (len({row["subject"] for row in seeded_rows}) == 1
                  and len({row["referrer"] for row in seeded_rows}) == 1
                  and len({row["payload_digest"] for row in seeded_rows}) == 1)
    lab.check("positive", "separate registry repositories contain equivalent byte-identical OCI cohorts",
              equivalent, {key: {field: row[field] for field in ("subject", "referrer", "payload_digest")}
                           for key, row in seeded["objects"].items()})

    bound_policy = []
    for row in policy:
        seed = seeded["objects"][row["id"]]
        if seed["repo"] != "retention/" + row["id"] or seed["created_at"] != row["created_at"]:
            raise RuntimeError("seed results do not match the declared repository and timestamp")
        bound_policy.append({**row, **{key: seed[key] for key in ("subject", "referrer", "referrers_tag")}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "retention-bound-policy"},
                "immutable": True, "data": {"worker.py": WORKER, "policy.json": json.dumps(bound_policy, sort_keys=True)}})
    baseline = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "retention-baseline"},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 30,
                         "template": {"spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                            "containers": [{"name": "observer", "image": PYTHON,
                              "command": ["python", "/fixture/worker.py", "observe"],
                              "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]}],
                            "volumes": [{"name": "fixture", "configMap": {"name": "retention-bound-policy"}}]}}}}
    lab.create(baseline)
    _wait_job(lab, "retention-baseline")
    baseline_raw, baseline_result = _log(lab, "retention-baseline")
    rows = baseline_result.get("objects", {})
    baseline_ok = (baseline_result.get("event") == "observed" and len(rows) == len(policy)
                   and all(x.get("subject") == 200 and x.get("referrer") == 200
                           and x.get("referrer_listed") for x in rows.values()))
    lab.check("red", "before scheduling every actual subject/referrer is retrievable",
              baseline_ok, rows)

    cronjob = resources[-1]
    cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]["volumes"] = [
        {"name": "fixture", "configMap": {"name": "retention-bound-policy"}}]
    lab.create(cronjob)
    cron = _json(lab, "get", "cronjob", "retention-scheduler")
    cron_uid = cron.get("metadata", {}).get("uid")
    cron_spec = cron.get("spec", {})
    lab.check("positive", "unique CronJob is configured for bounded UTC Forbid scheduling",
              bool(cron_uid) and cron_spec.get("timeZone") == "Etc/UTC"
              and cron_spec.get("concurrencyPolicy") == "Forbid"
              and cron_spec.get("startingDeadlineSeconds") == 20,
              {"uid_present": bool(cron_uid), "timeZone": cron_spec.get("timeZone"),
               "concurrencyPolicy": cron_spec.get("concurrencyPolicy"),
               "startingDeadlineSeconds": cron_spec.get("startingDeadlineSeconds")})

    deadline = time.monotonic() + 100
    scheduled_job = None
    while time.monotonic() < deadline and scheduled_job is None:
        jobs = _json(lab, "get", "jobs", "-l", f"saf-fixture-run={run_id}")
        for job in jobs.get("items", []):
            owners = job["metadata"].get("ownerReferences", [])
            if any(owner.get("uid") == cron_uid and owner.get("kind") == "CronJob"
                   and owner.get("controller") is True for owner in owners):
                scheduled_job = job
                break
        if scheduled_job is None:
            time.sleep(1)
    if scheduled_job is None:
        lab.block("CronJob controller did not create an owned Job within 100 seconds")
    lab.kubectl("patch", "cronjob", "retention-scheduler", "--type=merge",
                "-p", '{"spec":{"suspend":true}}')
    job_meta = scheduled_job["metadata"]
    scheduled_at = job_meta.get("annotations", {}).get("batch.kubernetes.io/cronjob-scheduled-timestamp", "")
    created_at = _rfc3339(job_meta["creationTimestamp"])
    try:
        scheduled_dt = _rfc3339(scheduled_at)
        valid_utc_stamp = (scheduled_dt.utcoffset() == timedelta(0)
                           and 0 <= (created_at - scheduled_dt).total_seconds() <= 20)
    except ValueError:
        valid_utc_stamp = False
    suspended = _json(lab, "get", "cronjob", "retention-scheduler")["spec"].get("suspend") is True
    lab.check("positive", "Kubernetes created the owned Job at its UTC schedule and further runs were suspended",
              valid_utc_stamp and suspended,
              {"controller_owned": True, "valid_utc_timestamp": valid_utc_stamp, "suspended": suspended})
    _wait_job(lab, job_meta["name"])
    retire_raw, retired = _log(lab, scheduled_job["metadata"]["name"])
    decisions = retired.get("decisions", {})
    deleted_ids = {row.get("id") for row in retired.get("deleted", [])}
    expected_reasons = {"eligible": [], "equivalent-held": ["hold"],
                        "negative-young": ["minimum_age"], "negative-retain-until": ["retention_active"],
                        "negative-subject-retained": ["subject_retained"]}
    reasons = {key: row.get("reasons") for key, row in decisions.items()}
    deleted_order = [row.get("digest") for row in retired.get("deleted", [])]
    eligible = seeded["objects"]["eligible"]
    expected_eligible = {"eligible"}
    controller_ok = (retired.get("event") == "retired" and deleted_ids == expected_eligible
                     and reasons == expected_reasons and deleted_order == [eligible["referrer"], eligible["subject"]]
                     and decisions.get("eligible", {}).get("eligible") is True
                     and all(decisions.get(k, {}).get("eligible") is False
                             for k in {"equivalent-held", "negative-young", "negative-retain-until",
                                       "negative-subject-retained"}))
    lab.check("positive", "scheduled controller deleted only independently eligible OCI manifests",
              controller_ok, {"reasons": reasons, "deleted_ids": sorted(deleted_ids),
                              "referrer_deleted_before_subject": deleted_order == [eligible["referrer"], eligible["subject"]]})

    observer = {**baseline, "metadata": {"name": "retention-after-scheduler"}}
    lab.create(observer)
    _wait_job(lab, "retention-after-scheduler")
    observed_raw, observed = _log(lab, "retention-after-scheduler")
    after = observed.get("objects", {})
    protected = {"equivalent-held", "negative-young", "negative-retain-until", "negative-subject-retained"}
    green_ok = (observed.get("event") == "observed" and after.get("eligible", {}).get("subject") == 404
                and after.get("eligible", {}).get("referrer") == 404
                and after.get("eligible", {}).get("referrer_listed") is False
                and all(after.get(k, {}).get("subject") == 200
                        and after.get(k, {}).get("referrer") == 200
                        and after.get(k, {}).get("referrer_listed") is True for k in protected))
    lab.check("green", "post-schedule observer sees eligible manifests disappear and protected payloads remain readable",
              green_ok, after)

    stable = {"deleted_ids": sorted(deleted_ids), "protected_ids": sorted(protected),
              "baseline_all_available": baseline_ok, "post_schedule": green_ok}
    stable_signature = hashlib.sha256(json.dumps(stable, sort_keys=True,
                                                  separators=(",", ":")).encode()).hexdigest()
    evidence = {"fixture": "SAF-K8S-0601-011-scheduled-retention-draft", "run_id": run_id,
                "registry_image": REGISTRY, "python_image": PYTHON,
                "cronjob_uid": cron_uid, "scheduled_job_uid": scheduled_job["metadata"]["uid"],
                "scheduled_timestamp": scheduled_at, "stable_outcomes": stable,
                "stable_outcome_sha256": stable_signature,
                "raw_scoped": {"seed": seed_raw, "baseline_observer": baseline_raw,
                               "controller": retire_raw, "post_observer": observed_raw}}
    path = Path(lab.evidence) / "scheduled-retention-fixture.json"
    path.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    path.chmod(0o600)
