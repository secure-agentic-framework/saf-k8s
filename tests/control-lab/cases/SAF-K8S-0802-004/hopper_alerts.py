"""Observe Alertmanager routing from a previously authenticated Hopper archive."""

import hashlib
import json
from pathlib import Path
import time
from urllib.parse import urlencode

PROMETHEUS = "docker.io/prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
ALERTMANAGER = "docker.io/prom/alertmanager:v0.28.1@sha256:27c475db5fb156cab31d5c18a4251ac7ed567746a2483ff264516437a39b15ba"
PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SOURCE = "fixture-hopper-metrics"
PROM = "fixture-hopper-prometheus"
ALERTS = "fixture-hopper-alertmanager"
RECEIVERS = {"archive-review": "fixture-hopper-review", "live-operations": "fixture-hopper-operations"}
JOB = "fixture-hopper-archive"
INSTANCE = f"{SOURCE}:8080"
ARCHIVE_DRIFT = "FixtureHopperArchiveApprovalMismatch"
LIVE_DRIFT = "FixtureHopperLiveFirmwareDrift"
LIVE_PROBE = "FixtureHopperLiveRouteProbe"
ARCHIVE_UNAVAILABLE = "FixtureHopperArchiveEvidenceUnavailable"
ARCHIVE_LABEL = "archived_hopper_reference"
PROBE_LABEL = "synthetic_live_route_probe"
MATCH = "fixture_hopper_archive_approval_match"
VERIFIED = "fixture_hopper_archive_verified"
LIVE = "fixture_hopper_live_eligible"
PROBE = "fixture_hopper_route_probe"
ARCHIVED = f'{{job="{JOB}",instance="{INSTANCE}"}}'
SCRIPT = Path(__file__).with_name("hopper_monitor.py")

HTTP = """
import json,sys,urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=4) as response:
    data=response.read(65537)
    if len(data)>65536: raise ValueError("oversized fixture response")
print(json.dumps(json.loads(data), separators=(",", ":")))
"""

WRITE_BASELINE = """
import os,sys
from pathlib import Path
next_path=Path("/scratch/baseline.next")
next_path.write_text(sys.argv[1]+"\\n", encoding="ascii")
os.replace(next_path,"/scratch/baseline")
"""


def resource(lab, kind, name, **fields):
    return lab.create({"apiVersion": "v1", "kind": kind, "metadata": {"name": name}, **fields})


def endpoint(lab, name, image, command, config, port, ready_path):
    labels = {"app": name}
    sandbox = {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
               "fsGroup": 1000, "seccompProfile": {"type": "RuntimeDefault"}}
    resource(lab, "Pod", name, metadata={"name": name, "labels": labels}, spec={
        "automountServiceAccountToken": False, "restartPolicy": "Never", "securityContext": sandbox,
        "containers": [{
            "name": "app", "image": image, "imagePullPolicy": "IfNotPresent", "command": command,
            "ports": [{"containerPort": port}],
            "readinessProbe": {"httpGet": {"path": ready_path, "port": port}, "periodSeconds": 1},
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                          "limits": {"cpu": "300m", "memory": "160Mi"}},
            "volumeMounts": [{"name": "config", "mountPath": "/fixture", "readOnly": True},
                             {"name": "scratch", "mountPath": "/scratch"}],
        }],
        "volumes": [{"name": "config", "configMap": {"name": config}},
                    {"name": "scratch", "emptyDir": {"sizeLimit": "32Mi"}}],
    })
    resource(lab, "Service", name, spec={"selector": labels, "ports": [{"port": port, "targetPort": port}]})


def configs(lab):
    scrape = {"job_name": JOB, "static_configs": [{"targets": [INSTANCE]}]}
    prom = {
        "global": {"scrape_interval": "1s", "scrape_timeout": "1s", "evaluation_interval": "1s"},
        "scrape_configs": [scrape], "rule_files": ["/fixture/rules.json"],
        "alerting": {"alertmanagers": [{"static_configs": [{"targets": [f"{ALERTS}:9093"]}]}]},
    }
    healthy = f"(up{ARCHIVED} == 1)"
    authenticated = f"({VERIFIED}{ARCHIVED} == 1) and on(job,instance) {healthy}"
    mismatch = f"({MATCH}{ARCHIVED} == 0) and on(job,instance) ({authenticated})"
    rules = {"groups": [{"name": "fixture-firmware-alerts", "rules": [
        {"alert": ARCHIVE_DRIFT, "expr": mismatch, "for": "2s",
         "labels": {"evidence_source": ARCHIVE_LABEL}},
        {"alert": LIVE_DRIFT, "expr": f"({mismatch}) and on(job,instance) ({LIVE}{ARCHIVED} == 1)",
         "for": "2s", "labels": {"evidence_source": "live_device"}},
        {"alert": ARCHIVE_UNAVAILABLE, "expr": f"up{ARCHIVED} == 0", "for": "4s",
         "labels": {"evidence_source": ARCHIVE_LABEL}},
        {"alert": LIVE_PROBE, "expr": f"({PROBE}{ARCHIVED} == 1) and on(job,instance) {healthy}",
         "for": "2s", "labels": {"evidence_source": PROBE_LABEL}},
    ]}]}
    matchers = {
        "archive-review": [f'alertname=~"{ARCHIVE_DRIFT}|{ARCHIVE_UNAVAILABLE}"',
                           f'evidence_source="{ARCHIVE_LABEL}"'],
        "live-operations": [f'alertname=~"{LIVE_DRIFT}|{LIVE_PROBE}"'],
    }
    manager = {
        "route": {"receiver": "discard", "group_by": ["alertname", "evidence_source"], "group_wait": "1s",
                  "group_interval": "2s", "repeat_interval": "1h",
                  "routes": [{"receiver": name, "matchers": selectors} for name, selectors in matchers.items()]},
        "receivers": [{"name": "discard"}, *[
            {"name": name, "webhook_configs": [{"url": f"http://{host}:18082/events",
                                               "send_resolved": name == "archive-review", "max_alerts": 2}]}
            for name, host in RECEIVERS.items()
        ]],
    }
    name = "fixture-hopper-prom-config"
    resource(lab, "ConfigMap", name, immutable=True, data={
        name: json.dumps(document) for name, document in (
            ("prometheus.json", prom), ("rules.json", rules), ("alertmanager.json", manager)
        )
    })
    return name


def start(lab, receipt, approved):
    cfg = "fixture-hopper-monitor-code"
    resource(lab, "ConfigMap", cfg, immutable=True, data={
        "monitor.py": SCRIPT.read_text(encoding="utf-8"), "receipt.json": json.dumps(receipt, sort_keys=True),
        "approved-baseline": approved + "\n",
    })
    assets = configs(lab)
    endpoint(lab, SOURCE, PYTHON, ["python", "-B", "/fixture/monitor.py", "exporter"], cfg, 8080, "/health")
    for name in RECEIVERS.values():
        endpoint(lab, name, PYTHON, ["python", "-B", "/fixture/monitor.py", "receiver"], cfg, 18082, "/health")
    endpoint(lab, ALERTS, ALERTMANAGER, ["/bin/alertmanager", "--config.file=/fixture/alertmanager.json",
             "--storage.path=/scratch", "--cluster.listen-address="], assets, 9093, "/-/ready")
    # Start Prometheus only after the expected exporter and both sinks are reachable.
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{SOURCE}", f"pod/{ALERTS}",
                *(f"pod/{name}" for name in RECEIVERS.values()), "--timeout=60s", timeout=70)
    endpoint(lab, PROM, PROMETHEUS, ["/bin/prometheus", "--config.file=/fixture/prometheus.json",
             "--storage.tsdb.path=/scratch", "--storage.tsdb.retention.time=10m"], assets, 9090, "/-/ready")
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{PROM}", "--timeout=60s", timeout=70)


def get(lab, url):
    result = lab.kubectl("exec", f"pod/{RECEIVERS['archive-review']}", "--", "python", "-c", HTTP,
                         url, timeout=12, allow_failure=True)
    if result.returncode == 0:
        return json.loads(result.stdout)
    return None


def has_sample(lab, metric, expected):
    url = f"http://{PROM}:9090/api/v1/query?" + urlencode({"query": f"{metric}{ARCHIVED}"})
    reply = get(lab, url)
    if not reply or reply.get("status") != "success" or reply["data"].get("resultType") != "vector":
        return False
    rows = reply["data"]["result"]
    if len(rows) != 1:
        return False
    return rows[0]["metric"].get("instance") == INSTANCE and float(rows[0]["value"][1]) == expected


def alerts(lab):
    reply = get(lab, f"http://{PROM}:9090/api/v1/alerts")
    if reply is None or reply.get("status") != "success":
        return None
    return {(item["labels"]["alertname"], item["labels"].get("evidence_source"), item["state"])
            for item in reply["data"]["alerts"]}


def deliveries(lab, receiver):
    data = get(lab, f"http://{RECEIVERS[receiver]}:18082/events")
    if type(data) is not list:
        return None
    if any(set(row) != {"receiver", "name", "status", "evidence_source"} for row in data):
        lab.block("An owned firmware receiver did not return the exact normalized route schema")
    return {(row["receiver"], row["name"], row["evidence_source"], row["status"]) for row in data}


def ready(lab, predicate, explanation):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.5)
    lab.block(explanation)


def state(lab, receipt, baseline, is_match):
    return get(lab, f"http://{SOURCE}:8080/state") == {
        "measurement_sha256": receipt["measurement_record_sha256"],
        "transcript_sha256": receipt["transcript_sha256"],
        "approval_match": is_match,
        "live_eligible": False,
        "baseline_sha256": baseline,
    }


def set_baseline(lab, digest):
    lab.kubectl("exec", f"pod/{SOURCE}", "--", "python", "-c", WRITE_BASELINE, digest)


def run(lab, receipt, approved):
    start(lab, receipt, approved)
    probe = (LIVE_PROBE, PROBE_LABEL, "firing")
    drift = (ARCHIVE_DRIFT, ARCHIVE_LABEL, "firing")
    unverified = (ARCHIVE_UNAVAILABLE, ARCHIVE_LABEL, "firing")
    probe_delivery = {("live-operations", *probe)}
    reported = receipt["measurement_record_sha256"]

    def match_samples(expected):
        return all(has_sample(lab, metric, count) for metric, count in (
            ("up", 1), (VERIFIED, 1), (LIVE, 0), (MATCH, expected)
        ))

    ready(lab, lambda: state(lab, receipt, approved, True) and match_samples(1)
          and alerts(lab) == {probe} and deliveries(lab, "archive-review") == set()
          and deliveries(lab, "live-operations") == probe_delivery,
          "Missing matching archive baseline or live-route positive comparator")

    mismatched = hashlib.sha256(("fixture-different-approved-baseline:" + reported).encode()).hexdigest()
    set_baseline(lab, mismatched)
    drift_delivery = {("archive-review", *drift)}
    ready(lab, lambda: state(lab, receipt, mismatched, False) and match_samples(0)
          and alerts(lab) == {probe, drift} and deliveries(lab, "archive-review") == drift_delivery
          and deliveries(lab, "live-operations") == probe_delivery,
          "The unchanged archived observation did not trigger the exact reviewer-only notification")
    drift_observed = {"matching_archive_quiet_with_live_receiver_proven": True,
                      "authenticated_measurement_and_transcript_unchanged": True,
                      "mismatched_baseline_observed_on_healthy_scrape": True,
                      "archive_mismatch_delivered_to_review_only": True}
    lab.check("archive-firmware-alert", "An approval mismatch on a verified Hopper archive reaches only the fixture reviewer",
              all(drift_observed.values()), drift_observed)

    set_baseline(lab, approved)
    drift_delivery.add(("archive-review", ARCHIVE_DRIFT, ARCHIVE_LABEL, "resolved"))
    ready(lab, lambda: state(lab, receipt, approved, True) and match_samples(1)
          and alerts(lab) == {probe} and deliveries(lab, "archive-review") == drift_delivery
          and deliveries(lab, "live-operations") == probe_delivery,
          "The correct restored comparison did not resolve the archive mismatch")

    set_baseline(lab, "fixture-invalid-baseline")
    unavailable_delivery = drift_delivery | {("archive-review", *unverified)}
    ready(lab, lambda: has_sample(lab, "up", 0) and alerts(lab) == {unverified}
          and deliveries(lab, "archive-review") == unavailable_delivery
          and deliveries(lab, "live-operations") == probe_delivery,
          "A failed collection did not route to archive availability separately from drift")
    set_baseline(lab, approved)
    unavailable_delivery.add(("archive-review", ARCHIVE_UNAVAILABLE, ARCHIVE_LABEL, "resolved"))
    ready(lab, lambda: state(lab, receipt, approved, True) and match_samples(1)
          and alerts(lab) == {probe} and deliveries(lab, "archive-review") == unavailable_delivery
          and deliveries(lab, "live-operations") == probe_delivery,
          "Restoring the baseline did not restore healthy archive collection")
    lifecycle = {"restored_baseline_resolved_the_mismatch_notification": True,
                 "failed_collection_not_classified_as_firmware_mismatch": True,
                 "archive_availability_failure_reached_review_only": True,
                 "restored_collection_resolved_the_availability_notification": True,
                 "live_receiver_recorded_only_its_synthetic_comparator": True}
    lab.check("archive-firmware-recovery", "Comparison recovery and evidence availability are distinct archive outcomes",
              all(lifecycle.values()), lifecycle)
    (lab.evidence / "hopper-archive-alerts.json").write_text(json.dumps({
        "scope": "archive rehearsal with synthetic approved baseline and local sinks",
        "measurement_sha256": reported,
        "approved_baseline_sha256": approved,
        "transcript_sha256": receipt["transcript_sha256"],
        "match_and_drift": drift_observed,
        "archive_recovery": lifecycle,
        "route_records": sorted(unavailable_delivery | probe_delivery),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
