"""Exercise failed, absent and healthy scrape jobs against the same exporter."""

from copy import deepcopy
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
import math
import os
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
spec = spec_from_file_location("saf_visibility_routes", HERE / "visibility_failure.py")
route = module_from_spec(spec)
spec.loader.exec_module(route)
JOBS = ("healthy", "failed", "vanished")
ALERTS = route.EXPECTED
METRIC = "DCGM_FI_DEV_FB_USED"
FAILED_PATH = "/saf-a100-visibility-intentional-missing-path"
PREFIX = route.PREFIX


class VisibilityBlocked(RuntimeError):
    pass


def hash_text(value):
    return hashlib.sha256(value.encode()).hexdigest()


def configs(target, refs):
    scrapes = [{"job_name": job, "metrics_path": "/metrics",
                "static_configs": [{"targets": [target], "labels": refs}]} for job in JOBS]
    receiver = "case-local-visibility"
    prom = {"global": {"scrape_interval": "1s", "scrape_timeout": "1s", "evaluation_interval": "1s"},
            "scrape_configs": scrapes, "alerting": {"alertmanagers": [
                {"static_configs": [{"targets": [PREFIX + "-alertmanager:9093"]}]}]}}
    rules = {"groups": [{"name": "case-a100-visibility", "rules": [
        {"alert": "FixtureSourceScrapeFailed", "expr": 'up{job="failed"} == 0', "for": "2s",
         "labels": {**refs, "severity": "warning"}},
        {"alert": "FixtureSourceTargetAbsent", "expr": 'absent_over_time(up{job="vanished"}[6s])', "for": "4s",
         "labels": {**refs, "job": "vanished", "instance": target, "severity": "warning"}},
    ]}]}
    am = {"route": {"receiver": receiver, "group_by": ["alertname", "capture_ref"], "group_wait": "1s",
                    "group_interval": "2s", "repeat_interval": "1h"}, "receivers": [
        {"name": receiver, "webhook_configs": [
            {"url": f"http://{PREFIX}-receiver:18082/events", "send_resolved": False, "max_alerts": 2}]}]}
    return prom, rules, am


def setup(case, target, refs):
    cfg = PREFIX + "-assets"
    prom, rules, am = configs(target, refs)
    case.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": cfg}, "data": {
        "prometheus.json": json.dumps(prom, sort_keys=True), "rules.json": json.dumps(rules),
        "alertmanager.json": json.dumps(am), "route_receiver.py": (HERE / "route_receiver.py").read_text()}})
    route.create_pod(case, PREFIX + "-receiver", route.PYTHON, ["python", "-B", "/fixture/route_receiver.py"],
                     18082, config_name=cfg, readiness="/health")
    route.create_pod(case, PREFIX + "-alertmanager", route.ALERTMANAGER,
                     ["/bin/alertmanager", "--config.file=/fixture/alertmanager.json",
                      "--storage.path=/scratch", "--cluster.listen-address="], 9093,
                     config_name=cfg, readiness="/-/ready")
    route.create_pod(case, PREFIX + "-prometheus", route.PROM,
                     ["/bin/prometheus", "--config.file=/fixture/prometheus.json",
                      "--storage.tsdb.path=/scratch", "--storage.tsdb.retention.time=10m", "--web.enable-lifecycle"],
                     9090, config_name=cfg, readiness="/-/ready")
    return prom


def config_text(config):
    return json.dumps(config, sort_keys=True)


def reload_config(case, config, phase):
    body = config_text(config)
    case.kubectl("patch", "configmap", PREFIX + "-assets", "--type=merge", "-p",
                 json.dumps({"data": {"prometheus.json": body}}))
    case.kubectl("annotate", "pod", PREFIX + "-prometheus", f"fixture.example/config-change={phase}", "--overwrite")

    def projected():
        result = case.kubectl("exec", "pod/" + PREFIX + "-prometheus", "--", "cat", "/fixture/prometheus.json",
                              allow_failure=True, timeout=12)
        return result.returncode == 0 and result.stdout in (body, body.encode())

    if not route.wait(projected, seconds=125):
        raise VisibilityBlocked("The case monitor never received the exact projected configuration")
    reload_code = ("from urllib.request import Request,urlopen; "
                   f"r=Request('http://{PREFIX}-prometheus:9090/-/reload',method='POST'); "
                   "assert urlopen(r,timeout=5).status == 200")
    case.kubectl("exec", "pod/" + PREFIX + "-receiver", "--", "python", "-c", reload_code, timeout=12)


def metric_query(job, target, labels, refs, interval=""):
    selectors = {**labels, **refs, "job": job, "instance": target}
    quoted = ",".join(f"{key}={json.dumps(value)}" for key, value in selectors.items())
    return f"{METRIC}{{{quoted}}}{interval}"


def recent_metric(case, job, target, labels, refs):
    rows = route.query(case, metric_query(job, target, labels, refs, "[6s]"))
    if not rows or len(rows) != 1 or not rows[0].get("values"):
        return None
    stamp, metric = map(float, rows[0]["values"][-1])
    if not math.isfinite(metric) or metric < 0 or not -2 <= time.time() - stamp <= 6:
        return None
    return {"sample_epoch_s": stamp, "framebuffer_mib": metric}


def up(case, job, target, refs, expected):
    rows = route.query(case, f'up{{job="{job}",instance="{target}"}}')
    return (isinstance(rows, list) and len(rows) == 1 and rows[0]["value"][1] == expected
            and rows[0]["metric"] == {**refs, "__name__": "up", "job": job, "instance": target})


def target_state(case, job, target, refs, *, path="/metrics", health="up"):
    data = route.read(case, f"http://{PREFIX}-prometheus:9090/api/v1/targets?state=active")
    if not isinstance(data, dict) or data.get("status") != "success":
        return False
    active = [row for row in data.get("data", {}).get("activeTargets", []) if row.get("scrapePool") == job]
    if health == "absent":
        return not active
    if len(active) != 1:
        return False
    row = active[0]
    return (row.get("health") == health and row.get("scrapeUrl") == f"http://{target}{path}"
            and row.get("labels") == {**refs, "job": job, "instance": target}
            and (health != "down" or "404 Not Found" in row.get("lastError", "")))


def deliveries(case, target):
    events = route.read(case, f"http://{PREFIX}-receiver:18082/events")
    if not isinstance(events, list):
        return None
    if any(alert["labels"].get("instance") != target for event in events for alert in event["alerts"]):
        return None
    return sorted(({
        "receiver": event["receiver"], "status": event["status"], "alert_status": alert["status"],
        **{key: alert["labels"][key] for key in
           ("alertname", "job", "fixture_target", "severity", "capture_ref", "workload_ref", "evidence_source")},
    } for event in events for alert in event["alerts"]), key=lambda row: (row["alertname"], row["job"]))


def required_deliveries(refs, expected):
    return [{"receiver": "case-local-visibility", "status": "firing", "alert_status": "firing",
             "alertname": alert, "job": job, "fixture_target": refs["fixture_target"],
             "severity": "warning", "capture_ref": refs["capture_ref"], "workload_ref": refs["workload_ref"],
             "evidence_source": refs["evidence_source"]}
            for alert, job, state in sorted(expected)]


def checkpoint(directory, filename, record):
    with (directory / filename).open("x") as stream:
        json.dump(record, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def exercise(case, directory, initial_source, source):
    target, labels, exporter_ref, _ = initial_source
    refs = {"fixture_target": "a100-visibility", "capture_ref": case.namespace,
            "workload_ref": hash_text(labels["pod_uid"]), "exporter_ref": exporter_ref,
            "evidence_source": hash_text(json.dumps([target, labels, exporter_ref], sort_keys=True))}
    initial = setup(case, target, refs)

    def read_source():
        actual_target, actual_labels, actual_exporter, actual_value = source()
        if (actual_target, actual_labels, actual_exporter) != (target, labels, exporter_ref):
            raise VisibilityBlocked("The device/workload/exporter join changed between phases")
        return actual_value

    def baseline():
        samples = {job: recent_metric(case, job, target, labels, refs) for job in JOBS}
        if (all(samples.values()) and all(up(case, job, target, refs, "1") and
                                          target_state(case, job, target, refs) for job in JOBS)
                and deliveries(case, target) == [] and route.alerts(case) == set()):
            return samples
        return None

    before = route.wait(baseline, seconds=50)
    if not before:
        raise VisibilityBlocked("The exact live exporter was not observable in each job before arming alerts")
    checkpoint(directory, "01-before-fault.json", {
        "seen": before, "direct_mib": read_source(), "workload_ref": refs["workload_ref"],
        "exporter_ref": exporter_ref, "receiver_initially_empty": True,
        "config_sha256": hash_text(config_text(initial))})

    failed_config = deepcopy(initial)
    failed_config["rule_files"] = ["/fixture/rules.json"]
    failed_config["scrape_configs"][1]["metrics_path"] = FAILED_PATH
    reload_config(case, failed_config, "wrong-scrape-path")
    failed_alert = {row for row in ALERTS if row[1] == "failed"}

    def failed_and_routed():
        return (up(case, "failed", target, refs, "0") and
                target_state(case, "failed", target, refs, path=FAILED_PATH, health="down") and
                route.query(case, metric_query("failed", target, labels, refs)) == [] and
                up(case, "vanished", target, refs, "1") and target_state(case, "vanished", target, refs) and
                route.alerts(case) == failed_alert and
                deliveries(case, target) == required_deliveries(refs, failed_alert))

    if not route.wait(failed_and_routed, seconds=65):
        raise VisibilityBlocked("The exact failed scrape and receiver delivery were not observed independently")
    checkpoint(directory, "02-failed-scrape.json", {
        "failed_target_http_404": True, "failed_up": 0, "failed_metric_absent": True,
        "vanished_job_still_up": True, "direct_mib": read_source(),
        "deliveries": required_deliveries(refs, failed_alert),
        "config_sha256": hash_text(config_text(failed_config))})

    vanished_config = deepcopy(failed_config)
    vanished_config["scrape_configs"] = [job for job in vanished_config["scrape_configs"]
                                        if job["job_name"] != "vanished"]
    reload_config(case, vanished_config, "remove-target")

    def absent_and_zero():
        zero = recent_metric(case, "healthy", target, labels, refs)
        absent = route.query(case, 'absent_over_time(up{job="vanished"}[6s])')
        if (zero and zero["framebuffer_mib"] == 0 and up(case, "healthy", target, refs, "1") and
                target_state(case, "healthy", target, refs) and target_state(case, "vanished", target, refs, health="absent")
                and up(case, "failed", target, refs, "0")
                and target_state(case, "failed", target, refs, path=FAILED_PATH, health="down")
                and route.query(case, 'up{job="vanished"}') == []
                and route.query(case, metric_query("vanished", target, labels, refs)) == []
                and absent and len(absent) == 1 and absent[0]["value"][1] == "1"
                and route.alerts(case) == ALERTS and deliveries(case, target) == required_deliveries(refs, ALERTS)):
            return zero
        return None

    zero = route.wait(absent_and_zero, seconds=65)
    if not zero or read_source() != 0:
        raise VisibilityBlocked("Removed-target delivery and a current direct and scraped measured zero are required")
    return {"failed_target_http_404": True, "vanished_target_absent": True, "healthy_measured_zero": zero,
            "direct_healthy_framebuffer_mib": 0, "workload_ref": refs["workload_ref"], "exporter_ref": exporter_ref,
            "device_ref": hash_text(labels["UUID"]), "target_ref": hash_text(target), "route_receipts": required_deliveries(refs, ALERTS),
            "query_lookback_seconds": 6, "config_sha256": hash_text(config_text(vanished_config)),
            "scrape_configuration_only": True}


