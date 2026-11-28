"""Verify live accelerator telemetry alert paths using synthetic series."""

import json
from pathlib import Path
import time
from urllib.parse import urlencode

SCOPE = ("Three checks evaluate synthetic in-cluster telemetry. Additive checks exercise a case-owned "
         "Prometheus/Alertmanager route, then replay two hash-pinned historical Tesla T4 framebuffer "
         "observations as explicitly historical fixture series. The replay proves rule and delivery "
         "behavior for those retained values; it does not establish live GPU collection, freshness, "
         "coverage, misuse, or production incident detection.")
PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
PROM = "docker.io/prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
EXPORTER = "fixture-accelerator-exporter"
MONITOR = "fixture-accelerator-monitor"
TARGETS = ("normal", "high", "missing")
METRIC = "fixture_gpu_utilization_ratio"


def config_files():
    baseline = {"global": {"scrape_interval": "2s", "scrape_timeout": "1s", "evaluation_interval": "2s"},
                "scrape_configs": [{"job_name": target, "metrics_path": "/" + target,
                                    "static_configs": [{"targets": [EXPORTER + ":8080"]}]}
                                   for target in TARGETS]}
    rules = {"groups": [{"name": "fixture-accelerator", "rules": [
        {"alert": "FixtureAcceleratorHigh", "expr": METRIC + " > 0.8", "for": "4s"},
        {"alert": "FixtureAcceleratorSignalMissing",
         "expr": "up == 1 unless on(job, instance) " + METRIC, "for": "4s"},
    ]}]}
    return {"baseline.json": json.dumps(baseline),
            "reviewed.json": json.dumps(dict(baseline, rule_files=["/fixture/rules.json"])),
            "rules.json": json.dumps(rules)}


def create_config(lab, name, files):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "immutable": True, "data": files})


def start(lab, name, image, command, port):
    container = {"name": "unit", "image": image, "command": command,
                 "ports": [{"containerPort": port}],
                 "volumeMounts": [{"name": "config", "mountPath": "/fixture", "readOnly": True},
                                  {"name": "scratch", "mountPath": "/scratch"}],
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}},
                 "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                               "limits": {"cpu": "350m", "memory": "160Mi"}}}
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"app": name}},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [container], "volumes": [{"name": "config", "configMap": {"name": name}},
                                                                 {"name": "scratch", "emptyDir": {}}]}})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + name, "--timeout=85s", timeout=93)


def service(lab, name, port):
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                "spec": {"selector": {"app": name}, "ports": [{"port": port, "targetPort": port}]}})


def get(lab, endpoint, **params):
    url = f"http://{MONITOR}:9090/api/v1/{endpoint}?{urlencode(params)}"
    request = "import sys, urllib.request; print(urllib.request.urlopen(sys.argv[1], timeout=3).read().decode())"
    result = lab.kubectl("exec", "pod/" + EXPORTER, "--", "python", "-c", request, url,
                         timeout=12, allow_failure=True)
    if result.returncode:
        return None
    response = json.loads(result.stdout)
    return response["data"] if response["status"] == "success" else None


def query(lab, expression):
    response = get(lab, "query", query=expression)
    return {row["metric"]["job"]: float(row["value"][1]) for row in response["result"]} if response else {}


def sample(lab):
    return query(lab, "up"), query(lab, METRIC)


def active(lab):
    response = get(lab, "alerts")
    if response is None:
        return None
    return {(alert["labels"]["alertname"], alert["labels"]["job"], alert["state"])
            for alert in response["alerts"]}


def until(probe):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(1)
    return False


def monitor(lab, config):
    start(lab, MONITOR, PROM, ["/bin/prometheus", "--storage.tsdb.path=/scratch",
                              "--config.file=/fixture/" + config, "--storage.tsdb.retention.time=1h"], 9090)


def run(lab):
    create_config(lab, EXPORTER, {"exporter.py": Path(__file__).with_name("exporter.py").read_text()})
    create_config(lab, MONITOR, config_files())
    service(lab, EXPORTER, 8080)
    service(lab, MONITOR, 9090)
    start(lab, EXPORTER, PYTHON, ["python", "-B", "/fixture/exporter.py"], 8080)
    monitor(lab, "baseline.json")
    expected = (dict.fromkeys(TARGETS, 1.0), {"normal": 0.2, "high": 0.95})
    baseline = until(lambda: sample(lab) == expected and active(lab) == set())
    lab.check("red", "The working scrape alone produces no alerts for the high or missing samples", baseline,
              {"all_targets_up_with_high_and_missing_inputs": baseline, "no_alerts_before_rules": baseline})

    lab.kubectl("delete", "pod", MONITOR, "--wait=true", "--grace-period=1")
    monitor(lab, "reviewed.json")
    alerts = {("FixtureAcceleratorHigh", "high", "firing"),
              ("FixtureAcceleratorSignalMissing", "missing", "firing")}
    matched = until(lambda: active(lab) == alerts)
    observed = active(lab)
    lab.check("green", "The reviewed rules fire distinct high-value and missing-signal alerts", matched and observed == alerts,
              {"firing": sorted(observed or set())})
    observed_samples = sample(lab)
    lab.check("positive", "The normal series remains visible and its target emits neither alert",
              observed_samples == expected and observed is not None and all(job != "normal" for _, job, _ in observed),
              {"up": observed_samples[0], "utilization": observed_samples[1], "normal_target_quiet": True})
    (lab.evidence / "accelerator-telemetry-observations.json").write_text(json.dumps({
        "scrape_up": observed_samples[0], "synthetic_utilization": observed_samples[1],
        "alerts": sorted(observed), "hardware_telemetry_tested": False, "notification_delivery_tested": False,
    }, indent=2) + "\n")


_published_run = run


def run(lab):
    _published_run(lab)
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("saf_0805_001_alert_route", Path(__file__).with_name("route_delivery.py"))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run(lab)
    visibility_spec = spec_from_file_location("saf_0805_001_visibility_failure",
                                               Path(__file__).with_name("visibility_failure.py"))
    visibility_module = module_from_spec(visibility_spec)
    visibility_spec.loader.exec_module(visibility_module)
    visibility_module.run(lab)
    module.run_t4_historical(lab)
    same_target_spec = spec_from_file_location("saf_0805_001_same_target_case",
                                               Path(__file__).with_name("same_target_case.py"))
    same_target = module_from_spec(same_target_spec)
    same_target_spec.loader.exec_module(same_target)
    same_target.run(lab)
