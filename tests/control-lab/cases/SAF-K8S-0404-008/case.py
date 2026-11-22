"""Verify TLS expiry telemetry and scoped alert delivery on disposable Kind."""
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from urllib.parse import urlencode

HERE = Path(__file__).resolve().parent
FIXTURE = "saf-cert-fixture"
HOST = f"{FIXTURE}.saf-test.svc.cluster.local"
PROBE = "saf-cert-probe"
PROMETHEUS = "saf-cert-prometheus"
ALERTMANAGER = "saf-cert-alertmanager"
ALERT = "FixtureCertificateNearExpiry"
THRESHOLD = 2 * 86400
TARGETS = {"near-expiry": 8443, "healthy": 9443}
IMAGE = {
    FIXTURE: "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
    PROBE: "docker.io/prom/blackbox-exporter:v0.27.0@sha256:a50c4c0eda297baa1678cd4dc4712a67fdea713b832d43ce7fcc5f9bea05094d",
    PROMETHEUS: "docker.io/prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996",
    ALERTMANAGER: "docker.io/prom/alertmanager:v0.28.1@sha256:27c475db5fb156cab31d5c18a4251ac7ed567746a2483ff264516437a39b15ba",
}
SCOPE = (
    "Kubernetes v1.36.1. Two fixture HTTPS certificates are signed by the local "
    "CA and served by actual TLS endpoints. Blackbox Exporter verifies trust and "
    "reports leaf expiry. Prometheus independently scrapes both endpoints with "
    "the rule disabled and enabled, and Alertmanager routes the exact near-expiry "
    "notification to a disposable in-cluster receiver."
)


def certificates(lab):
    private = lab.kubeconfig.parent / "tls-fixtures"
    private.mkdir(mode=0o700)
    ca, ca_key = private / "ca.crt", private / "ca.key"
    lab.command("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "30", "-subj", "/CN=SAF disposable certificate CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", str(ca_key), "-out", str(ca))
    extension = private / "leaf.ext"
    extension.write_text(f"subjectAltName=DNS:{HOST}\n"
                         "basicConstraints=critical,CA:FALSE\n"
                         "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    paths, expiry = [], {}
    for label, days in (("near-expiry", 1), ("healthy", 7)):
        cert, key, csr = (private / f"{label}.{suffix}" for suffix in ("crt", "key", "csr"))
        lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-subj", f"/CN={HOST}", "-keyout", str(key), "-out", str(csr))
        lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                    "-CAcreateserial", "-days", str(days), "-extfile", str(extension), "-out", str(cert))
        date = lab.command("openssl", "x509", "-in", str(cert), "-noout", "-enddate").stdout.strip()
        expiry[label] = int(datetime.strptime(date.split("=", 1)[1], "%b %d %H:%M:%S %Y GMT")
                            .replace(tzinfo=timezone.utc).timestamp())
        paths.extend((f"--from-file={cert}", f"--from-file={key}"))
    lab.kubectl("create", "secret", "generic", "saf-cert-private", *paths)
    return ca.read_text(), expiry


def configure(lab, name, files):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": files})


def deploy(lab, name, args, ports, *, command=None, private=False):
    volume_mounts = [{"name": "config", "mountPath": "/saf", "readOnly": True}]
    volumes = [{"name": "config", "configMap": {"name": name}}]
    if private:
        volume_mounts.append({"name": "tls", "mountPath": "/tls", "readOnly": True})
        volumes.append({"name": "tls", "secret": {"secretName": "saf-cert-private"}})
    unit = {"name": "app", "image": IMAGE[name], "args": args,
            "ports": [{"containerPort": port} for port in ports],
            "volumeMounts": volume_mounts,
            "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "15m", "memory": "20Mi"},
                          "limits": {"cpu": "500m", "memory": "256Mi"}}}
    if command:
        unit["command"] = command
    selector = {"app": name}
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
                "spec": {"replicas": 1, "selector": {"matchLabels": selector},
                         "template": {"metadata": {"labels": selector},
                                      "spec": {"automountServiceAccountToken": False, "containers": [unit],
                                               "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                                               "volumes": volumes}}}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                "spec": {"selector": selector,
                         "ports": [{"name": f"http-{port}", "port": port, "targetPort": port} for port in ports]}})
    lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=120s", timeout=130)


def prometheus_configs():
    targets = [{"targets": [f"https://{HOST}:{port}/"], "labels": {"certificate": label}}
               for label, port in TARGETS.items()]
    config = {
        "global": {"scrape_interval": "2s", "evaluation_interval": "2s"},
        "scrape_configs": [{
            "job_name": "fixture-certificates", "metrics_path": "/probe",
            "params": {"module": ["fixture_tls"]}, "static_configs": targets,
            "relabel_configs": [
                {"source_labels": ["__address__"], "target_label": "__param_target"},
                {"target_label": "__address__", "replacement": f"{PROBE}:9115"},
            ],
        }],
        "alerting": {"alertmanagers": [{"static_configs": [{"targets": [f"{ALERTMANAGER}:9093"]}]}]},
    }
    enabled = {**config, "rule_files": ["/saf/rules.json"]}
    rules = {"groups": [{"name": "fixture-certificate-expiry", "rules": [{
        "alert": ALERT,
        "expr": f'probe_ssl_earliest_cert_expiry{{job="fixture-certificates"}} - time() < {THRESHOLD}',
        "for": "4s", "labels": {"severity": "warning", "scope": "fixture"},
        "annotations": {"summary": "Owned fixture certificate approaches expiry"},
    }]}]}
    return {"baseline.json": json.dumps(config), "prometheus.json": json.dumps(enabled),
            "rules.json": json.dumps(rules)}


def get_json(lab, url):
    script = ("import sys, urllib.request; "
              "print(urllib.request.urlopen(sys.argv[1], timeout=4).read().decode())")
    response = lab.kubectl("exec", f"deployment/{FIXTURE}", "--", "python", "-c", script, url,
                           allow_failure=True, timeout=14)
    return json.loads(response.stdout) if not response.returncode else None


def query(lab, expression):
    parameters = urlencode({"query": expression})
    response = get_json(lab, f"http://{PROMETHEUS}:9090/api/v1/query?{parameters}")
    return {row["metric"]["certificate"]: float(row["value"][1])
            for row in response["data"]["result"]} if response and response["status"] == "success" else {}


def wait_for(probe, timeout=85):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = probe()
        if result:
            return result
        time.sleep(1)
    return None


def run(lab):
    ca, expiry = certificates(lab)
    configure(lab, FIXTURE, {"server.py": (HERE / "fixture_server.py").read_text()})
    deploy(lab, FIXTURE, ["/saf/server.py"], (8080, *TARGETS.values()),
           command=["python"], private=True)
    module = {"modules": {"fixture_tls": {"prober": "http", "timeout": "5s",
              "http": {"preferred_ip_protocol": "ip4", "fail_if_not_ssl": True,
                       "tls_config": {"ca_file": "/saf/ca.crt"}}}}}
    configure(lab, PROBE, {"config.json": json.dumps(module), "ca.crt": ca})
    deploy(lab, PROBE, ["--config.file=/saf/config.json"], (9115,))
    route = {"route": {"receiver": "discard", "group_by": ["alertname", "certificate"],
                       "group_wait": "1s", "group_interval": "5s",
                       "routes": [{"matchers": [f'alertname="{ALERT}"', 'scope="fixture"'],
                                   "receiver": "local-fixture"}]},
             "receivers": [{"name": "discard"},
                           {"name": "local-fixture", "webhook_configs": [
                               {"url": f"http://{FIXTURE}:8080/notify", "send_resolved": False}]}]}
    configure(lab, ALERTMANAGER, {"config.json": json.dumps(route)})
    deploy(lab, ALERTMANAGER, ["--config.file=/saf/config.json", "--cluster.listen-address="], (9093,))
    configure(lab, PROMETHEUS, prometheus_configs())
    deploy(lab, PROMETHEUS, ["--config.file=/saf/baseline.json"], (9090,))

    target = 'probe_ssl_earliest_cert_expiry{job="fixture-certificates"}'
    matched = wait_for(lambda: query(lab, target) == expiry
                       and query(lab, 'probe_success{job="fixture-certificates"}') == dict.fromkeys(TARGETS, 1))
    lab.check("positive", "TLS-verified expiry metrics match both certificate notAfter values",
              matched, {"expected_subjects": sorted(expiry), "exact_expiries_matched": bool(matched)})
    baseline = get_json(lab, f"http://{PROMETHEUS}:9090/api/v1/alerts")
    receiver = f"http://{FIXTURE}:8080/received"
    baseline_clear = bool(baseline and baseline["data"]["alerts"] == [] and get_json(lab, receiver) == [])
    lab.check("red", "Expiry metrics are present and no alert is produced without a rule",
              baseline_clear, {"no_alert_or_notification": baseline_clear})

    patch = {"spec": {"template": {"spec": {
        "containers": [{"name": "app", "args": ["--config.file=/saf/prometheus.json"]}],
    }}}}
    lab.kubectl("patch", "deployment", PROMETHEUS, "--type=strategic", "-p", json.dumps(patch))
    lab.kubectl("rollout", "status", f"deployment/{PROMETHEUS}", "--timeout=90s", timeout=100)
    def fired():
        result = get_json(lab, f"http://{PROMETHEUS}:9090/api/v1/alerts")
        alerts = result["data"]["alerts"] if result else []
        observed = [(row["labels"].get("certificate"), row["state"])
                    for row in alerts if row["labels"].get("alertname") == ALERT]
        return observed if observed == [("near-expiry", "firing")] else None

    observed = wait_for(fired)
    healthy_scraped = query(lab, target) == expiry
    lab.check("green", "The rule fires for near expiry and keeps the observed healthy certificate clear",
              observed and healthy_scraped,
              {"alerts": observed, "both_certificates_still_measured": healthy_scraped})
    def delivered():
        messages = get_json(lab, receiver)
        if not messages:
            return None
        delivered_alerts = {(
            message["receiver"], alert["labels"].get("alertname"),
            alert["labels"].get("certificate"), alert["labels"].get("severity"),
            alert["status"], alert["annotations"].get("summary"),
        ) for message in messages for alert in message["alerts"]}
        expected = {("local-fixture", ALERT, "near-expiry", "warning", "firing",
                     "Owned fixture certificate approaches expiry")}
        return sorted(delivered_alerts) if delivered_alerts == expected else None

    notification = wait_for(delivered)
    lab.check("green", "Alertmanager delivers the exact firing certificate and route fields",
              notification, {"webhook_notifications": notification})
