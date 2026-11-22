"""Exercise fixture-only upstream/provider bulletin polling and CronJob recovery."""
import json
from pathlib import Path
import time


HERE = Path(__file__).parent
SCOPE = (
    "A disposable kind cluster runs a CronJob against an in-cluster inert HTTP fixture. "
    "Synthetic records preserve JSON Feed 1.1 and RSS 2.0 field meanings. The case observes "
    "controller-created Jobs during an upstream outage and recovery. It does not connect to public feeds, prove "
    "source subscriptions or event routing/delivery, assess advisory applicability, or test "
    "production cluster/provider coverage."
)

PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
FIXTURE_CONFIG = "advisory-monitor-fixtures"
FIXTURE_DEPLOYMENT = "advisory-fixture"
MONITOR_CRONJOB = "advisory-monitor"


def _config_map(name, data):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": "saf-test"}, "data": data}


def _base_pod(container, volumes, *, restart_policy):
    return {
        "serviceAccountName": "default",
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                            "runAsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [container], "volumes": volumes,
        "restartPolicy": restart_policy,
    }


def _manifests(fixtures):
    fixture_data = {
        "mode": "down",
        "kubernetes.json": json.dumps(fixtures["kubernetes_json_feed"], separators=(",", ":")),
        "aws.xml": fixtures["aws_rss"],
        "fixture_server.py": (HERE / "fixture_server.py").read_text(encoding="utf-8"),
        "monitor.py": (HERE / "monitor.py").read_text(encoding="utf-8"),
    }
    yield _config_map(FIXTURE_CONFIG, fixture_data)
    fixture_pod = _base_pod({
        "name": "fixture-server", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["python", "/app/fixture_server.py"],
        "ports": [{"containerPort": 8080}],
        "volumeMounts": [{"name": "app", "mountPath": "/app", "readOnly": True},
                         {"name": "fixtures", "mountPath": "/fixtures", "readOnly": True},
                         {"name": "state", "mountPath": "/state", "readOnly": True}],
        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
    }, [
        {"name": "app", "configMap": {"name": FIXTURE_CONFIG,
                                         "items": [{"key": "fixture_server.py", "path": "fixture_server.py"}]}},
        {"name": "fixtures", "configMap": {"name": FIXTURE_CONFIG,
                                             "items": [{"key": "kubernetes.json", "path": "kubernetes.json"},
                                                       {"key": "aws.xml", "path": "aws.xml"}]}},
        {"name": "state", "configMap": {"name": FIXTURE_CONFIG,
                                           "items": [{"key": "mode", "path": "mode"}]}},
    ], restart_policy="Always")
    yield {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": FIXTURE_DEPLOYMENT, "namespace": "saf-test"},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": FIXTURE_DEPLOYMENT}},
                 "template": {"metadata": {"labels": {"app": FIXTURE_DEPLOYMENT}},
                              "spec": fixture_pod}},
    }
    yield {"apiVersion": "v1", "kind": "Service",
           "metadata": {"name": FIXTURE_DEPLOYMENT, "namespace": "saf-test"},
           "spec": {"selector": {"app": FIXTURE_DEPLOYMENT},
                    "ports": [{"port": 8080, "targetPort": 8080}]}}
    job_pod = _base_pod({
        "name": "monitor", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["python", "/app/monitor.py"],
        "volumeMounts": [{"name": "app", "mountPath": "/app", "readOnly": True}],
        "env": [{"name": "KUBERNETES_FEED_URL",
                 "value": f"http://{FIXTURE_DEPLOYMENT}.saf-test.svc:8080/kubernetes/index.json"},
                {"name": "AWS_BULLETIN_URL",
                 "value": f"http://{FIXTURE_DEPLOYMENT}.saf-test.svc:8080/aws/rss.xml"}],
        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
    }, [{"name": "app", "configMap": {"name": FIXTURE_CONFIG,
                                             "items": [{"key": "monitor.py", "path": "monitor.py"}]}}],
        restart_policy="Never")
    yield {"apiVersion": "batch/v1", "kind": "CronJob",
           "metadata": {"name": MONITOR_CRONJOB, "namespace": "saf-test"},
           "spec": {"schedule": "* * * * *", "timeZone": "Etc/UTC", "suspend": True,
                    "concurrencyPolicy": "Forbid", "startingDeadlineSeconds": 30,
                    "jobTemplate": {"metadata": {"labels": {"app": MONITOR_CRONJOB}},
                                    "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 40,
                                              "template": {"metadata": {"labels": {"app": MONITOR_CRONJOB}},
                                                           "spec": job_pod}}}}}


def _wait_fixture_mode(lab, expected_code):
    probe = f"""import urllib.request, urllib.error
url = 'http://127.0.0.1:8080/health'
try:
    with urllib.request.urlopen(url, timeout=2) as response:
        status = response.status
except urllib.error.HTTPError as error:
    status = error.code
print(status)
raise SystemExit(0 if status == {expected_code} else 1)
"""
    deadline = time.monotonic() + 90
    observed = None
    while time.monotonic() < deadline:
        result = lab.kubectl("exec", f"deploy/{FIXTURE_DEPLOYMENT}", "--", "python", "-c", probe,
                             allow_failure=True)
        observed = result.stdout.strip()
        if result.returncode == 0:
            return observed
        time.sleep(1)
    raise AssertionError(f"fixture server did not reach HTTP {expected_code}; last={observed!r}")


def jobs(lab):
    result = lab.kubectl("get", "jobs", "-l", f"app={MONITOR_CRONJOB}", "-o", "json")
    return json.loads(result.stdout)["items"]


def wait_for_scheduled_job(lab, cron_uid, seen):
    deadline = time.monotonic() + 115
    while time.monotonic() < deadline:
        for job in jobs(lab):
            meta, status = job["metadata"], job.get("status", {})
            if meta["name"] in seen:
                continue
            owned = any(ref["kind"] == "CronJob" and ref["uid"] == cron_uid and ref.get("controller")
                        for ref in meta.get("ownerReferences", []))
            annotated = bool(meta.get("annotations", {}).get("batch.kubernetes.io/cronjob-scheduled-timestamp"))
            if not owned or not annotated:
                lab.block("The advisory Job was not created by the CronJob controller")
            failed = any(entry["type"] == "Failed" and entry["status"] == "True"
                         for entry in status.get("conditions", []))
            if failed or status.get("succeeded"):
                logs = lab.kubectl("logs", f"job/{meta['name']}").stdout.splitlines()
                return bool(status.get("succeeded")), logs
        time.sleep(2)
    lab.block("The CronJob controller did not complete a new advisory Job within the sample window")


def run(lab):
    fixtures = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
    for manifest in _manifests(fixtures):
        lab.kubectl("apply", "-f", "-", payload=json.dumps(manifest))
    lab.kubectl("rollout", "status", f"deployment/{FIXTURE_DEPLOYMENT}", "--timeout=90s", timeout=100)
    outage_code = _wait_fixture_mode(lab, 503)
    cron = json.loads(lab.kubectl("get", "cronjob", MONITOR_CRONJOB, "-o", "json").stdout)
    cron_uid = cron["metadata"]["uid"]
    lab.kubectl("patch", "cronjob", MONITOR_CRONJOB, "--type=merge", "-p", '{"spec":{"suspend":false}}')
    succeeded, logs = wait_for_scheduled_job(lab, cron_uid, set())
    reported = "monitor_poll_failed source=kubernetes-json-feed status=503" in logs
    provider = "source=aws-security-bulletin-rss items=1" in logs
    lab.check("red", "A scheduled Job reports the upstream outage while still parsing the provider feed",
              not succeeded and reported and provider,
              {"scheduled": True, "job_succeeded": succeeded, "source_http_status": outage_code,
               "upstream_outage_reported": reported, "provider_parsed": provider})

    lab.kubectl("patch", "configmap", FIXTURE_CONFIG, "--type=merge", "-p", '{"data":{"mode":"healthy"}}')
    lab.kubectl("rollout", "restart", f"deployment/{FIXTURE_DEPLOYMENT}")
    lab.kubectl("rollout", "status", f"deployment/{FIXTURE_DEPLOYMENT}", "--timeout=90s", timeout=100)
    healthy_code = _wait_fixture_mode(lab, 200)
    earlier = {item["metadata"]["name"] for item in jobs(lab)}
    succeeded, logs = wait_for_scheduled_job(lab, cron_uid, earlier)
    upstream = "source=kubernetes-json-feed items=1" in logs
    provider = "source=aws-security-bulletin-rss items=1" in logs
    lab.check("green", "A new Job from the same CronJob reports recovery after the source returns",
              succeeded and upstream, {"scheduled": True, "job_succeeded": succeeded,
                                       "source_http_status": healthy_code, "upstream_parsed": upstream})
    lab.check("positive", "The recovered Job also parses the unaffected provider feed",
              provider, {"provider_parsed": provider, "records_are_synthetic": True})
