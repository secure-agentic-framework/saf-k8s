"""Verify reconciliation age while genuine healthy signals remain present."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTROL_ID = "SAF-K8S-0606-031"
APP = "saf-health-fixture"
OBSERVER = "saf-gitops-age-observer"
ALERT = "GitOpsReconciliationStale"
SUMMARY = "Owned fixture reconciliation timestamp is stale"
LABELS = f'namespace="argocd",name="{APP}"'
HEALTH = f'argocd_app_info{{{LABELS},health_status="Healthy",sync_status="Synced"}} == 1'
READ = f'saf_fixture_api_read_success{{{LABELS}}} == 1'
OBSERVER_HEALTH = f'saf_fixture_application_healthy{{{LABELS}}} == 1'
STAMP = f'saf_fixture_reconciliation_timestamp_seconds{{{LABELS}}}'
VALID = f'{STAMP} and on (namespace,name) ({READ}) and on (namespace,name) ({OBSERVER_HEALTH}) and on (namespace,name) ({HEALTH})'
INTERVAL = 15
THRESHOLD = 45
SCOPE = (
    "Owned Argo CD v3.6.1, Prometheus, Alertmanager and one inert Application. "
    "A restricted observer reads its real reconciliation timestamp. The test pauses "
    "automatic polling for the disposable controller and verifies timestamp staleness "
    "while native application health, scrapes and successful observer reads remain present."
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def polling(lab, seconds):
    settings = {"timeout.reconciliation": f"{seconds}s", "timeout.reconciliation.jitter": "0s",
                "timeout.hard.reconciliation": "0s"}
    lab.kubectl("-n", "argocd", "patch", "configmap", "argocd-cm", "--type=merge",
                "-p", json.dumps({"data": settings}))
    workloads = ("statefulset/argocd-application-controller", "deployment/argocd-repo-server")
    lab.kubectl("-n", "argocd", "rollout", "restart", *workloads)
    for workload in workloads:
        lab.kubectl("-n", "argocd", "rollout", "status", workload, "--timeout=120s", timeout=130)
    config = json.loads(lab.kubectl("-n", "argocd", "get", "configmap", "argocd-cm", "-o", "json").stdout)
    if any(config["data"].get(key) != value for key, value in settings.items()):
        lab.block("Exact fixture polling settings were not retained")


def observer(lab, image):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": OBSERVER},
                "automountServiceAccountToken": False})
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": OBSERVER, "namespace": "argocd"},
        "rules": [{"apiGroups": ["argoproj.io"], "resources": ["applications"],
                   "resourceNames": [APP], "verbs": ["get"]}],
    }
    binding = {
        "apiVersion": role["apiVersion"], "kind": "RoleBinding", "metadata": role["metadata"],
        "subjects": [{"kind": "ServiceAccount", "name": OBSERVER, "namespace": "saf-test"}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": OBSERVER},
    }
    for resource in (role, binding):
        lab.kubectl("-n", "argocd", "create", "-f", "-", payload=json.dumps(resource))
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": OBSERVER},
                "data": {"observer.py": (HERE / "observer.py").read_text()}})
    labels = {"app": OBSERVER}
    lab.create({
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": OBSERVER},
        "spec": {"replicas": 1, "selector": {"matchLabels": labels}, "template": {
            "metadata": {"labels": labels}, "spec": {
                "serviceAccountName": OBSERVER, "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "volumes": [{"name": "code", "configMap": {"name": OBSERVER}},
                            {"name": "identity", "projected": {"sources": [
                                {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                                {"configMap": {"name": "kube-root-ca.crt",
                                                "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                            ]}}],
                "containers": [{"name": "observer", "image": image, "command": ["python", "/code/observer.py"],
                                "securityContext": {"allowPrivilegeEscalation": False,
                                                    "readOnlyRootFilesystem": True,
                                                    "capabilities": {"drop": ["ALL"]}},
                                "resources": {"requests": {"cpu": "10m", "memory": "20Mi"},
                                              "limits": {"cpu": "100m", "memory": "48Mi"}},
                                "volumeMounts": [{"name": name, "mountPath": "/" + name, "readOnly": True}
                                                 for name in ("code", "identity")]}],
            },
        }},
    })
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": OBSERVER},
                "spec": {"selector": labels, "ports": [{"port": 8080, "targetPort": 8080}]}})
    lab.kubectl("rollout", "status", f"deployment/{OBSERVER}", "--timeout=90s", timeout=100)


def settings(monitor):
    files = monitor.config_text()
    prom = json.loads(files["prometheus.json"])
    prom["scrape_configs"].append({"job_name": OBSERVER, "static_configs": [{"targets": [f"{OBSERVER}:8080"]}]})
    files["prometheus.json"] = json.dumps(prom)
    rules = json.loads(files["rules.json"])
    expr = f'time() - {STAMP} > {THRESHOLD} and on (namespace,name) ({VALID})'
    rules["groups"][0]["rules"].append({"alert": ALERT, "expr": expr, "for": "4s",
                                       "labels": {"severity": "warning", "scope": "fixture"},
                                       "annotations": {"summary": SUMMARY}})
    files["rules.json"] = json.dumps(rules)
    return files


def delivered(monitor, lab, state):
    expected = ("fixture-webhook", ALERT, APP, "argocd", "fixture", "warning", SUMMARY, state, True, True)
    return next((row for row in monitor.matching_notifications(lab, ALERT) if row == expected), None)


def samples(monitor, lab, after=None):
    current = monitor.query(lab, VALID)
    if current and len(current) == 1:
        stamp = float(current[0]["value"][1])
        if after is None or stamp > after:
            return stamp
    return None


def targets_up(monitor, lab):
    payload = monitor.json_url(lab, f"http://{monitor.PROM}:9090/api/v1/targets") or {}
    return {row["labels"]["job"] for row in payload.get("data", {}).get("activeTargets", [])
            if row["health"] == "up"} == {OBSERVER, "argocd-fixture"}


def run(lab):
    base = load(HERE.parent / "case.py", "gitops_freshness_base")
    monitor = load(HERE.parent / "monitor" / "monitor_case.py", "gitops_freshness_monitor")
    base.run(lab)
    fixture_workload = base.workload_observation(lab)
    polling(lab, INTERVAL)
    observer(lab, monitor.PY_IMAGE)
    monitor.install_monitor(lab, settings(monitor))
    cadence = []
    for _ in range(3):
        stamp = monitor.wait_for(lambda: samples(monitor, lab, cadence[-1] if cadence else None), timeout=55)
        if stamp is None:
            lab.block("No successive healthy reconciliation timestamp from the authorized observer")
        cadence.append(stamp)
    interval_matches = all(0 < end - start <= INTERVAL * 2 for start, end in zip(cadence, cadence[1:]))
    lab.check("positive", "Three real authorized readings observe the running reconciliation cadence",
              interval_matches and targets_up(monitor, lab) and not delivered(monitor, lab, "firing"),
              {"three_advancing_timestamps": interval_matches, "configured_interval_seconds": INTERVAL,
               "both_targets_up": targets_up(monitor, lab), "stale_alert_absent": not delivered(monitor, lab, "firing")})

    polling(lab, 0)
    fired = monitor.wait_for(lambda: delivered(monitor, lab, "firing"), timeout=110)
    paused = samples(monitor, lab)
    stale = monitor.query(lab, f"time() - {STAMP} > {THRESHOLD}")
    fresh_health_present = bool(paused and targets_up(monitor, lab))
    lab.check("green", "Paused periodic polling fires while current healthy telemetry is still available",
              bool(fired and paused and stale and fresh_health_present and base.workload_observation(lab) == fixture_workload),
              {"age_exceeds_threshold": bool(stale), "live_healthy_status": fresh_health_present,
               "firing_webhook": fired, "workload_unchanged": base.workload_observation(lab) == fixture_workload})

    polling(lab, INTERVAL)
    renewed = monitor.wait_for(lambda: samples(monitor, lab, paused), timeout=70)
    resolved = monitor.wait_for(lambda: delivered(monitor, lab, "resolved"), timeout=75)
    unchanged = base.workload_observation(lab) == fixture_workload
    (lab.evidence / "reconciliation-age-observations.json").write_text(json.dumps({
        "cadence": cadence, "paused": paused, "resumed": renewed, "firing": fired, "resolved": resolved,
        "threshold_seconds": THRESHOLD,
    }, indent=2) + "\n")
    lab.check("positive", "Resuming periodic polling advances the timestamp and resolves the exact stale alert",
              bool(renewed and resolved and unchanged and targets_up(monitor, lab)),
              {"new_reconciliation_timestamp": bool(renewed), "workload_unchanged": unchanged,
               "resolved_webhook": resolved})
