"""Small, closed-zone CoreDNS logging and static observer integration case."""
import json
import importlib.util
from pathlib import Path
import time

from fixtures import container, pod, ready

SCOPE = (
    "A dedicated CoreDNS instance in local Kubernetes v1.36.1 serves a closed fixture zone. "
    "A fixed harmless canary resolves before logging, and two owned A queries resolve afterward. "
    "The nine-check fixture copies observed rows into a ConfigMap for its static observer Job. "
    "An additive named ServiceAccount collector separately reads the exact owned CoreDNS Pod log "
    "through the Kubernetes API, checks exact benign rows and a refused unrelated Pod log path, "
    "and emits sanitized predicates only. Production collection, analytic coverage and protective "
    "enforcement need separate evidence."
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
HERE = Path(__file__).resolve().parent

CANARY = "signal.fixture.test."
NORMAL = "health.fixture.test."
ALERT = {
    "rule": "fixture-static-canary",
    "severity": "test",
    "namespace": "saf-test",
    "qname": CANARY,
    "qtype": "A",
}

COREFILE_NO_LOG = """.:1053 {
    errors
    file /etc/coredns/fixture.db fixture.test
}
"""
COREFILE_WITH_LOG = """.:1053 {
    errors
    log . "{\\\"qname\\\":\\\"{name}\\\",\\\"qtype\\\":\\\"{type}\\\",\\\"qclass\\\":\\\"{class}\\\",\\\"proto\\\":\\\"{proto}\\\",\\\"rcode\\\":\\\"{rcode}\\\"}"
    file /etc/coredns/fixture.db fixture.test
}
"""
ZONEFILE = """$ORIGIN fixture.test.
$TTL 60
@ IN SOA ns.fixture.test. hostmaster.fixture.test. ( 1 60 60 60 60 )
@ IN NS ns.fixture.test.
ns IN A 192.0.2.53
signal IN A 192.0.2.11
health IN A 192.0.2.10
"""


def _configmap(corefile):
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "saf-dns-fixture", "labels": {"app": "saf-dns-fixture"}},
        "data": {"Corefile": corefile, "fixture.db": ZONEFILE},
    }


def _deployment(image):
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "saf-dns-fixture", "labels": {"app": "saf-dns-fixture"}},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "saf-dns-fixture"}},
            "template": {
                "metadata": {"labels": {"app": "saf-dns-fixture"}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [{
                        "name": "coredns",
                        "image": image,
                        "args": ["-conf", "/etc/coredns/Corefile"],
                        "ports": [{"name": "dns-udp", "containerPort": 1053, "protocol": "UDP"},
                                  {"name": "dns-tcp", "containerPort": 1053, "protocol": "TCP"}],
                        "readinessProbe": {"tcpSocket": {"port": 1053}, "periodSeconds": 1},
                        "volumeMounts": [{"name": "config", "mountPath": "/etc/coredns", "readOnly": True}],
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]},
                            "runAsNonRoot": True,
                            "runAsUser": 65532,
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                    }],
                    "volumes": [{"name": "config", "configMap": {"name": "saf-dns-fixture"}}],
                },
            },
        },
    }


def _apply(lab, resource):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(resource))


def _dns_image(lab):
    result = lab.kubectl(
        "get", "deployments", "-n", "kube-system", "-l", "k8s-app=kube-dns", "-o", "json"
    )
    deployments = json.loads(result.stdout).get("items", [])
    for deployment in deployments:
        for item in deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []):
            if item.get("name") == "coredns" or "coredns" in item.get("image", "").lower():
                return item["image"]
    lab.block("Could not identify the cluster's existing CoreDNS image")


def _query(lab, name, server):
    expected = {CANARY: "192.0.2.11", NORMAL: "192.0.2.10"}[name]
    query = (HERE / "dns-query.py").read_text()
    result = lab.kubectl("exec", "dns-observer", "--", "python", "-c", query, name, server, expected)
    return json.loads(result.stdout)


def _log_rows(text):
    rows = []
    for line in text.splitlines():
        start = line.find('{')
        if start < 0:
            continue
        try:
            row = json.loads(line[start:])
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and {"qname", "qtype", "qclass", "proto", "rcode"} <= row.keys():
            rows.append(row)
    return rows


def _observe(lab, rows):
    name = "scoped-dns-observer"
    _apply(lab, {
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
        "data": {"rows.json": json.dumps(rows), "observer.py": (HERE / "observer.py").read_text()},
    })
    workload = pod(name, [container(
        "observer", image=PYTHON_IMAGE, command=["python", "/fixture/observer.py"],
        volumeMounts=[{"name": "scope", "mountPath": "/fixture", "readOnly": True}],
    )], automountServiceAccountToken=False, volumes=[{"name": "scope", "configMap": {"name": name}}])
    _apply(lab, {
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 45,
                 "template": {"spec": workload["spec"]}},
    })
    lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=55s", timeout=65)
    return json.loads(lab.kubectl("logs", f"job/{name}", "-c", "observer").stdout)


def _wait_deployment(lab):
    status = lab.kubectl("rollout", "status", "deployment/saf-dns-fixture",
                          "--timeout=45s", timeout=55, allow_failure=True)
    if status.returncode != 0:
        lab.kubectl("describe", "pods", "-l", "app=saf-dns-fixture", allow_failure=True)
        lab.kubectl("logs", "deployment/saf-dns-fixture", "-c", "coredns", allow_failure=True)
        lab.block("Owned CoreDNS fixture failed its rollout")
    result = lab.kubectl("get", "pods", "-l", "app=saf-dns-fixture", "-o", "json")
    candidates = [
        item for item in json.loads(result.stdout)["items"]
        if "deletionTimestamp" not in item["metadata"]
        and any(c["type"] == "Ready" and c["status"] == "True"
                for c in item.get("status", {}).get("conditions", []))
    ]
    if len(candidates) != 1:
        lab.block(f"Expected one live fixture CoreDNS Pod, found {len(candidates)}")
    return candidates[0]


def _logs(lab, pod_name):
    return lab.kubectl("logs", pod_name, "-c", "coredns").stdout


def run(lab):
    image = _dns_image(lab)
    _apply(lab, _configmap(COREFILE_NO_LOG))
    _apply(lab, _deployment(image))
    lab.create(pod("dns-observer", [container(
        "client", image=PYTHON_IMAGE, command=["python", "-c", "import time; time.sleep(600)"],
    )], automountServiceAccountToken=False))
    ready(lab, "dns-observer")
    fixture = _wait_deployment(lab)
    ready_image = fixture["status"]["containerStatuses"][0]
    lab.check("positive", "Owned DNS fixture uses the observed CoreDNS image from this pinned Kind release",
              ready_image["ready"] is True and ready_image["image"] == image,
              {"coredns_image": image, "image_is_ready": ready_image["ready"]})
    pod_name = fixture["metadata"]["name"]

    baseline = _query(lab, CANARY, fixture["status"]["podIP"])
    baseline_logs = _logs(lab, pod_name)
    lab.check("red", "The canary resolves before query logging is enabled",
              all(baseline.values()) and CANARY not in baseline_logs,
              {"expected_answer_verified": all(baseline.values()), "query_row_absent": CANARY not in baseline_logs})

    _apply(lab, _configmap(COREFILE_WITH_LOG))
    lab.kubectl("rollout", "restart", "deployment/saf-dns-fixture")
    enabled = _wait_deployment(lab)
    pod_name = enabled["metadata"]["name"]
    answers = {name: _query(lab, name, enabled["status"]["podIP"]) for name in (CANARY, NORMAL)}
    expected = [
        {"qname": name, "qtype": "A", "qclass": "IN", "proto": "udp", "rcode": "NOERROR"}
        for name in sorted(answers)
    ]
    deadline = time.monotonic() + 10
    while True:
        rows = sorted(_log_rows(_logs(lab, pod_name)), key=lambda row: row["qname"])
        if rows == expected or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    answers_ok = all(all(answer.values()) for answer in answers.values())
    restarted = enabled["metadata"]["uid"] != fixture["metadata"]["uid"]
    lab.check("green", "Both actual DNS responses and exact structured stdout records match",
              rows == expected and answers_ok and restarted,
              {"rows": rows, "both_answered": answers_ok, "restarted": restarted})
    alerts = _observe(lab, rows)
    (lab.evidence / "dns-observer-evidence.json").write_text(
        json.dumps({"dns_rows": rows, "observer": alerts}, indent=2, sort_keys=True) + "\n"
    )
    lab.check("positive", "The separate observer Job receives both records and emits only the expected canary alert",
              alerts == {"observed_records": 2, "alerts": [ALERT]},
              alerts)
    extension_spec = importlib.util.spec_from_file_location("dns_anomaly", HERE / "extension.py")
    extension = importlib.util.module_from_spec(extension_spec)
    extension_spec.loader.exec_module(extension)
    extension.run_anomaly_extension(lab, enabled["status"]["podIP"], lambda: _logs(lab, pod_name))

    collector_spec = importlib.util.spec_from_file_location("dns_api_log_collector", HERE / "api-log-collector.py")
    collector_module = importlib.util.module_from_spec(collector_spec)
    collector_spec.loader.exec_module(collector_module)
    collected = collector_module.run_api_log_collector(lab, enabled, extension)
    lab.check(
        "positive",
        "The named collector ServiceAccount has only exact Pod metadata access and CoreDNS Pod log access",
        collected.get("exact_named_rbac_policy") is True
        and collected.get("named_service_account") is True,
        {"exact_named_rbac_policy": collected.get("exact_named_rbac_policy") is True,
         "named_service_account": collected.get("named_service_account"),
         "metadata_pod_names_count": 2, "pod_log_resource_names_count": 1},
    )
    lab.check(
        "positive",
        "The API-reading collector validates the exact ten benign fixture rows from the owned CoreDNS Pod",
        collected.get("collector_completed") is True
        and collected.get("named_target_identity_valid") is True
        and collected.get("target_identity_stable_during_read") is True
        and collected.get("target_log_api_status_200") is True
        and collected.get("exact_case_fixture_rows") is True
        and collected.get("observed_fixture_row_count") == 10,
        {"target_identity_valid": collected.get("named_target_identity_valid") is True,
         "target_identity_stable": collected.get("target_identity_stable_during_read") is True,
         "api_read_succeeded": collected.get("target_log_api_status_200") is True,
         "exact_fixture_rows": collected.get("exact_case_fixture_rows") is True,
         "fixture_row_count": collected.get("observed_fixture_row_count")},
    )
    lab.check(
        "green",
        "The same ServiceAccount is refused access to the unrelated owned DNS client Pod logs",
        collected.get("collector_completed") is True
        and collected.get("unrelated_owned_pod_log_status_403") is True,
        {"unrelated_log_read_refused": collected.get("unrelated_owned_pod_log_status_403") is True,
         "http_status": collected.get("unrelated_status_class")},
    )
