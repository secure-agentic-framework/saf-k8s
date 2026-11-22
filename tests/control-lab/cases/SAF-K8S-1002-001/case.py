"""Ordinary authentication checks for case-owned metric read endpoints.

No writes are issued to either metrics endpoint. Credentials, TLS private keys,
and authorization headers are kept in process memory or disposable Secrets and
are excluded from the standard lab command log and evidence receipts.
"""
import base64
from contextlib import contextmanager
import http.client
import importlib.util
import json
import re
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import time
from urllib.parse import quote, urlsplit


NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
PROMETHEUS_IMAGE = "docker.io/prom/prometheus:v3.16.0@sha256:e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06"
EXPORTER_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
PROMETHEUS_USER = "saf-synthetic-reader"
PROMETHEUS_SERVICE = "prometheus.saf-test.svc"
EXPORTER_SERVICE = "saf-prom-exporter.saf-test.svc"
METRICS_SERVICE = "metrics-server.kube-system.svc"
METRICS_READER = "saf-1002-reader"
METRICS_DENIED = "saf-1002-denied"
SCOPE_NAMESPACES = ("saf-1002-alpha", "saf-1002-beta")
AGGREGATED_METRICS_ROLE = "system:aggregated-metrics-reader"
METRICS_API_PATH = "/apis/metrics.k8s.io/v1beta1/namespaces/saf-test/pods/saf-metrics-fixture"
PROM_QUERY = 'saf_fixture_metric{fixture="1002-001",workload="synthetic"}'
PROM_LABELS = {"__name__": "saf_fixture_metric", "fixture": "1002-001", "workload": "synthetic"}
SCOPE = (
    "Kubernetes v1.36.1 Kind. TLS-verified authentication checks cover Prometheus, a case-owned HTTPS "
    "exporter, direct Metrics Server exposition and the aggregated Metrics API. Subject- and "
    "resource-specific observations use synthetic principals and metrics. Production endpoint inventory, "
    "permission breadth and deployment settings require separate evidence."
)


def _metrics_case():
    path = Path(__file__).resolve().parents[1] / "SAF-K8S-1001-017" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_metrics_fixture_1001_017", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("The sibling SAF-K8S-1001-017 fixture is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_kind(lab, temporary):
    config = _metrics_case().prepare_kind(lab, temporary)
    text = config.read_text()
    marker = "    apiServer:\n      extraArgs:\n"
    if text.count(marker) != 1:
        lab.block("The reused Kind metrics fixture did not expose the API server arguments")
    config.write_text(text.replace(marker, marker + '        - name: anonymous-auth\n          value: "false"\n'))
    return config


def _write(path, content, mode=0o600):
    path.write_text(content)
    path.chmod(mode)


def _checked(args, *, input_text=None, timeout=60):
    result = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"fixture setup command failed ({args[0]}): {result.stderr.strip()[:500]}")
    return result.stdout


@contextmanager
def _port_forward(lab, namespace, service, remote_port):
    output = lab.kubeconfig.parent / f"forward-{namespace}-{service}.log"
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "-n", namespace, "port-forward", "--address", "127.0.0.1", f"svc/{service}", f":{remote_port}"]
    with output.open("w") as log:
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=lab.env)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                found = re.search(r"Forwarding from 127\.0\.0\.1:(\d+)", output.read_text())
                if found:
                    yield int(found.group(1))
                    return
                if process.poll() is not None:
                    break
                time.sleep(.2)
            lab.block(f"The loopback port-forward for {service} did not become ready")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def _https(port, server_name, ca_file, path, *, authorization=None, basic=None):
    context = ssl.create_default_context(cafile=str(ca_file))
    headers = {"Accept": "application/json, text/plain; version=0.0.4"}
    if authorization is not None:
        headers["Authorization"] = authorization
    if basic is not None:
        headers["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode("ascii")

    class PinnedNameConnection(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection(("127.0.0.1", port), timeout=8)
            self.sock = context.wrap_socket(raw, server_hostname=server_name)

    connection = PinnedNameConnection(server_name, port=port, timeout=10, context=context)
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(256 * 1024)
        return {"status": response.status,
                "headers": {k.lower(): v for k, v in response.getheaders()
                            if k.lower() in ("content-type", "www-authenticate")},
                "body": body.decode("utf-8", "replace")}
    finally:
        connection.close()


def _token(lab, service_account):
    # Direct subprocess capture keeps the synthetic bearer token out of commands.log.
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "-n", "saf-test", "create", "token", service_account, "--duration=10m"]
    return _checked(args, timeout=30).strip()


def _api_get(lab, token=None, namespace="saf-test", pod="saf-metrics-fixture"):
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "config", "view", "--minify", "--raw", "-o"]
    endpoint = urlsplit(_checked([*args, "jsonpath={.clusters[0].cluster.server}"]).strip())
    ca_data = _checked([*args, "jsonpath={.clusters[0].cluster.certificate-authority-data}"]).strip()
    if endpoint.scheme != "https" or endpoint.hostname not in {"127.0.0.1", "localhost"}:
        lab.block("The fixture API server is not exposed on the expected loopback HTTPS listener")
    context = ssl.create_default_context(cadata=base64.b64decode(ca_data).decode("ascii"))
    connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port, timeout=12, context=context)
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    try:
        path = f"/apis/metrics.k8s.io/v1beta1/namespaces/{namespace}/pods/{pod}"
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return {"status": response.status, "body": response.read(65536).decode("utf-8", "replace")}
    finally:
        connection.close()


def _evidence(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _deploy_web(lab, name, image, port, volume_specs, command):
    labels = {"app": name}
    mounts = [{"name": key, "mountPath": path, "readOnly": "emptyDir" not in source}
              for key, path, source in volume_specs]
    volumes = [{"name": key, **source} for key, _, source in volume_specs]
    lab.create({
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
        "spec": {"replicas": 1, "selector": {"matchLabels": labels}, "template": {
            "metadata": {"labels": labels}, "spec": {
                "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                    "fsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                "volumes": volumes,
                "containers": [{"name": name, "image": image, **command,
                                "ports": [{"containerPort": port}], "volumeMounts": mounts,
                                "readinessProbe": {"tcpSocket": {"port": port}, "periodSeconds": 2},
                                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}],
            },
        }},
    })
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                "spec": {"selector": labels, "ports": [{"port": port, "targetPort": port}]}})
    lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=95s", timeout=105)


def _tls_secret(lab, name, directory, dns_name):
    _metrics_case().create_fixture_tls(lab, directory, dns_name)
    lab.kubectl("create", "secret", "tls", name, "--cert", str(directory / "tls.crt"),
                "--key", str(directory / "tls.key"))
    return directory / "ca.crt"


def _install_prometheus(lab, temporary):
    fixture = Path(__file__).with_name("prometheus-exporter.py")
    lab.kubectl("create", "configmap", "saf-prometheus-exporter", f"--from-file=exporter.py={fixture}")
    exporter_password = secrets.token_urlsafe(24)
    exporter_password_file = temporary / "exporter-password"
    _write(exporter_password_file, exporter_password + "\n")
    lab.kubectl("create", "secret", "generic", "saf-exporter-auth",
                 f"--from-file=password={exporter_password_file}")
    exporter_ca = _tls_secret(lab, "saf-exporter-tls", temporary / "exporter-tls", EXPORTER_SERVICE)
    _deploy_web(lab, "saf-prom-exporter", EXPORTER_IMAGE, 9108, [
        ("fixture", "/fixture", {"configMap": {"name": "saf-prometheus-exporter"}}),
        ("tls", "/tls", {"secret": {"secretName": "saf-exporter-tls"}}),
        ("auth", "/auth", {"secret": {"secretName": "saf-exporter-auth"}}),
    ], {"command": ["python", "/fixture/exporter.py"]})

    prometheus_password = secrets.token_urlsafe(24)
    verifier = _checked(["htpasswd", "-Bni", PROMETHEUS_USER], input_text=prometheus_password + "\n",
                        timeout=20).strip().split(":", 1)[1]
    prometheus_ca = _tls_secret(lab, "saf-prometheus-tls", temporary / "prometheus-tls", PROMETHEUS_SERVICE)
    scrape = temporary / "prometheus.yml"
    baseline = temporary / "web-baseline.yml"
    protected = temporary / "web-protected.yml"
    _write(scrape, "global:\n  scrape_interval: 4s\nscrape_configs:\n"
                   "  - job_name: saf-synthetic\n    scheme: https\n"
                   "    basic_auth:\n      username: saf-synthetic-scraper\n"
                   "      password_file: /etc/prometheus/exporter-password\n"
                   "    tls_config:\n      ca_file: /etc/prometheus/exporter-ca.crt\n"
                   f"    static_configs:\n      - targets: [\"{EXPORTER_SERVICE}:9108\"]\n")
    tls_config = ("tls_server_config:\n  cert_file: /tls/tls.crt\n  key_file: /tls/tls.key\n")
    _write(baseline, tls_config)
    _write(protected, tls_config + f"basic_auth_users:\n  {PROMETHEUS_USER}: {verifier}\n")
    for variant, web in (("baseline", baseline), ("protected", protected)):
        lab.kubectl("create", "secret", "generic", f"saf-prometheus-{variant}",
                    f"--from-file=prometheus.yml={scrape}", f"--from-file=web.yml={web}",
                    f"--from-file=exporter-password={exporter_password_file}",
                    f"--from-file=exporter-ca.crt={exporter_ca}")
    _deploy_web(lab, "prometheus", PROMETHEUS_IMAGE, 9090, [
        ("config", "/etc/prometheus", {"secret": {"secretName": "saf-prometheus-baseline"}}),
        ("tls", "/tls", {"secret": {"secretName": "saf-prometheus-tls"}}),
        ("data", "/prometheus", {"emptyDir": {}}),
    ], {"args": ["--config.file=/etc/prometheus/prometheus.yml", "--web.config.file=/etc/prometheus/web.yml",
                   "--storage.tsdb.path=/prometheus", "--storage.tsdb.retention.time=1h"]})
    return prometheus_password, prometheus_ca, exporter_password, exporter_ca


def _wait_for(probe, predicate, description, timeout=65):
    deadline = time.monotonic() + timeout
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(2)
    raise RuntimeError(f"{description} did not become available (last HTTP status {value['status']})")


def _prom_sample(response):
    if response["status"] != 200:
        return False
    document = json.loads(response["body"])
    rows = document["data"]["result"]
    return (document["status"] == "success" and len(rows) == 1
            and all(rows[0]["metric"].get(k) == v for k, v in PROM_LABELS.items())
            and rows[0]["value"][1] == "42")


def _podmetrics(response, namespace="saf-test", pod="saf-metrics-fixture"):
    if response["status"] != 200:
        return False
    document = json.loads(response["body"])
    return (document["kind"] == "PodMetrics" and document["apiVersion"] == "metrics.k8s.io/v1beta1"
            and document["metadata"]["name"] == pod
            and document["metadata"]["namespace"] == namespace
            and any(row["name"] == "idle" and "memory" in row["usage"] for row in document["containers"]))


def _create_metrics_reader(lab):
    service_account = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": METRICS_READER, "namespace": "saf-test"}}
    denied_account = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": METRICS_DENIED, "namespace": "saf-test"}}
    lab.kubectl("apply", "-f", "-", payload=json.dumps(service_account))
    lab.kubectl("apply", "-f", "-", payload=json.dumps(denied_account))
    pod = _fixture_pod("saf-metrics-fixture", "saf-test")
    lab.kubectl("apply", "-f", "-", payload=json.dumps(pod))
    lab.kubectl("wait", "--for=condition=Ready", "pod/saf-metrics-fixture", "--timeout=90s", timeout=95)
    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": {"name": "saf-1002-metric-endpoint-reader"},
            "rules": [{"nonResourceURLs": ["/metrics"], "verbs": ["get"]},
                      {"apiGroups": ["metrics.k8s.io"], "resources": ["pods"], "resourceNames": ["saf-metrics-fixture"], "verbs": ["get"]}]}
    binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
               "metadata": {"name": "saf-1002-metric-endpoint-reader"},
               "subjects": [{"kind": "ServiceAccount", "name": METRICS_READER, "namespace": "saf-test"}],
               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "saf-1002-metric-endpoint-reader"}}
    lab.kubectl("apply", "-f", "-", payload=json.dumps(role))
    lab.kubectl("apply", "-f", "-", payload=json.dumps(binding))



def _fixture_pod(name, namespace):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace},
           "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                    "containers": [{"name": "idle",
                        "image": "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec",
                        "command": ["sh", "-c", "sleep 3600"],
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "50m", "memory": "32Mi"}},
                        "securityContext": {"allowPrivilegeEscalation": False, "runAsNonRoot": True,
                            "runAsUser": 65534, "capabilities": {"drop": ["ALL"]},
                            "seccompProfile": {"type": "RuntimeDefault"}}}]}}


def _aggregate_permissions(lab):
    names = ("view", "edit", "admin")
    roles = json.loads(lab.kubectl("get", "clusterroles", *names, "-o", "json").stdout)["items"]
    return {
        role["metadata"]["name"]: [rule for rule in role.get("rules", [])
                                   if "metrics.k8s.io" in rule.get("apiGroups", [])]
        for role in roles
    }


def _scoped_metrics_access(lab, before):
    """Exercise view aggregation and namespace boundaries with synthetic identities."""
    namespaces = list(SCOPE_NAMESPACES)
    for namespace in namespaces:
        lab.kubectl("create", "namespace", namespace)
        account = {"apiVersion": "v1", "kind": "ServiceAccount",
                   "metadata": {"name": "scoped-reader", "namespace": namespace}}
        lab.kubectl("-n", namespace, "apply", "-f", "-", payload=json.dumps(account))
        pod = _fixture_pod("scope-metrics-fixture", namespace)
        lab.kubectl("-n", namespace, "apply", "-f", "-", payload=json.dumps(pod))
        lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", "pod/scope-metrics-fixture",
                    "--timeout=90s", timeout=95)
        binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                   "metadata": {"name": "scoped-reader-view", "namespace": namespace},
                   "subjects": [{"kind": "ServiceAccount", "name": "scoped-reader", "namespace": namespace}],
                   "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"}}
        lab.kubectl("-n", namespace, "apply", "-f", "-", payload=json.dumps(binding))

    def cluster_role():
        return json.loads(lab.kubectl("get", "clusterrole", AGGREGATED_METRICS_ROLE, "-o", "json").stdout)

    role = cluster_role()
    expected_verbs = {"get", "list", "watch"}
    after = _wait_for(lambda: _aggregate_permissions(lab),
                      lambda roles: len(roles) == 3 and all(
                          any({"pods", "nodes"} <= set(rule.get("resources", []))
                              and expected_verbs <= set(rule.get("verbs", [])) for rule in rules)
                          for rules in roles.values()), "RBAC convergence for view, edit and admin")
    wrong_name = lab.kubectl("get", "clusterrole", "system:metrics-reader", "--ignore-not-found",
                             "-o", "name").stdout.strip()
    lab.check("red", "The original role name does not resolve after the tagged installation",
              not wrong_name and len(before) == 3 and all(not rules for rules in before.values()),
              {"listed_old_role": bool(wrong_name), "preinstall_metrics_roles": sum(map(bool, before.values()))})
    relevant_rules = [rule for rule in role.get("rules", [])
                      if "metrics.k8s.io" in rule.get("apiGroups", [])]
    expected_rule = {"apiGroups": ["metrics.k8s.io"], "resources": ["pods", "nodes"],
                     "verbs": ["get", "list", "watch"]}
    expected_labels = {"rbac.authorization.k8s.io/aggregate-to-view": "true",
                       "rbac.authorization.k8s.io/aggregate-to-edit": "true",
                       "rbac.authorization.k8s.io/aggregate-to-admin": "true"}
    labels = role.get("metadata", {}).get("labels", {})
    exact_role = (relevant_rules == [expected_rule]
                  and all(labels.get(key) == value for key, value in expected_labels.items()))
    lab.check("positive", "Metrics Server installed the tagged aggregated reader role and permissions",
              exact_role, {"name": role.get("metadata", {}).get("name"),
                           "labels": {key: labels.get(key) for key in expected_labels},
                           "metrics_rules": relevant_rules})
    role_metadata = {"name": role["metadata"]["name"], "labels": labels,
                     "metrics_rules": relevant_rules, "before_installation": before,
                     "after_installation": after, "original_role_reference": wrong_name}
    _evidence(lab, "aggregated-metrics-role.json", role_metadata)

    decisions = {}
    for namespace in namespaces:
        subject = f"system:serviceaccount:{namespace}:scoped-reader"
        for target in namespaces:
            result = lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                                 "auth", "can-i", "get", "pods.metrics.k8s.io", "-n", target,
                                 "--as", subject, allow_failure=True)
            decisions[f"{subject} -> {target}"] = {"subject": subject, "namespace": target,
                "verb": "get", "api_group": "metrics.k8s.io", "resource": "pods",
                "allowed": result.stdout.strip().lower() == "yes", "exit_code": result.returncode,
                "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
    _evidence(lab, "metrics-rbac-authorization.json", decisions)
    expected = {f"system:serviceaccount:{namespaces[0]}:scoped-reader -> {namespaces[0]}": True,
                f"system:serviceaccount:{namespaces[0]}:scoped-reader -> {namespaces[1]}": False,
                f"system:serviceaccount:{namespaces[1]}:scoped-reader -> {namespaces[0]}": False,
                f"system:serviceaccount:{namespaces[1]}:scoped-reader -> {namespaces[1]}": True}
    observed = {key: row["allowed"] for key, row in decisions.items()}
    lab.check("positive", "Namespaced view grants metrics reads only in the bound namespace",
              observed == expected, observed)

    tokens = {namespace: _checked(["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                                   "-n", namespace, "create", "token", "scoped-reader", "--duration=10m"], timeout=30).strip()
              for namespace in namespaces}
    runtime = {}
    for namespace in namespaces:
        own = _wait_for(lambda: _api_get(lab, tokens[namespace], namespace, "scope-metrics-fixture"),
                        lambda reply: _podmetrics(reply, namespace, "scope-metrics-fixture"),
                        f"Authorized PodMetrics in {namespace}", timeout=80)
        other_namespace = namespaces[1] if namespace == namespaces[0] else namespaces[0]
        other = _api_get(lab, tokens[namespace], other_namespace, "scope-metrics-fixture")
        runtime[namespace] = {"own_namespace": own, "other_namespace": other}
    runtime_ok = all(row["own_namespace"]["status"] == 200
                     and _podmetrics(row["own_namespace"], namespace, "scope-metrics-fixture")
                     and row["other_namespace"]["status"] == 403
                     for namespace, row in runtime.items())
    _evidence(lab, "metrics-rbac-runtime.json", runtime)
    lab.check("positive", "Scoped readers retrieve own namespace metrics and are denied cross-namespace",
              runtime_ok, {namespace: {"own": row["own_namespace"]["status"],
                                       "other": row["other_namespace"]["status"]}
                           for namespace, row in runtime.items()})


def run(lab):
    temporary = lab.kubeconfig.parent
    base = _metrics_case()
    before = _aggregate_permissions(lab)
    base._install_metrics_server(lab, temporary)
    _create_metrics_reader(lab)
    _scoped_metrics_access(lab, before)
    prom_password, prom_ca, exporter_password, exporter_ca = _install_prometheus(lab, temporary)
    path = "/api/v1/query?query=" + quote(PROM_QUERY)
    raw = {}
    with _port_forward(lab, "saf-test", "prometheus", 9090) as port:
        baseline = _wait_for(lambda: _https(port, PROMETHEUS_SERVICE, prom_ca, path),
                             _prom_sample, "Unauthenticated baseline query")
    raw["prometheus_baseline"] = baseline
    lab.check("red", "TLS alone leaves the exact fixture Prometheus query readable without credentials",
              _prom_sample(baseline), {"http_status": baseline["status"], "fixture_value": 42})
    patch = {"spec": {"template": {"spec": {"volumes": [
        {"name": "config", "secret": {"secretName": "saf-prometheus-protected"}},
    ]}}}}
    lab.kubectl("patch", "deployment", "prometheus", "--type=strategic", "-p", json.dumps(patch))
    lab.kubectl("rollout", "status", "deployment/prometheus", "--timeout=100s", timeout=110)

    with _port_forward(lab, "saf-test", "prometheus", 9090) as port:
        def query(**auth):
            return _https(port, PROMETHEUS_SERVICE, prom_ca, path, **auth)

        prom = {"absent": query(), "malformed": query(authorization="Basic !!!"),
                "wrong": query(basic=f"{PROMETHEUS_USER}:wrong-fixture-password"),
                "permitted": _wait_for(lambda: query(basic=f"{PROMETHEUS_USER}:{prom_password}"),
                                       _prom_sample, "Authenticated Prometheus result")}
    raw["prometheus_protected"] = prom
    status = {name: row["status"] for name, row in prom.items()}
    lab.check("green", "Prometheus requires valid credentials and serves the same exact sample over TLS",
              status == {"absent": 401, "malformed": 401, "wrong": 401, "permitted": 200}
              and _prom_sample(prom["permitted"]), status)

    with _port_forward(lab, "saf-test", "saf-prom-exporter", 9108) as port:
        def scrape(**auth):
            return _https(port, EXPORTER_SERVICE, exporter_ca, "/metrics", **auth)
        exporter = {"absent": scrape(), "wrong": scrape(basic="saf-synthetic-scraper:wrong-fixture-password"),
                    "permitted": scrape(basic=f"saf-synthetic-scraper:{exporter_password}")}
    raw["fixture_exporter"] = exporter
    status = {name: row["status"] for name, row in exporter.items()}
    lab.check("green", "The independent HTTPS exporter requires the scraper credential",
              status == {"absent": 401, "wrong": 401, "permitted": 200}
              and 'saf_fixture_metric{fixture="1002-001",workload="synthetic"} 42' in exporter["permitted"]["body"],
              status)

    token = _token(lab, METRICS_READER)
    denied = _token(lab, METRICS_DENIED)
    metrics_ca = temporary / "metrics-api" / "ca.crt"
    with _port_forward(lab, "kube-system", "metrics-server", 443) as port:
        def endpoint(value=None):
            header = "Bearer " + value if value else None
            return _https(port, METRICS_SERVICE, metrics_ca, "/metrics", authorization=header)
        direct = {"absent": endpoint(), "malformed": endpoint("synthetic-invalid-token"),
                  "unauthorized": endpoint(denied), "permitted": endpoint(token)}
    raw["metrics_server_direct"] = direct
    status = {name: row["status"] for name, row in direct.items()}
    _evidence(lab, "endpoint-decisions.json", raw)
    lab.check("green", "Direct Metrics Server denies anonymous and unauthorized readers",
              status == {"absent": 403, "malformed": 401, "unauthorized": 403, "permitted": 200}
              and "# HELP go_goroutines" in direct["permitted"]["body"], status)

    aggregated = {"absent": _api_get(lab), "malformed": _api_get(lab, "synthetic-invalid-token"),
                  "unauthorized": _api_get(lab, denied),
                  "permitted": _wait_for(lambda: _api_get(lab, token), _podmetrics,
                                         "Authenticated named PodMetrics sample", timeout=75)}
    raw["metrics_api_aggregated"] = aggregated
    _evidence(lab, "endpoint-decisions.json", raw)
    status = {name: row["status"] for name, row in aggregated.items()}
    lab.check("positive", "The aggregated Metrics API validates credentials and returns the exact authorized PodMetrics",
              status == {"absent": 401, "malformed": 401, "unauthorized": 403, "permitted": 200}
              and _podmetrics(aggregated["permitted"]), status)
