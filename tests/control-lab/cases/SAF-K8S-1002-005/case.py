"""Exercise authenticated custom/external metrics and Prometheus discovery RBAC."""
import base64
import http.client
import importlib.util
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
from urllib.parse import quote


NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
ADAPTER_IMAGE = "registry.k8s.io/prometheus-adapter/prometheus-adapter:v0.12.0@sha256:932eae60e2bcf9c4660d6442da066ef1a79b4ea7cc232c61c7303069216ca006"
PROMETHEUS_IMAGE = "docker.io/prom/prometheus:v3.16.0@sha256:e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06"
EXPORTER_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAMESPACES = ("saf-1002-alpha", "saf-1002-beta")
SYSTEM_NS = "saf-1002-monitoring"
PROM_QUERY = 'up{app="saf-metric-source"}'
SCOPE = (
    "Fresh Kind v1.36.1. A digest-pinned Prometheus Adapter v0.12.0 serves real aggregated custom and "
    "external metrics APIs from synthetic Prometheus series. Two namespace-owned ServiceAccount tokens "
    "exercise live API-server authorization and compare exact synthetic samples, cross-namespace and "
    "cluster-scope denials, and the explicit external-rule exception. Prometheus Kubernetes pod discovery "
    "is separately scoped to the two fixture namespaces. A narrow API-server audit policy demonstrates "
    "that coverage depends on configured policy/backend. No production endpoint or identity is used."
)


def _write(path, content, mode=0o600):
    path.write_text(content)
    path.chmod(mode)


def prepare_kind(lab, temporary):
    """Enable an intentionally selective audit policy and retain only metadata events."""
    audit_dir = temporary / "saf-audit"
    audit_dir.mkdir(mode=0o755)
    policy = audit_dir / "policy.yaml"
    _write(policy, """apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
- level: None
  resources:
  - group: external.metrics.k8s.io
    resources: ["*"]
- level: Metadata
  resources:
  - group: custom.metrics.k8s.io
    resources: ["*"]
- level: None
""")
    config = temporary / "kind.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(policy))}
    containerPath: /etc/kubernetes/saf-audit-policy.yaml
    readOnly: true
  - hostPath: {json.dumps(str(audit_dir))}
    containerPath: /var/log/saf-audit
  kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
      - name: audit-policy-file
        value: /etc/kubernetes/saf-audit-policy.yaml
      - name: audit-log-path
        value: /var/log/saf-audit/audit.log
      extraVolumes:
      - name: saf-audit-policy
        hostPath: /etc/kubernetes/saf-audit-policy.yaml
        mountPath: /etc/kubernetes/saf-audit-policy.yaml
        readOnly: true
        pathType: File
      - name: saf-audit-logs
        hostPath: /var/log/saf-audit
        mountPath: /var/log/saf-audit
        readOnly: false
        pathType: DirectoryOrCreate
""")
    return config


def _run(args, *, env=None, input_text=None, timeout=30):
    result = subprocess.run(args, env=env, input=input_text, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stderr.strip()[:400]}")
    return result.stdout


def _evidence(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _create(lab, api_version, kind, name, namespace, spec, *, metadata_extra=None):
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    if metadata_extra:
        metadata.update(metadata_extra)
    obj = {"apiVersion": api_version, "kind": kind, "metadata": metadata}
    obj.update(spec)
    where = ("-n", namespace) if namespace else ()
    lab.kubectl(*where, "create", "-f", "-", payload=json.dumps(obj))


def _apply_namespace(lab, namespace):
    lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}})


def _binding(lab, name, namespace, role_name, subject_name, subject_namespace):
    _create(lab, "rbac.authorization.k8s.io/v1", "RoleBinding", name, namespace, {
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role_name},
        "subjects": [{"kind": "ServiceAccount", "name": subject_name, "namespace": subject_namespace}],
    })


def _port_forward(lab, namespace, service, remote_port):
    path = lab.evidence / f"port-forward-{service}.log"
    env = dict(lab.env)
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "-n", namespace, "port-forward", "--address", "127.0.0.1", f"svc/{service}",
            f":{remote_port}"]
    log = path.open("w")
    process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=env)
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            text = path.read_text()
            found = re.search(r"Forwarding from 127\.0\.0\.1:(\d+)", text)
            if found:
                return process, log, int(found.group(1))
            if process.poll() is not None:
                break
            time.sleep(.25)
        raise RuntimeError(f"Port-forward for {service} did not start")
    except Exception:
        process.terminate()
        log.close()
        raise


def _stop_forward(forward):
    process, log, _ = forward
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    log.close()


def _api_credentials(lab):
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "config", "view", "--minify", "--raw", "-o"]
    server = _run([*args, "jsonpath={.clusters[0].cluster.server}"])
    ca = _run([*args, "jsonpath={.clusters[0].cluster.certificate-authority-data}"])
    # The API server URL and CA remain in process memory; neither is copied to evidence.
    return server.strip(), base64.b64decode(ca.strip()).decode()


def _api_get(server, ca_pem, path, token):
    from urllib.parse import urlsplit
    endpoint = urlsplit(server)
    if endpoint.scheme != "https" or endpoint.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("The fixture Kubernetes API must be a local HTTPS listener")
    context = ssl.create_default_context(cadata=ca_pem)

    class LoopbackTLS(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection((endpoint.hostname, endpoint.port), timeout=8)
            self.sock = context.wrap_socket(raw, server_hostname=endpoint.hostname)

    connection = LoopbackTLS(endpoint.hostname, port=endpoint.port, timeout=12, context=context)
    try:
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(256 * 1024).decode("utf-8", "replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"message": body[:500]}
        audit_ids = [token.strip() for token in (response.getheader("Audit-ID") or "").split(",")
                     if token.strip()]
        if len(set(audit_ids)) > 1:
            raise RuntimeError("The API server and adapter disagree about the request audit ID")
        return {"status": response.status, "body": parsed,
                "audit_id": audit_ids[0] if audit_ids else None, "audit_id_copies": len(audit_ids)}
    finally:
        connection.close()


def _token(lab, namespace, service_account):
    # Capture the synthetic token directly in memory; do not write it to the command log or evidence.
    return _run(["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                 "-n", namespace, "create", "token", service_account, "--duration=10m"],
                env=lab.env, timeout=30).strip()


def _sample_map(reply, metric_type):
    if reply["status"] != 200:
        return {}
    body = reply["body"]
    items = body.get("items", [])
    rows = {}
    for item in items:
        if metric_type == "custom":
            key = item.get("describedObject", {}).get("name", "")
        else:
            key = item.get("metricLabels", {}).get("namespace", "")
        rows[key] = str(item.get("value", ""))
    return rows


def _wait_api(lab, server, ca, path, token, predicate, description, seconds=150):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = _api_get(server, ca, path, token)
        if predicate(last):
            return last
        time.sleep(2)
    history = {"probe": description, "last_response": last}
    _evidence(lab, "last-metrics-response.json", history)
    lab.block(f"{description} unavailable; last status={last['status']}")


EXPORTER = r'''from http.server import BaseHTTPRequestHandler, HTTPServer
import os
namespace=os.environ["NAMESPACE"]
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  requests, queue = (11, 5) if namespace.endswith("alpha") else (22, 9)
  body=(
      f'saf_workload_requests_per_second{{namespace="{namespace}",pod="{namespace}-metrics"}} {requests}\n'
      f'saf_queue_depth{{namespace="{namespace}",queue="synthetic"}} {queue}\n'
      f'saf_shared_queue_depth{{namespace="{namespace}",queue="synthetic"}} {queue}\n'
  ).encode()
  self.send_response(200); self.send_header("Content-Type","text/plain; version=0.0.4"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self,*a): pass
HTTPServer(("0.0.0.0",9108),H).serve_forever()
'''


def _prometheus(lab):
    _create(lab, "v1", "ServiceAccount", "prometheus", SYSTEM_NS, {})
    for namespace in NAMESPACES:
        _create(lab, "rbac.authorization.k8s.io/v1", "Role", "saf-prometheus-pod-discovery", namespace, {
            "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}]})
        _binding(lab, "saf-prometheus-pod-discovery", namespace, "saf-prometheus-pod-discovery",
                 "prometheus", SYSTEM_NS)

    for namespace in NAMESPACES:
        _create(lab, "v1", "ConfigMap", "saf-exporter-code", namespace, {"data": {"exporter.py": EXPORTER}})
        _create(lab, "v1", "Pod", namespace + "-metrics", namespace, {
            "spec": {"automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "source", "image": EXPORTER_IMAGE,
                "command": ["python", "/fixture/exporter.py"], "env": [{"name": "NAMESPACE", "value": namespace}],
                "ports": [{"name": "metrics", "containerPort": 9108}],
                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                "readinessProbe": {"tcpSocket": {"port": 9108}, "periodSeconds": 2},
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}],
                     "volumes": [{"name": "fixture", "configMap": {"name": "saf-exporter-code"}}]}},
            metadata_extra={"labels": {"app": "saf-metric-source"},
                            "annotations": {"prometheus.io/scrape": "true"}})
        lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", "pod/" + namespace + "-metrics", "--timeout=90s", timeout=100)

    prom_config = """global:\n  scrape_interval: 3s\nscrape_configs:\n- job_name: saf-kubernetes-pod-discovery\n  kubernetes_sd_configs:\n  - role: pod\n    namespaces:\n      names: [saf-1002-alpha, saf-1002-beta]\n  relabel_configs:\n  - source_labels: [__meta_kubernetes_pod_label_app]\n    action: keep\n    regex: saf-metric-source\n  - source_labels: [__meta_kubernetes_pod_container_port_name]\n    action: keep\n    regex: metrics\n  - source_labels: [__meta_kubernetes_namespace]\n    target_label: namespace\n  - source_labels: [__meta_kubernetes_pod_name]\n    target_label: pod\n"""
    _create(lab, "v1", "ConfigMap", "saf-prometheus-config", SYSTEM_NS, {"data": {"prometheus.yml": prom_config}})
    _create(lab, "apps/v1", "Deployment", "prometheus", SYSTEM_NS, {"spec": {
        "replicas": 1, "selector": {"matchLabels": {"app": "prometheus"}},
        "template": {"metadata": {"labels": {"app": "prometheus"}}, "spec": {
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "serviceAccountName": "prometheus", "containers": [{"name": "prometheus", "image": PROMETHEUS_IMAGE,
                "args": ["--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.path=/prometheus",
                         "--storage.tsdb.retention.time=1h"], "ports": [{"name": "web", "containerPort": 9090}],
                "volumeMounts": [{"name": "config", "mountPath": "/etc/prometheus", "readOnly": True},
                                 {"name": "data", "mountPath": "/prometheus"}],
                "readinessProbe": {"httpGet": {"path": "/-/ready", "port": 9090}, "periodSeconds": 2},
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}],
            "volumes": [{"name": "config", "configMap": {"name": "saf-prometheus-config"}}, {"name": "data", "emptyDir": {}}]}}}})
    _create(lab, "v1", "Service", "prometheus", SYSTEM_NS, {"spec": {
        "selector": {"app": "prometheus"}, "ports": [{"name": "web", "port": 9090, "targetPort": 9090}]}})
    lab.kubectl("-n", SYSTEM_NS, "rollout", "status", "deployment/prometheus", "--timeout=120s", timeout=130)


def _serving_certificate(lab):
    fixture = Path(__file__).resolve().parents[1] / "SAF-K8S-1001-017" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_adapter_tls_fixture", fixture)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    directory = lab.kubeconfig.parent / "adapter-tls"
    helper.create_fixture_tls(lab, directory, f"prometheus-adapter.{SYSTEM_NS}.svc")
    lab.kubectl("-n", SYSTEM_NS, "create", "secret", "tls", "saf-adapter-tls",
                "--cert", str(directory / "tls.crt"), "--key", str(directory / "tls.key"))
    return base64.b64encode((directory / "ca.crt").read_bytes()).decode()


def _adapter(lab):
    ca = _serving_certificate(lab)
    _create(lab, "v1", "ServiceAccount", "prometheus-adapter", SYSTEM_NS, {})
    # These are the v0.12.0 upstream serving and delegated-auth permissions.
    _create(lab, "rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "saf-adapter-auth-delegator", None, {
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:auth-delegator"},
        "subjects": [{"kind": "ServiceAccount", "name": "prometheus-adapter", "namespace": SYSTEM_NS}]})
    _create(lab, "rbac.authorization.k8s.io/v1", "Role", "saf-adapter-config-reader", "kube-system", {
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["extension-apiserver-authentication"], "verbs": ["get", "list", "watch"]}]})
    _binding(lab, "saf-adapter-config-reader", "kube-system", "saf-adapter-config-reader", "prometheus-adapter", SYSTEM_NS)
    _create(lab, "rbac.authorization.k8s.io/v1", "ClusterRole", "saf-adapter-resource-lister", None, {
        "rules": [{"apiGroups": [""], "resources": ["nodes", "namespaces", "pods", "services"], "verbs": ["get", "list", "watch"]}]})
    _create(lab, "rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "saf-adapter-resource-lister", None, {
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "saf-adapter-resource-lister"},
        "subjects": [{"kind": "ServiceAccount", "name": "prometheus-adapter", "namespace": SYSTEM_NS}]})

    config = """rules:
- seriesQuery: 'saf_workload_requests_per_second{namespace!="",pod!=""}'
  resources:
    overrides:
      namespace: {resource: namespace}
      pod: {resource: pod}
  name:
    matches: '^saf_workload_requests_per_second$'
    as: saf_workload_requests_per_second
  metricsQuery: 'sum(<<.Series>>{<<.LabelMatchers>>}) by (<<.GroupBy>>)'
externalRules:
- seriesQuery: 'saf_queue_depth{namespace!=""}'
  resources:
    overrides:
      namespace: {resource: namespace}
    namespaced: true
  metricsQuery: 'sum(<<.Series>>{<<.LabelMatchers>>}) by (namespace)'
- seriesQuery: 'saf_shared_queue_depth{namespace!=""}'
  resources:
    namespaced: false
  metricsQuery: 'sum(<<.Series>>{<<.LabelMatchers>>}) by (namespace)'
"""
    _create(lab, "v1", "ConfigMap", "adapter-config", SYSTEM_NS, {"data": {"config.yaml": config}})
    _create(lab, "apps/v1", "Deployment", "prometheus-adapter", SYSTEM_NS, {"spec": {
        "replicas": 1, "selector": {"matchLabels": {"app": "prometheus-adapter"}},
        "template": {"metadata": {"labels": {"app": "prometheus-adapter"}}, "spec": {
            "serviceAccountName": "prometheus-adapter", "containers": [{"name": "adapter", "image": ADAPTER_IMAGE,
                "args": ["--tls-cert-file=/var/run/serving-cert/tls.crt",
                         "--tls-private-key-file=/var/run/serving-cert/tls.key",
                         "--config=/etc/adapter/config.yaml",
                         "--metrics-relist-interval=5s", "--metrics-max-age=1m",
                         f"--prometheus-url=http://prometheus.{SYSTEM_NS}.svc:9090/", "--secure-port=6443"],
                "ports": [{"name": "https", "containerPort": 6443}],
                "volumeMounts": [{"name": "config", "mountPath": "/etc/adapter", "readOnly": True},
                                 {"name": "serving-cert", "mountPath": "/var/run/serving-cert", "readOnly": True},
                                 {"name": "tmp", "mountPath": "/tmp"}],
                "readinessProbe": {"httpGet": {"path": "/readyz", "port": "https", "scheme": "HTTPS"}, "initialDelaySeconds": 10, "periodSeconds": 2},
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}],
            "volumes": [{"name": "config", "configMap": {"name": "adapter-config"}}, {"name": "serving-cert", "secret": {"secretName": "saf-adapter-tls"}}, {"name": "tmp", "emptyDir": {}}]}}}})
    _create(lab, "v1", "Service", "prometheus-adapter", SYSTEM_NS, {"spec": {
        "selector": {"app": "prometheus-adapter"}, "ports": [{"name": "https", "port": 443, "targetPort": 6443}]}})
    for group in ("custom.metrics.k8s.io", "external.metrics.k8s.io"):
        version = "v1beta1"
        _create(lab, "apiregistration.k8s.io/v1", "APIService", f"{version}.{group}", None, {"spec": {
            "group": group, "version": version, "groupPriorityMinimum": 100,
            "versionPriority": 100, "insecureSkipTLSVerify": False, "caBundle": ca,
            "service": {"namespace": SYSTEM_NS, "name": "prometheus-adapter", "port": 443}}})
    lab.kubectl("-n", SYSTEM_NS, "rollout", "status", "deployment/prometheus-adapter", "--timeout=150s", timeout=160)
    lab.kubectl("wait", "--for=condition=Available", "apiservice/v1beta1.custom.metrics.k8s.io", "--timeout=150s", timeout=160)
    lab.kubectl("wait", "--for=condition=Available", "apiservice/v1beta1.external.metrics.k8s.io", "--timeout=150s", timeout=160)


def _identities_and_rbac(lab):
    for namespace in NAMESPACES:
        _create(lab, "v1", "ServiceAccount", "scoped-reader", namespace, {})


def _grant_metric_reads(lab):
    for namespace in NAMESPACES:
        _create(lab, "rbac.authorization.k8s.io/v1", "Role", "metric-reader", namespace, {
            "rules": [
                {"apiGroups": ["custom.metrics.k8s.io"], "resources": ["pods/saf_workload_requests_per_second"], "verbs": ["get"]},
                {"apiGroups": ["external.metrics.k8s.io"], "resources": ["saf_queue_depth", "saf_shared_queue_depth"], "verbs": ["list"]},
            ]})
        _binding(lab, "metric-reader", namespace, "metric-reader", "scoped-reader", namespace)


def _discovery_checks(lab):
    decisions = {}
    for namespace in (*NAMESPACES, "default"):
        subject = f"system:serviceaccount:{SYSTEM_NS}:prometheus"
        for verb, resource, target in (("list", "pods", namespace), ("list", "nodes", "")):
            result = lab.kubectl("auth", "can-i", verb, resource, *( ["-n", target] if target else [] ),
                                 "--as", subject, allow_failure=True)
            decisions[f"{verb} {resource} {target or '<cluster>'}"] = {
                "subject": subject, "verb": verb, "resource": resource, "namespace": target or None,
                "allowed": result.stdout.strip().lower() == "yes", "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(), "exit_code": result.returncode}
    expected = {"list pods saf-1002-alpha": True, "list nodes <cluster>": False,
                "list pods default": False, "list pods saf-1002-beta": True}
    actual = {key: item["allowed"] for key, item in decisions.items()}
    _evidence(lab, "prometheus-discovery-rbac.json", decisions)
    lab.check("positive", "Prometheus discovery identity reads pods in both owned namespaces and is denied cluster resources",
              actual == expected, actual)


def _prometheus_samples(lab):
    forward = _port_forward(lab, SYSTEM_NS, "prometheus", 9090)
    try:
        _, _, port = forward
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            query = quote('up{namespace=~"saf-1002-(alpha|beta)"}')
            deadline = time.monotonic() + 60
            last = None
            while time.monotonic() < deadline:
                connection.request("GET", "/api/v1/query?query=" + query)
                response = connection.getresponse()
                payload = json.loads(response.read(256 * 1024))
                last = payload.get("data", {}).get("result", [])
                target_rows = [row for row in last if row.get("metric", {}).get("pod", "").endswith("-metrics")]
                observed = {row.get("metric", {}).get("namespace"): row.get("value", [None, ""])[1]
                            for row in target_rows}
                expected = {namespace: "1" for namespace in NAMESPACES}
                if response.status == 200 and payload.get("status") == "success" and len(target_rows) == 2 and observed == expected:
                    _evidence(lab, "prometheus-discovery-samples.json", {"query": 'up{namespace=~"saf-1002-(alpha|beta)"}',
                                                                           "samples": observed})
                    lab.check("positive", "Prometheus discovers and scrapes exactly one synthetic target in each owned namespace",
                              observed == expected, observed)
                    return
                time.sleep(2)
            lab.block(f"Prometheus did not discover both synthetic targets; last result={last}")
        finally:
            connection.close()
    finally:
        _stop_forward(forward)


def _api_samples_and_authorization(lab):
    server, ca = _api_credentials(lab)
    tokens = {namespace: _token(lab, namespace, "scoped-reader") for namespace in NAMESPACES}
    runtime = {}
    for namespace in NAMESPACES:
        other = NAMESPACES[1] if namespace == NAMESPACES[0] else NAMESPACES[0]
        custom_path = f"/apis/custom.metrics.k8s.io/v1beta1/namespaces/{namespace}/pods/*/saf_workload_requests_per_second"
        external_path = f"/apis/external.metrics.k8s.io/v1beta1/namespaces/{namespace}/saf_queue_depth"
        custom = _wait_api(lab, server, ca, custom_path, tokens[namespace],
                           lambda r: r["status"] == 200 and bool(_sample_map(r, "custom")),
                           f"custom metric for {namespace}")
        external = _wait_api(lab, server, ca, external_path, tokens[namespace],
                             lambda r: r["status"] == 200 and bool(_sample_map(r, "external")),
                             f"external metric values for {namespace}")
        shared_path = f"/apis/external.metrics.k8s.io/v1beta1/namespaces/{namespace}/saf_shared_queue_depth"
        shared = _wait_api(lab, server, ca, shared_path, tokens[namespace],
                           lambda r: r["status"] == 200 and len(_sample_map(r, "external")) == 2,
                           f"explicitly shared external metric for {namespace}")
        cross_custom = _api_get(server, ca,
            f"/apis/custom.metrics.k8s.io/v1beta1/namespaces/{other}/pods/*/saf_workload_requests_per_second", tokens[namespace])
        cross_external = _api_get(server, ca,
            f"/apis/external.metrics.k8s.io/v1beta1/namespaces/{other}/saf_queue_depth", tokens[namespace])
        # Probe the equivalent path without a namespace with the same scoped token.
        cluster_custom = _api_get(server, ca,
            "/apis/custom.metrics.k8s.io/v1beta1/pods/*/saf_workload_requests_per_second", tokens[namespace])
        runtime[namespace] = {"own_custom": custom, "cross_custom": cross_custom,
                              "own_external": external, "cross_external": cross_external, "shared_external": shared,
                              "cluster_scope_custom": cluster_custom}

    samples = {namespace: {"custom": _sample_map(row["own_custom"], "custom"),
                           "external": _sample_map(row["own_external"], "external"),
                           "shared_external": _sample_map(row["shared_external"], "external")}
               for namespace, row in runtime.items()}
    expected_custom = {NAMESPACES[0]: {f"{NAMESPACES[0]}-metrics": "11"},
                       NAMESPACES[1]: {f"{NAMESPACES[1]}-metrics": "22"}}
    expected_external = {NAMESPACES[0]: {NAMESPACES[0]: "5"}, NAMESPACES[1]: {NAMESPACES[1]: "9"}}
    expected_shared = {NAMESPACES[0]: "5", NAMESPACES[1]: "9"}
    _evidence(lab, "metrics-runtime-decisions.json", runtime)
    _evidence(lab, "metrics-samples.json", {"observed": samples, "expected_custom": expected_custom,
                                              "expected_external": expected_external, "expected_shared": expected_shared})
    lab.check("green", "Custom metric reads return only the exact sample for each token's owned namespace",
              all(samples[ns]["custom"] == expected_custom[ns] for ns in NAMESPACES), samples)
    lab.check("green", "The namespaced external rule restricts the same underlying input to each authorized namespace",
              all(samples[ns]["external"] == expected_external[ns] for ns in NAMESPACES), samples)
    lab.check("positive", "The intentionally shared rule returns both fixture namespaces to authorized readers",
              all(samples[ns]["shared_external"] == expected_shared for ns in NAMESPACES), samples)
    denials = {namespace: {"cross_custom": row["cross_custom"]["status"],
                           "cross_external": row["cross_external"]["status"],
                           "cluster_scope_custom": row["cluster_scope_custom"]["status"]}
               for namespace, row in runtime.items()}
    lab.check("positive", "The scoped readers are denied cross-namespace requests and a cluster-scope custom request",
              all(row["cross_custom"] == 403 and row["cross_external"] == 403
                  and row["cluster_scope_custom"] == 403 for row in denials.values()), denials)
    return runtime


def _audit_check(lab, runtime):
    audit_path = lab.kubeconfig.parent / "saf-audit" / "audit.log"
    deadline = time.monotonic() + 20
    expected = {
        out[label]["audit_id"]: out[label]["status"]
        for out in runtime.values() for label in ("own_custom", "cross_custom")
    }
    omitted = {out[label]["audit_id"] for out in runtime.values() for label in ("own_external", "cross_external", "shared_external")}
    if None in expected or None in omitted or len(expected) != 4 or len(omitted) != 6:
        lab.block("Exact request audit IDs are unavailable")
    content = ""
    while time.monotonic() < deadline:
        try:
            content = audit_path.read_text()
            if all(audit_id in content for audit_id in expected):
                break
        except FileNotFoundError:
            pass
        time.sleep(1)
    events = []
    for line in content.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        uri = event.get("requestURI", "")
        group = "custom.metrics.k8s.io" if "custom.metrics.k8s.io" in uri else (
            "external.metrics.k8s.io" if "external.metrics.k8s.io" in uri else "")
        if group:
            events.append({"group": group, "audit_id": event.get("auditID"), "user": event.get("user", {}).get("username"),
                           "verb": event.get("verb"), "requestURI": uri, "stage": event.get("stage"),
                           "responseCode": event.get("responseStatus", {}).get("code")})
    completed = {event["audit_id"]: event["responseCode"] for event in events
                 if event["stage"] == "ResponseComplete"}
    custom_seen = all(completed.get(audit_id) == code for audit_id, code in expected.items())
    external_seen = any(audit_id in content for audit_id in omitted)
    _evidence(lab, "audit-metadata-decisions.json", {"configured_policy": "Metadata for custom metrics; None for external metrics; None catch-all",
                                                       "events": events, "raw_log_preserved": False})
    lab.check("positive", "Audit events follow the configured policy: custom reads logged, external reads omitted",
              custom_seen and not external_seen,
              {"custom_event_seen": custom_seen, "external_event_seen": external_seen,
               "policy_file_configured": True})


def run(lab):
    for namespace in (SYSTEM_NS, *NAMESPACES):
        _apply_namespace(lab, namespace)
    _identities_and_rbac(lab)
    _prometheus(lab)
    _adapter(lab)
    _discovery_checks(lab)
    _prometheus_samples(lab)
    server, ca = _api_credentials(lab)
    denied_token = _token(lab, NAMESPACES[0], "scoped-reader")
    denied_path = f"/apis/custom.metrics.k8s.io/v1beta1/namespaces/{NAMESPACES[0]}/pods/*/saf_workload_requests_per_second"
    unbound = _api_get(server, ca, denied_path, denied_token)
    lab.check("red", "Authenticated namespace identity without a metrics RoleBinding is denied at the real API",
              unbound["status"] == 403, {"http_status": unbound["status"]})
    _evidence(lab, "unbound-metric-read.json", unbound)
    _grant_metric_reads(lab)
    runtime = _api_samples_and_authorization(lab)
    _audit_check(lab, runtime)
