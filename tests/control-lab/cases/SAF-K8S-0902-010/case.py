"""Probe structured role-boundary handling in a disposable Kind workload."""
import json
import base64
import os
from pathlib import Path
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
APP = "saf-role-boundary"
PORT = 8080
SCOPE = (
    "One disposable Kind cluster runs one case-owned Python Pod behind a ClusterIP Service. "
    "The Pod contains a deterministic HTTP fixture and a local recording sink, with no model, "
    "external network call, classifier, or production component. Policy off accepts one fixed "
    "benign request with an extra metadata field and demonstrates that the field is ignored as "
    "data. Policy on permits only a public user role and content, constructs fixed trusted "
    "system/developer roles internally, rejects unknown roles and public developer/system "
    "fields, and proves rejected requests do not reach the recording sink. This is structured "
    "application-boundary evidence only; it does not test prompt classification, model behavior, "
    "prompt-injection detection/generalization, or production serving and gateway configuration. "
    "An additive stage validates a projected client ServiceAccount token with Kubernetes TokenReview "
    "over SAN-verified internal TLS, derives the fixed user role from the verified principal, and "
    "refuses a conflicting role before the same local dispatcher."
)


def _ready_pod(lab, expected_mode):
    deadline = time.monotonic() + 80
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "pods", "-l", "app=" + APP, "-o", "json")
        pods = json.loads(result.stdout)["items"]
        if len(pods) == 1:
            pod = pods[0]
            containers = pod.get("spec", {}).get("containers", [])
            env = containers[0].get("env", []) if containers else []
            conditions = pod.get("status", {}).get("conditions", [])
            ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in conditions)
            if (pod.get("status", {}).get("phase") == "Running" and ready
                    and {"name": "POLICY_MODE", "value": expected_mode} in env):
                return pod
        time.sleep(0.4)
    lab.block("Role-boundary fixture did not become Ready in the requested policy mode")


def _deploy(lab, mode, service_account=None, automount_token=False):
    lab.kubectl("delete", "deployment", APP, "--ignore-not-found=true", "--cascade=foreground", "--wait=true",
                timeout=35)
    labels = {"app": APP, "fixture": "true"}
    container = {
        "name": "fixture", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-B", "/fixture/server.py"],
        "env": [{"name": "POLICY_MODE", "value": mode}],
        "ports": [{"name": "http", "containerPort": PORT}],
        "volumeMounts": [{"name": "code", "mountPath": "/fixture", "readOnly": True}],
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                             "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                      "limits": {"cpu": "200m", "memory": "96Mi"}},
        "readinessProbe": {"httpGet": {"path": "/health", "port": "http",
                                         "scheme": "HTTPS" if mode == "role-source" else "HTTP"},
                           "periodSeconds": 1, "failureThreshold": 20},
    }
    pod_spec = {
        "automountServiceAccountToken": automount_token,
        "terminationGracePeriodSeconds": 1,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                            "runAsGroup": 65534, "fsGroup": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "volumes": [{"name": "code", "configMap": {"name": APP + "-code"}}],
        "containers": [container],
    }
    if mode == "role-source":
        pod_spec["volumes"].append({"name": "tls", "secret": {"secretName": APP + "-tls",
                                                                      "defaultMode": 0o440}})
        container["volumeMounts"].append({"name": "tls", "mountPath": "/fixture-tls", "readOnly": True})
    if service_account:
        pod_spec["serviceAccountName"] = service_account
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": APP, "labels": labels},
                "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                         "selector": {"matchLabels": labels},
                         "template": {"metadata": {"labels": labels}, "spec": pod_spec}}})
    lab.kubectl("rollout", "status", "deployment/" + APP, "--timeout=75s", timeout=85)
    pod = _ready_pod(lab, mode)
    _assert_service_targets(lab, pod)
    return pod


def _assert_service_targets(lab, pod):
    expected_uid = pod["metadata"]["uid"]
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "endpointslice", "-l",
                             "kubernetes.io/service-name=" + APP, "-o", "json")
        slices = json.loads(result.stdout)["items"]
        ready_uids = [endpoint.get("targetRef", {}).get("uid")
                      for item in slices for endpoint in (item.get("endpoints") or [])
                      if endpoint.get("conditions", {}).get("ready") is True]
        if ready_uids == [expected_uid]:
            return
        time.sleep(0.25)
    lab.block("The case-owned Service does not target exactly the current Ready fixture Pod")


def _observe(lab, mode):
    probe = (HERE / "probe.py").read_text(encoding="utf-8")
    result = lab.kubectl("exec", "-i", "deployment/" + APP, "--", "python", "-B", "-",
                         mode, payload=probe, timeout=30)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block("Role-boundary probe returned invalid JSON: " + str(error))


def run(lab):
    source = (HERE / "server.py").read_text(encoding="utf-8")
    probe = (HERE / "probe.py").read_text(encoding="utf-8")
    config = lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                         "metadata": {"name": APP + "-code"}, "immutable": True,
                         "data": {"server.py": source, "probe.py": probe}})
    if config.get("data", {}).get("server.py") != source or config.get("immutable") is not True:
        lab.block("Kubernetes did not retain the exact immutable fixture source")
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": APP},
                "spec": {"type": "ClusterIP", "selector": {"app": APP, "fixture": "true"},
                         "ports": [{"name": "http", "port": PORT, "targetPort": "http"}]}})

    _deploy(lab, "off")
    red = _observe(lab, "off")
    red_result = red.get("results", {}).get("metadata_extra", {})
    red_state = red.get("state", {})
    red_ok = (red.get("mode") == "off" and red_result.get("status") == 200
              and red_result.get("body", {}).get("accepted") is True
              and red_result.get("body", {}).get("metadata_ignored") is True
              and red_state.get("mode") == "off"
              and red_state.get("dispatch_count") == 1
              and red_state.get("last_roles") == ["system", "developer", "user"])
    lab.check("red", "Policy off accepts the fixed benign extra metadata field and ignores it as data",
              red_ok, {"mode": red.get("mode"), "request": red_result,
                       "recording_sink": red_state})

    pod = _deploy(lab, "on")
    green = _observe(lab, "on")
    results = green.get("results", {})
    rejected = {name: results.get(name, {}) for name in (
        "metadata_extra", "unknown_role", "public_developer_field", "public_system_field")}
    after_rejections = green.get("after_rejections", {})
    green_ok = (green.get("mode") == "on"
                and rejected["metadata_extra"].get("status") == 400
                and rejected["metadata_extra"].get("body", {}).get("reason") == "unsupported_field"
                and rejected["unknown_role"].get("status") == 400
                and rejected["unknown_role"].get("body", {}).get("reason") == "unknown_role"
                and rejected["public_developer_field"].get("status") == 400
                and rejected["public_developer_field"].get("body", {}).get("reason") == "reserved_role_field"
                and rejected["public_system_field"].get("status") == 400
                and rejected["public_system_field"].get("body", {}).get("reason") == "reserved_role_field"
                and after_rejections.get("mode") == "on"
                and after_rejections.get("dispatch_count") == 0)
    lab.check("green", "Policy on rejects extra metadata, unknown roles, and client developer/system fields before dispatch",
              green_ok, {"mode": green.get("mode"), "rejections": rejected,
                         "recording_sink_after_rejections": after_rejections})

    positive = results.get("ordinary_user", {})
    positive_state = green.get("after_positive", {})
    positive_ok = (positive.get("status") == 200
                   and positive.get("body", {}).get("answer") == "4"
                   and positive_state.get("dispatch_count") == 1
                   and positive_state.get("last_messages") == [
                       {"role": "system", "content": "Fixture system context."},
                       {"role": "developer", "content": "Fixture developer context."},
                       {"role": "user", "content": "What is 2+2?"}]
                   and pod.get("status", {}).get("phase") == "Running"
                   and any(c.get("type") == "Ready" and c.get("status") == "True"
                           for c in pod.get("status", {}).get("conditions", []))
                   and pod["spec"]["containers"][0].get("image") == IMAGE)
    lab.check("positive", "An ordinary user request builds trusted roles and reaches the deterministic sink",
              positive_ok, {"request": positive, "recording_sink": positive_state,
                            "image": IMAGE,
                            "ready": pod.get("status", {}).get("phase") == "Running"})

    evidence = {"control_id": "SAF-K8S-0902-010", "fixture_only": True,
                "pod_uid": pod["metadata"]["uid"],
                "workload_image": IMAGE, "red": red, "green": green,
                "observation_boundary": "local deterministic recording sink; no model or classifier"}
    (lab.evidence / "role-boundary-observations.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")

    _identity_role_source_witness(lab)


def _identity_role_source_witness(lab):
    server_sa = APP + "-reviewer"
    client_sa = "inference-user"
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": server_sa, "labels": {"fixture": "true"}},
                "automountServiceAccountToken": True})
    _create_fixture_tls_secret(lab)
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": client_sa, "labels": {"fixture": "true"}},
                "automountServiceAccountToken": True})
    role_name = APP + "-tokenreview"
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "metadata": {"name": role_name, "labels": {"fixture": "true"}},
                "rules": [{"apiGroups": ["authentication.k8s.io"],
                           "resources": ["tokenreviews"], "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                "metadata": {"name": role_name, "labels": {"fixture": "true"}},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                            "name": role_name},
                "subjects": [{"kind": "ServiceAccount", "name": server_sa,
                              "namespace": "saf-test"}]})

    allowed = lab.kubectl("auth", "can-i", "create", "tokenreviews.authentication.k8s.io",
                          "--as=system:serviceaccount:saf-test:" + server_sa).stdout.strip()
    unrelated = lab.kubectl("auth", "can-i", "get", "secrets",
                            "--as=system:serviceaccount:saf-test:" + server_sa, allow_failure=True).stdout.strip()
    if allowed != "yes" or unrelated != "no":
        lab.block("The case reviewer identity did not have only the intended TokenReview permission")

    _deploy(lab, "role-source", service_account=server_sa, automount_token=True)
    client = {"apiVersion": "v1", "kind": "Pod",
              "metadata": {"name": APP + "-identity-client",
                           "labels": {"app": APP + "-identity-client", "fixture": "true"}},
              "spec": {"serviceAccountName": client_sa, "automountServiceAccountToken": True,
                       "restartPolicy": "Never", "terminationGracePeriodSeconds": 1,
                       "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                           "seccompProfile": {"type": "RuntimeDefault"}},
                       "volumes": [{"name": "code", "configMap": {"name": APP + "-code"}},
                                   {"name": "tls-trust", "secret": {"secretName": APP + "-tls",
                                                                        "items": [{"key": "tls.crt", "path": "tls.crt"}]}}],
                       "containers": [{"name": "client", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                                       "command": ["python", "-B", "-c", "import time; time.sleep(240)"],
                                       "volumeMounts": [{"name": "code", "mountPath": "/fixture", "readOnly": True},
                                                        {"name": "tls-trust", "mountPath": "/fixture-trust", "readOnly": True}],
                                       "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                     "limits": {"cpu": "100m", "memory": "64Mi"}}}]}}
    lab.create(client)
    lab.kubectl("wait", "--for=condition=Ready", "pod", APP + "-identity-client",
                "--timeout=45s", timeout=50)
    client_pod = json.loads(lab.kubectl("get", "pod", APP + "-identity-client", "-o", "json").stdout)
    projected = (client_pod.get("spec", {}).get("serviceAccountName") == client_sa
                 and client_pod.get("spec", {}).get("automountServiceAccountToken") is True
                 and any(any("serviceAccountToken" in item for item in volume.get("projected", {}).get("sources", []))
                         for volume in client_pod.get("spec", {}).get("volumes", [])))
    if not projected:
        lab.block("Client Pod did not receive its native projected ServiceAccount token")

    raw = lab.kubectl("exec", APP + "-identity-client", "--", "python", "-B",
                      "/fixture/probe.py", "role-source", timeout=25).stdout
    try:
        observed = json.loads(raw)
    except json.JSONDecodeError:
        lab.block("Authenticated role-source witness returned no stable JSON")
    state_ok = (observed.get("baseline_dispatch_count") == 0
                and observed.get("unauthenticated_status") == 401
                and observed.get("unauthenticated_reason") == "identity_unverified"
                and observed.get("dispatch_count_after_unauthenticated") == 0
                and observed.get("conflict_status") == 403
                and observed.get("conflict_reason") == "role_source_conflict"
                and observed.get("dispatch_count_after_conflict") == 0
                and observed.get("positive_status") == 200
                and observed.get("identity_authenticated") is True
                and observed.get("identity_role") == "user"
                and observed.get("identity_binding") == "approved-inference-user-serviceaccount"
                and observed.get("identity_source") == "projected-serviceaccount-tokenreview"
                and observed.get("answer") == "4"
                and observed.get("dispatch_count_after_positive") == 1
                and observed.get("last_roles") == ["system", "developer", "user"])
    lab.check("positive", "The fixed user role is derived from a TokenReview-verified projected ServiceAccount identity; unauthenticated and conflicting role requests stop before dispatch",
              projected and allowed == "yes" and unrelated == "no" and state_ok,
              {"projected_serviceaccount_token_observed": projected,
               "reviewer_can_create_tokenreviews": allowed == "yes",
               "reviewer_cannot_read_secrets": unrelated == "no",
               "unauthenticated_refused_before_dispatch": observed.get("unauthenticated_status") == 401
                   and observed.get("dispatch_count_after_unauthenticated") == 0,
               "conflicting_developer_role_refused_before_dispatch": observed.get("conflict_status") == 403
                   and observed.get("conflict_reason") == "role_source_conflict"
                   and observed.get("dispatch_count_after_conflict") == 0,
               "verified_role_source": observed.get("identity_source"),
               "approved_identity_binding": observed.get("identity_binding"),
               "effective_role": observed.get("identity_role"),
               "permitted_request_dispatches_once": observed.get("positive_status") == 200
                   and observed.get("dispatch_count_after_positive") == 1,
               "trusted_role_order": observed.get("last_roles")})
    (lab.evidence / "authenticated-role-source.json").write_text(
        json.dumps(lab.checks[-1], indent=2, sort_keys=True) + "\n")


def _create_fixture_tls_secret(lab):
    """Create a short-lived SAN-correct endpoint cert without logging its key."""
    name = APP + "-tls"
    with tempfile.TemporaryDirectory(prefix="saf-role-tls-") as directory:
        os.chmod(directory, 0o700)
        root = Path(directory)
        key_path, cert_path = root / "tls.key", root / "tls.crt"
        generated = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key_path), "-out", str(cert_path), "-days", "1",
             "-subj", "/CN=saf-role-boundary",
             "-addext", "subjectAltName=DNS:saf-role-boundary"],
            capture_output=True, text=True, timeout=25, check=False,
        )
        if generated.returncode or not cert_path.is_file() or not key_path.is_file():
            lab.block("The bounded local fixture certificate could not be generated")
        key_path.chmod(0o600)
        cert_path.chmod(0o600)
        manifest_path = root / "secret.json"
        manifest = {"apiVersion": "v1", "kind": "Secret",
                    "metadata": {"name": name, "labels": {"fixture": "true"}},
                    "type": "kubernetes.io/tls",
                    "data": {"tls.crt": base64.b64encode(cert_path.read_bytes()).decode("ascii"),
                             "tls.key": base64.b64encode(key_path.read_bytes()).decode("ascii")}}
        descriptor = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(manifest, output)
        lab.kubectl("create", "-f", str(manifest_path), "-o", "name")
        manifest_path.unlink()
