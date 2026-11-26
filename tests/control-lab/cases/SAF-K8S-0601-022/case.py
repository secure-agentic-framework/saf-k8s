"""Test namespace-local image pull Secret delivery and a private fixture pull."""
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid
from typing import Callable, Optional
from collections import Counter
from http.client import HTTPConnection
from urllib.parse import unquote

from fixtures import container, pod, ready

@dataclass(frozen=True)
class PrivatePullFixture:
    """Case-owned handles only; credential values are deliberately absent."""
    registry_container: str
    node_container: str
    registry_alias: str
    repository: str
    digest: str
    image_ref: str
    host_port: int
    htpasswd_path: Path
    secret_name: str
    external_secret_name: str
    provider_data_secret: str


HERE = Path(__file__).resolve().parent
ACCOUNT = "fixture-pull-account"
SECRET = "fixture-empty-pull-config"
SCOPE = (
    "One disposable namespace, an empty dockerconfigjson Secret and normal ServiceAccount "
    "admission. Reference injection and an ordinary public-image workload are verified. "
    "A pinned owned registry separately checks wrong-credential refusal and a correct "
    "same-namespace Secret pulling one exact inert digest. The correct Secret is additionally "
    "reconciled by pinned ESO from a case-owned HTTPS webhook provider. External Secret managers, CI "
    "delivery, rotation and production authorization need separate evidence."
)

ESO_NS = "fixture-eso"
ESO_ACCOUNT = "fixture-eso-sync"
ESO_SOURCE = "fixture-eso-registry-source"
ESO_STORE = "fixture-eso-registry-store"
ESO_EXTERNAL_SECRET = "fixture-eso-registry-target"
ESO_SECRET = "fixture-external-pull-secret"
ESO_DENIED_EXTERNAL_SECRET = "fixture-eso-denied-target"
ESO_DENIED_SECRET = "fixture-external-denied-secret"
ESO_POLICY = "fixture-external-pull-secret-controller.saf.example.org"
ESO_LABEL = "saf.example.org/external-pull-policy"
ESO_DENY = "the designated external pull Secret is managed by its approved controller"
ESO_CHART_VERSION = "2.15.0"
ESO_CHART_SHA = "ed94d41cc67e392ea45e370345eb491b0fdc21387f1aaaefcf8e2e6c85089e1d"
ESO_IMAGE_TAG = "v2.15.0@sha256:6888f243e5f8f7592c6d7fae2a5547c9e33531441b47b53807b9093b25a00e31"
ESO_PYTHON_IMAGE = (
    "docker.io/library/python:3.13.2-alpine@sha256:"
    "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
)


def classify(surface, form):
    if form == "direct-value" and surface in {"Pod workload", "Dockerfile", "CI environment"}:
        return "prohibited-value"
    if surface == "Pod imagePullSecrets reference" and form == "name-only-reference":
        return "allowed-reference"
    return "unclassified"


def evaluate_examples(lab):
    samples = json.loads((HERE / "embedding-cases.json").read_text())
    observed = {sample["surface"]: classify(sample["surface"], sample["form"])
                for sample in samples}
    expected = {
        "Pod workload": "prohibited-value",
        "Dockerfile": "prohibited-value",
        "CI environment": "prohibited-value",
        "Pod imagePullSecrets reference": "allowed-reference",
    }
    lab.check("red", "The policy example flags embedded-value forms in each named surface",
              observed == expected, observed)


def create_empty_pull_secret(lab):
    resource = {
        "apiVersion": "v1", "kind": "Secret", "metadata": {"name": SECRET},
        "type": "kubernetes.io/dockerconfigjson",
        "stringData": {".dockerconfigjson": json.dumps({"auths": {}})},
    }
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", "saf-test", "--request-timeout=20s",
        "create", "-f", "-", "-o", "name",
    ]
    result = subprocess.run(command, input=json.dumps(resource), text=True,
                            capture_output=True, env=lab.env, timeout=30)
    lab.check("positive", "The API admits the namespace-local empty pull configuration",
              result.returncode == 0 and result.stdout.strip() == f"secret/{SECRET}",
              {"secret_admitted": result.returncode == 0})


REGISTRY_IMAGE = (
    "docker.io/library/registry:3.0.0@sha256:"
    "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
SKOPEO_IMAGE = (
    "quay.io/skopeo/stable:v1.20.0@sha256:"
    "47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4"
)


def _quiet(args, *, env, input_text=None, timeout=45, allow_failure=False):
    """Keep credential-adjacent subprocess output out of evidence and command logs."""
    try:
        result = subprocess.run(args, input=input_text, text=True, capture_output=True,
                                env=env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"{Path(args[0]).name} could not complete") from error
    if result.returncode and not allow_failure:
        raise RuntimeError(f"{Path(args[0]).name} returned a failure")
    return result


def _quiet_kubectl(lab, *args, input_text=None, timeout=45, allow_failure=False):
    return _quiet([
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", "saf-test", f"--request-timeout={timeout - 5}s", *args,
    ], env=lab.env, input_text=input_text, timeout=timeout, allow_failure=allow_failure)


def _install_eso(lab, temp):
    lab.command("helm", "pull", "external-secrets", "--repo", "https://charts.external-secrets.io",
                "--version", ESO_CHART_VERSION, "--destination", str(temp), timeout=90)
    chart = temp / f"external-secrets-{ESO_CHART_VERSION}.tgz"
    if hashlib.sha256(chart.read_bytes()).hexdigest() != ESO_CHART_SHA:
        lab.block("External Secrets Operator chart digest did not match the reviewed version")
    lab.command("helm", "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
                "upgrade", "--install", "fixture-eso", str(chart), "--namespace", ESO_NS,
                "--create-namespace", "--set-string", f"serviceAccount.name={ESO_ACCOUNT}",
                "--set-string", f"image.tag={ESO_IMAGE_TAG}",
                "--set-string", f"webhook.image.tag={ESO_IMAGE_TAG}",
                "--set-string", f"certController.image.tag={ESO_IMAGE_TAG}",
                "--wait", "--timeout", "160s", timeout=175)


def _start_eso_source(lab, temp, registry_config_json):
    cert, key = temp / "eso-provider.pem", temp / "eso-provider-key.pem"
    source_dns = f"{ESO_SOURCE}.saf-test.svc"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=" + source_dns, "-addext", "subjectAltName=DNS:" + source_dns,
                "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(key), "-out", str(cert))
    lab.kubectl("create", "secret", "tls", ESO_SOURCE, "--cert=" + str(cert), "--key=" + str(key), "-o", "name")

    source_code = {
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": ESO_SOURCE},
        "data": {"server.py": (HERE / "provider.py").read_text(encoding="utf-8")},
    }
    created = _quiet_kubectl(lab, "create", "-f", "-", "-o", "name",
                             input_text=json.dumps(source_code), timeout=20)
    if created.returncode or created.stdout.strip() != f"configmap/{ESO_SOURCE}":
        raise RuntimeError("case-owned external-secret provider code was not created")
    source_data = {"apiVersion": "v1", "kind": "Secret",
                   "metadata": {"name": ESO_SOURCE + "-data"},
                   "stringData": {"registry-config.json": registry_config_json}}
    created = _quiet_kubectl(lab, "create", "-f", "-", "-o", "name",
                             input_text=json.dumps(source_data), timeout=20)
    if created.returncode or created.stdout.strip() != f"secret/{ESO_SOURCE}-data":
        raise RuntimeError("case-owned external-secret fixture data was not created")

    provider = pod(ESO_SOURCE, [container("source", image=ESO_PYTHON_IMAGE,
        command=["python3", "/source/server.py"], volumeMounts=[
            {"name": "code", "mountPath": "/source", "readOnly": True},
            {"name": "data", "mountPath": "/data", "readOnly": True},
            {"name": "tls", "mountPath": "/tls", "readOnly": True},
            {"name": "evidence", "mountPath": "/evidence"},
        ])], automountServiceAccountToken=False,
        securityContext={"fsGroup": 65534}, volumes=[
            {"name": "code", "configMap": {"name": ESO_SOURCE}},
            {"name": "data", "secret": {"secretName": ESO_SOURCE + "-data", "defaultMode": 0o440}},
            {"name": "tls", "secret": {"secretName": ESO_SOURCE, "defaultMode": 0o440}},
            {"name": "evidence", "emptyDir": {}},
        ])
    provider["metadata"]["labels"] = {"app": ESO_SOURCE}
    lab.create(provider)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": ESO_SOURCE},
                "spec": {"selector": {"app": ESO_SOURCE}, "ports": [{"port": 9443, "targetPort": 9443}]}})
    ready(lab, ESO_SOURCE)
    return base64.b64encode(cert.read_bytes()).decode("ascii")


def _install_eso_target_policy(lab):
    actor = f"system:serviceaccount:{ESO_NS}:{ESO_ACCOUNT}"
    lab.kubectl("label", "namespace", "saf-test", f"{ESO_LABEL}=true")
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": ESO_POLICY},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"],
                    "operations": ["CREATE", "UPDATE"], "resources": ["secrets"]}]},
                    "validations": [{"expression": f"object.metadata.name != '{ESO_SECRET}' || request.userInfo.username == '{actor}'",
                                     "message": ESO_DENY}]}})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": ESO_POLICY},
                "spec": {"policyName": ESO_POLICY, "validationActions": ["Deny"],
                         "matchResources": {"namespaceSelector": {"matchLabels": {ESO_LABEL: "true"}}}}})


def _external_secret(name, target, remote_key):
    return {"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret",
            "metadata": {"name": name},
            "spec": {"refreshInterval": "1h", "refreshPolicy": "Periodic",
                     "secretStoreRef": {"name": ESO_STORE, "kind": "SecretStore"},
                     "target": {"name": target, "creationPolicy": "Owner", "deletionPolicy": "Retain",
                                "template": {"type": "kubernetes.io/dockerconfigjson"}},
                     "data": [{"secretKey": ".dockerconfigjson", "remoteRef": {"key": remote_key}}]}}


def _create_eso_store(lab, ca_bundle):
    server_dns = f"{ESO_SOURCE}.saf-test.svc"
    lab.create({"apiVersion": "external-secrets.io/v1", "kind": "SecretStore",
                "metadata": {"name": ESO_STORE},
                "spec": {"provider": {"webhook": {
                    "url": f"https://{server_dns}:9443/{{{{ .remoteRef.key }}}}", "method": "GET",
                    "timeout": "3s", "result": {"jsonPath": "$.value"}, "caBundle": ca_bundle}}}})


def _external_secret_condition(lab, name):
    result = lab.kubectl("get", f"externalsecret/{name}",
                         "-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}",
                         allow_failure=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def _quiet_secret(lab, name):
    result = _quiet_kubectl(lab, "get", "secret", name, "-o", "json",
                            timeout=15, allow_failure=True)
    return json.loads(result.stdout) if result.returncode == 0 else None


def _provider_rows(lab):
    result = _quiet_kubectl(lab, "exec", ESO_SOURCE, "--", "cat",
                            "/evidence/provider-access.jsonl", timeout=15, allow_failure=True)
    if result.returncode:
        return []
    rows = []
    for line in result.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if set(row) == {"path", "status"}:
            rows.append(row)
    return rows


def _poll(lab, probe, expected, failure, seconds=70):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if probe() == expected:
            return
        time.sleep(1)
    lab.block(failure)


def _reconcile_external_pull_secret(lab, temp, alias, good_config):
    """Use the pinned local ESO/Webhook fixture to create the exact pull Secret."""
    _install_eso(lab, temp)
    ca_bundle = _start_eso_source(lab, temp, json.dumps(good_config, sort_keys=True))
    _install_eso_target_policy(lab)
    _create_eso_store(lab, ca_bundle)

    direct_candidate = {"apiVersion": "v1", "kind": "Secret",
                        "metadata": {"name": ESO_SECRET},
                        "type": "kubernetes.io/dockerconfigjson",
                        "stringData": {".dockerconfigjson": json.dumps({"auths": {alias: {"auth": "fixture-only"}}})}}
    def direct_write_denied():
        direct = lab.create(direct_candidate, dry_run=True, allow_failure=True)
        return direct.returncode != 0 and ESO_POLICY in direct.stderr and ESO_DENY in direct.stderr
    _poll(lab, direct_write_denied, True,
          "The target Secret admission rule did not become effective", seconds=30)
    direct_denied = True

    lab.create(_external_secret(ESO_DENIED_EXTERNAL_SECRET, ESO_DENIED_SECRET,
                                "denied-registry-auth"))
    def denied_provider_read():
        rows = _provider_rows(lab)
        return (_external_secret_condition(lab, ESO_DENIED_EXTERNAL_SECRET) == "False"
                and any(row == {"path": "/denied-registry-auth", "status": 403} for row in rows))
    _poll(lab, denied_provider_read, True,
          "The denied external read did not produce its exact provider 403 and failed Ready state")
    denied_target_absent = _quiet_secret(lab, ESO_DENIED_SECRET) is None
    lab.check("red", "A denied provider read returns 403, fails reconciliation, and creates no target Secret",
              denied_target_absent,
              {"provider_403_observed": True, "external_secret_not_ready": True,
               "denied_target_absent": denied_target_absent})

    lab.create(_external_secret(ESO_EXTERNAL_SECRET, ESO_SECRET, "fixture-registry-auth"))
    def target_matches():
        row = _quiet_secret(lab, ESO_SECRET)
        if not row or row.get("type") != "kubernetes.io/dockerconfigjson":
            return False
        encoded = row.get("data", {}).get(".dockerconfigjson", "")
        try:
            observed = json.loads(base64.b64decode(encoded, validate=True))
        except (ValueError, json.JSONDecodeError):
            return False
        owner = any(ref.get("kind") == "ExternalSecret" and ref.get("name") == ESO_EXTERNAL_SECRET
                    for ref in row.get("metadata", {}).get("ownerReferences", []))
        provider_200 = any(event == {"path": "/fixture-registry-auth", "status": 200}
                           for event in _provider_rows(lab))
        return (_external_secret_condition(lab, ESO_EXTERNAL_SECRET) == "True"
                and owner and observed == good_config and provider_200)
    _poll(lab, target_matches, True,
          "The approved ExternalSecret did not reconcile the exact owned dockerconfigjson target")
    synced = _quiet_secret(lab, ESO_SECRET) or {}
    encoded = synced.get("data", {}).get(".dockerconfigjson", "")
    try:
        synchronized_config = json.loads(base64.b64decode(encoded, validate=True))
    except (ValueError, json.JSONDecodeError):
        synchronized_config = None
    owner_match = any(ref.get("kind") == "ExternalSecret" and ref.get("name") == ESO_EXTERNAL_SECRET
                      for ref in synced.get("metadata", {}).get("ownerReferences", []))
    provider_200 = any(event == {"path": "/fixture-registry-auth", "status": 200}
                       for event in _provider_rows(lab))
    target_matches_exactly = (synced.get("type") == "kubernetes.io/dockerconfigjson"
                              and synchronized_config == good_config and owner_match
                              and ".dockerconfigjson" in synced.get("data", {}) and provider_200
                              and _external_secret_condition(lab, ESO_EXTERNAL_SECRET) == "True")
    lab.check("green", "The approved controller owns the exact pull Secret while direct target writes are denied",
              direct_denied and target_matches_exactly,
              {"direct_target_write_denied": direct_denied,
               "dockerconfigjson_type_match": synced.get("type") == "kubernetes.io/dockerconfigjson",
               "dockerconfigjson_value_matches_in_memory": synchronized_config == good_config,
               "dockerconfigjson_key_present": ".dockerconfigjson" in synced.get("data", {}),
               "provider_200_observed": provider_200,
               "external_secret_owner_match": owner_match,
               "external_secret_ready": _external_secret_condition(lab, ESO_EXTERNAL_SECRET) == "True"})


def _private_image_pod(name, image, secret):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": "saf-test"},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "imagePullSecrets": [{"name": secret}],
            "containers": [{
                "name": "fixture", "image": image, "imagePullPolicy": "Always",
                "command": ["sh", "-ec", "printf private-pull-ok"],
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "32Mi"}},
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                    "runAsNonRoot": True, "runAsUser": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            }],
        },
    }


def _registry_records(raw):
    """Read the pinned registry's combined HTTP access log, without retaining it."""
    records = []
    for line in raw.splitlines():
        entry = re.match(
            r'^\S+ \S+ \S+ \[[^]]+\] "(HEAD|GET) (/v2/\S*) HTTP/[\d.]+" (\d{3}) (?:\d+|-)(?: |$)',
            line,
        )
        if entry:
            method, uri, status = entry.groups()
            records.append((method, unquote(uri.split("?", 1)[0]), int(status)))
    return records


def _record_delta(before, after):
    remaining = Counter(before)
    delta = []
    for record in after:
        if remaining[record]:
            remaining[record] -= 1
        else:
            delta.append(record)
    return delta


def _wait_registry(host_port):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        connection = HTTPConnection("127.0.0.1", host_port, timeout=2)
        try:
            connection.request("GET", "/v2/")
            if connection.getresponse().status == 401:
                return
        except OSError:
            pass
        finally:
            connection.close()
        time.sleep(0.3)
    raise RuntimeError("owned registry did not issue its expected authentication challenge")


def _get_pod_quiet(lab, name):
    result = _quiet([
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", "saf-test", "--request-timeout=10s", "get", "pod", name, "-o", "json",
    ], env=lab.env, timeout=15, allow_failure=True)
    if result.returncode:
        return None
    return json.loads(result.stdout)


def _wait_private_pod(lab, name, *, denied=False, timeout=60):
    deadline = time.monotonic() + timeout
    last = None
    expected = {"ErrImagePull", "ImagePullBackOff"}
    while time.monotonic() < deadline:
        last = _get_pod_quiet(lab, name)
        if last:
            status = last.get("status", {})
            containers = status.get("containerStatuses", [])
            waiting = {c.get("state", {}).get("waiting", {}).get("reason") for c in containers}
            if denied and waiting & expected:
                return last
            if not denied and (status.get("phase") in {"Succeeded", "Failed"}):
                return last
        time.sleep(1)
    return last


def _node_has_digest(lab, node, digest):
    result = _quiet(["docker", "exec", node, "crictl", "images", "-o", "json"],
                    env=lab.env, timeout=20)
    try:
        inventory = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("CRI image inventory was not JSON") from error
    for image in inventory.get("images", []):
        if digest in image.get("repoDigests", []) or digest in image.get("repoTags", []):
            return True
        if any(isinstance(value, str) and value.endswith("@" + digest)
               for value in image.get("repoDigests", [])):
            return True
    return False


def _node_has_private_reference(lab, node, image, digest):
    result = _quiet(["docker", "exec", node, "crictl", "inspecti", image],
                    env=lab.env, timeout=20, allow_failure=True)
    if result.returncode:
        return False
    try:
        status = json.loads(result.stdout).get("status", {})
    except json.JSONDecodeError as error:
        raise RuntimeError("CRI image inspection was not JSON") from error
    return image in status.get("repoDigests", []) and image.endswith("@" + digest)


def _create_pull_secret(lab, name, path):
    result = lab.kubectl(
        "create", "secret", "generic", name, "--type=kubernetes.io/dockerconfigjson",
        "--from-file=.dockerconfigjson=" + str(path), timeout=25,
    )
    return result.returncode == 0 and result.stdout.strip() == f"secret/{name} created"


def run_private_pull_checks(lab, *, on_pull_verified: Optional[Callable[[PrivatePullFixture], None]] = None):
    """Prove private pulls; optionally expose the owned lifecycle before cleanup."""
    registry = f"saf-private-{lab.cluster}"
    node = f"{lab.cluster}-control-plane"
    network = f"{lab.cluster}-pull-net"
    tmp = Path(tempfile.mkdtemp(prefix="saf-0601-022-pull-"))
    os.chmod(tmp, 0o700)
    network_created = registry_started = False
    cleanup_failed = False
    try:
        if lab.command("docker", "container", "inspect", registry,
                       allow_failure=True).returncode == 0:
            lab.block("Generated private-pull container name already exists")
        for image in (REGISTRY_IMAGE, SKOPEO_IMAGE, "docker.io/library/busybox:1.37.0@sha256:"
                      "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec",
                      ESO_PYTHON_IMAGE):
            lab.command("docker", "image", "inspect", "--format", "{{.Id}}", image)

        if lab.command("docker", "network", "inspect", network, allow_failure=True).returncode == 0:
            lab.block("Generated private-pull Docker network already exists")
        network_created = True
        lab.command("docker", "network", "create", network)
        lab.command("docker", "network", "connect", network, node)

        username = "saf-pull-" + secrets.token_hex(6)
        password = secrets.token_urlsafe(32)
        wrong_password = secrets.token_urlsafe(32)
        auth_result = _quiet(["htpasswd", "-B", "-n", "-i", username], env=lab.env,
                             input_text=password + "\n", timeout=15)
        htpasswd = tmp / "htpasswd"
        htpasswd.write_text(auth_result.stdout, encoding="utf-8")
        htpasswd.chmod(0o600)

        alias = "saf-pull-reg-" + uuid.uuid4().hex[:10]
        registry_started = True
        lab.command(
            "docker", "run", "--detach", "--rm", "--name", registry,
            "--network", network, "--network-alias", alias,
            "--publish", "127.0.0.1::5000",
            "--env", "REGISTRY_LOG_ACCESSLOG_DISABLED=false",
            "--env", "REGISTRY_AUTH=htpasswd",
            "--env", "REGISTRY_AUTH_HTPASSWD_REALM=saf-0601-022",
            "--env", "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
            "--volume", f"{htpasswd}:/auth/htpasswd:ro", REGISTRY_IMAGE,
        )
        port_rows = lab.command("docker", "port", registry, "5000/tcp").stdout.strip().splitlines()
        if len(port_rows) != 1:
            lab.block("owned registry has an unexpected published endpoint")
        match = re.fullmatch(r"127\.0\.0\.1:(\d+)", port_rows[0])
        if not match:
            lab.block("owned registry did not bind exclusively to IPv4 loopback")
        _wait_registry(int(match.group(1)))

        hosts_dir = tmp / "certs.d" / f"{alias}:5000"
        hosts_dir.mkdir(parents=True)
        hosts = hosts_dir / "hosts.toml"
        hosts.write_text(f'[host."http://{alias}:5000"]\ncapabilities = ["pull", "resolve"]\n',
                         encoding="utf-8")
        settings = f"/etc/containerd/certs.d/{alias}:5000"
        lab.command("docker", "exec", "--user", "0", node, "mkdir", "-p", settings)
        lab.command("docker", "cp", str(hosts), f"{node}:{settings}/hosts.toml")

        seed = tmp / "seed"
        seed.mkdir(mode=0o700)
        auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        authfile = seed / "auth.json"
        authfile.write_text(json.dumps({"auths": {f"{alias}:5000": {"auth": auth}}}),
                            encoding="utf-8")
        authfile.chmod(0o600)
        archive = seed / "fixture.tar"
        busybox = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
        _quiet(["docker", "image", "save", "--output", str(archive), busybox],
               env=lab.env, timeout=60)
        repo = "saf-fixture/0601-022/busybox"
        digest_file = seed / "digest"
        _quiet([
            "docker", "run", "--rm", "--network", network, "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--volume", f"{seed}:/fixture", SKOPEO_IMAGE,
            "copy", "--format", "oci", "--authfile", "/fixture/auth.json", "--dest-tls-verify=false",
            "--digestfile", "/fixture/digest", "docker-archive:/fixture/fixture.tar",
            f"docker://{alias}:5000/{repo}:owned",
        ], env=lab.env, timeout=120)
        digest = digest_file.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            lab.block("owned image push did not return an immutable digest")
        image = f"{alias}:5000/{repo}@{digest}"

        wrong_config = {"auths": {f"{alias}:5000": {
            "username": username, "password": wrong_password,
            "auth": base64.b64encode(f"{username}:{wrong_password}".encode()).decode(),
        }}}
        good_config = {"auths": {f"{alias}:5000": {
            "username": username, "password": password,
            "auth": base64.b64encode(f"{username}:{password}".encode()).decode(),
        }}}
        wrong_file = tmp / "wrong-config.json"
        wrong_file.write_text(json.dumps(wrong_config), encoding="utf-8")
        wrong_file.chmod(0o600)
        _reconcile_external_pull_secret(lab, tmp, f"{alias}:5000", good_config)
        del username, password, wrong_password, auth, authfile, wrong_config
        wrong_secret, good_secret = "fixture-wrong-private-pull", ESO_SECRET
        if not _create_pull_secret(lab, wrong_secret, wrong_file):
            lab.block("wrong-credential fixture Secret was not admitted")
        del good_config

        if _node_has_digest(lab, node, digest):
            lab.block("Unique private fixture digest unexpectedly exists in the node cache")

        def registry_log():
            return _quiet(["docker", "logs", registry], env=lab.env, timeout=15).stdout

        before_denied = _registry_records(registry_log())
        denied_name = "private-pull-wrong-credential"
        lab.create(_private_image_pod(denied_name, image, wrong_secret))
        denied_pod = _wait_private_pod(lab, denied_name, denied=True, timeout=60) or {}
        statuses = denied_pod.get("status", {}).get("containerStatuses", [])
        waiting = {item.get("state", {}).get("waiting", {}).get("reason") for item in statuses}
        started = any(item.get("containerID") or item.get("state", {}).get("running")
                      or item.get("state", {}).get("terminated") for item in statuses)
        denied_log = _registry_records(registry_log())
        denied_delta = _record_delta(before_denied, denied_log)
        manifest_path = f"/v2/{repo}/manifests/{digest}"
        registry_denial = any(method in {"HEAD", "GET"} and uri in {"/v2/", manifest_path} and status == 401
                              for method, uri, status in denied_delta)
        credential_error = any(
            image in message and re.search(r"(?i)\b401\b|unauthorized|authentication required", message)
            for item in statuses for message in [item.get("state", {}).get("waiting", {}).get("message", "")]
        )
        digest_cached = _node_has_digest(lab, node, digest)
        denial_observed = bool(waiting & {"ErrImagePull", "ImagePullBackOff"})
        lab.check("red", "The wrong same-namespace pull credential is refused by the owned registry",
                  denial_observed and not started and registry_denial and credential_error and not digest_cached,
                  {"pod_refused": denial_observed, "no_container_started": not started,
                   "owned_registry_401_observed": registry_denial, "exact_image_credential_error": credential_error,
                   "digest_not_cached": not digest_cached})

        lab.kubectl("delete", "pod", denied_name, "--wait=true", "--timeout=45s")
        before_allowed = _registry_records(registry_log())
        allowed_name = "private-pull-correct-credential"
        lab.create(_private_image_pod(allowed_name, image, good_secret))
        allowed_pod = _wait_private_pod(lab, allowed_name, timeout=90) or {}
        allowed_status = (allowed_pod.get("status", {}).get("containerStatuses") or [{}])[0]
        phase = allowed_pod.get("status", {}).get("phase")
        output = _quiet([
            "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "--namespace", "saf-test", "--request-timeout=15s", "logs", allowed_name,
        ], env=lab.env, timeout=20, allow_failure=True)
        log_delta = _record_delta(before_allowed, _registry_records(registry_log()))
        manifest_200 = any(method == "GET" and uri == manifest_path and status == 200
                           for method, uri, status in log_delta)
        # CRI imageID may be the config digest; require the exact registry repoDigest.
        exact_repo_digest = _node_has_private_reference(lab, node, image, digest)
        good_pull = (phase == "Succeeded" and output.returncode == 0
                     and output.stdout.strip() == "private-pull-ok"
                     and manifest_200 and exact_repo_digest and not allowed_status.get("error"))
        lab.check("positive", "The correct same-namespace Secret authorizes an exact private-image pull",
                  good_pull,
                  {"pod_succeeded": phase == "Succeeded", "command_succeeded": output.returncode == 0
                   and output.stdout.strip() == "private-pull-ok", "manifest_request_authorized": manifest_200,
                   "exact_digest_observed": exact_repo_digest})
        if good_pull and on_pull_verified is not None:
            on_pull_verified(PrivatePullFixture(
                registry_container=registry, node_container=node,
                registry_alias=alias, repository=repo, digest=digest, image_ref=image,
                host_port=int(match.group(1)), htpasswd_path=htpasswd,
                secret_name=good_secret, external_secret_name=ESO_EXTERNAL_SECRET,
                provider_data_secret=ESO_SOURCE + "-data"))
    except RuntimeError as error:
        lab.block(str(error))
    finally:
        cleanups = []
        if registry_started:
            cleanups.append(("container", ["docker", "rm", "-f", registry],
                             ["docker", "container", "inspect", registry]))
        if network_created:
            # The owned Kind node stays live until the enclosing runner cleans up.
            try:
                _quiet(["docker", "network", "disconnect", network, node], env=lab.env,
                       timeout=20, allow_failure=True)
            except RuntimeError:
                cleanup_failed = True
            cleanups.append(("network", ["docker", "network", "rm", network],
                             ["docker", "network", "inspect", network]))
        for _kind, remove, inspect in cleanups:
            try:
                _quiet(remove, env=lab.env, timeout=20, allow_failure=True)
                remaining = _quiet(inspect, env=lab.env, timeout=20, allow_failure=True)
                cleanup_failed = cleanup_failed or remaining.returncode == 0
            except RuntimeError:
                cleanup_failed = True
        shutil.rmtree(tmp, ignore_errors=True)
        if cleanup_failed:
            lab.block("Owned private-pull registry or network cleanup did not complete")


EMBED_NAMESPACE_LABEL = "saf.example.org/0601-022-literal-auth-fixture"
EMBED_POLICY = "fixture-literal-registry-auth-deny"
EMBED_DENIAL = "literal registry-auth marker values are not permitted in Pod environment fields"
EMBED_MARKER = "PUBLIC_SYNTHETIC_FIXTURE_MARKER_ONLY"


def _embedded_auth_pod(name, *, inline_marker):
    env = ([{"name": "REGISTRY_AUTH", "value": EMBED_MARKER}]
           if inline_marker else [])
    request = pod(name, [container("probe", command=["true"], env=env)],
                  serviceAccountName=ACCOUNT, automountServiceAccountToken=False)
    request["metadata"].update({
        "namespace": "saf-test",
        "labels": {"saf.example.org/case": "0601-022-literal-auth"},
    })
    if not inline_marker:
        request["spec"]["imagePullSecrets"] = [{"name": SECRET}]
    return request


def _literal_auth_vap(lab):
    expression = (
        "object.spec.containers.all(c, !has(c.env) || c.env.all(e, "
        "!(e.name == 'REGISTRY_AUTH' && has(e.value) && e.value != ''))) && "
        "(!has(object.spec.initContainers) || object.spec.initContainers.all(c, "
        "!has(c.env) || c.env.all(e, !(e.name == 'REGISTRY_AUTH' && "
        "has(e.value) && e.value != ''))))"
    )
    policy = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": EMBED_POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                   "operations": ["CREATE", "UPDATE"],
                                   "resources": ["pods"]}],
            },
            "validations": [{"expression": expression, "message": EMBED_DENIAL}],
        },
    }
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": EMBED_POLICY},
        "spec": {
            "policyName": EMBED_POLICY,
            "validationActions": ["Deny"],
            "matchResources": {"namespaceSelector": {
                "matchLabels": {EMBED_NAMESPACE_LABEL: "true"}}},
        },
    }
    lab.create(policy)
    lab.create(binding)


def run_literal_auth_vap(lab):
    # This is a namespace-local reference case. The marker is public inert text,
    # never a credential; only server-side dry-run Pods are submitted here.
    lab.kubectl("label", "namespace", "saf-test",
                 f"{EMBED_NAMESPACE_LABEL}=true", "--overwrite")
    inline = _embedded_auth_pod("literal-auth-marker", inline_marker=True)
    reference = _embedded_auth_pod("name-only-auth-reference", inline_marker=False)
    baseline_inline = lab.create(inline, dry_run=True, allow_failure=True)
    baseline_reference = lab.create(reference, dry_run=True, allow_failure=True)
    baseline_ok = baseline_inline.returncode == 0 and baseline_reference.returncode == 0
    lab.check("positive", "Before the fixture policy, the marker example and name-only pull reference are accepted",
              baseline_ok,
              {"marker_example_accepted": baseline_inline.returncode == 0,
               "name_only_reference_accepted": baseline_reference.returncode == 0,
               "scope": "fixed public marker; server-side dry-run only"})

    _literal_auth_vap(lab)
    deadline = time.monotonic() + 25
    while True:
        denied = lab.create(inline, dry_run=True, allow_failure=True)
        denied_as_expected = denied.returncode != 0 and EMBED_DENIAL in denied.stderr
        if denied_as_expected or time.monotonic() >= deadline:
            break
        time.sleep(0.4)
    accepted = lab.create(reference, dry_run=True, allow_failure=True)
    reference_remains_accepted = accepted.returncode == 0
    persisted = lab.kubectl("get", "pod", inline["metadata"]["name"], reference["metadata"]["name"],
                            "--ignore-not-found", "-o", "name").stdout.strip()
    no_dry_run_pods = not persisted
    lab.check("green", "The scoped VAP rejects the literal registry-auth marker in a Pod env value",
              denied_as_expected and no_dry_run_pods,
              {"expected_denial": denied_as_expected,
               "neither_dry_run_pod_persisted": no_dry_run_pods,
               "scope": "REGISTRY_AUTH env value; fixture namespace; server-side dry-run"})
    lab.check("positive", "A name-only imagePullSecrets reference remains admissible under the VAP",
              reference_remains_accepted and no_dry_run_pods,
              {"name_only_reference_accepted": reference_remains_accepted,
               "neither_dry_run_pod_persisted": no_dry_run_pods,
               "scope": "existing case-owned empty pull Secret name; server-side dry-run"})

def run(lab):
    evaluate_examples(lab)
    lab.kubectl("create", "serviceaccount", ACCOUNT)
    body = pod("fixture-pull-reference", [container("public-probe", command=["true"])],
               serviceAccountName=ACCOUNT, automountServiceAccountToken=False)
    baseline = lab.create(body, dry_run=True)["spec"]
    lab.check("red", "The Pod has no injected pull reference before linking the ServiceAccount",
              not baseline.get("imagePullSecrets"), {"pull_references": baseline.get("imagePullSecrets", [])})

    create_empty_pull_secret(lab)
    patch = json.dumps({"imagePullSecrets": [{"name": SECRET}]})
    lab.kubectl("patch", "serviceaccount", ACCOUNT, "--type=merge", "-p", patch)
    deadline = time.monotonic() + 20
    expected = [{"name": SECRET}]
    observed = []
    while time.monotonic() < deadline:
        observed = lab.create(body, dry_run=True)["spec"].get("imagePullSecrets", [])
        if observed == expected:
            break
        time.sleep(0.5)
    lab.check("green", "Kubernetes admission injects the exact same-namespace Secret name",
              observed == expected, {"pull_references": observed})

    admitted = lab.create(body)
    lab.kubectl("wait", "pod/fixture-pull-reference", "--for=jsonpath={.status.phase}=Succeeded",
                "--timeout=75s", timeout=85)
    references = admitted["spec"].get("imagePullSecrets", [])
    lab.check("positive", "The live public-image Pod carries only the expected name reference",
              references == expected, {"pull_references": references, "workload_succeeded": True})
    run_private_pull_checks(lab)
    run_literal_auth_vap(lab)
