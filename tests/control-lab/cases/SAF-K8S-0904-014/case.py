"""Stage-scoped artifact access and lifecycle configuration on SeaweedFS 4.53."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
NAMESPACE = "saf-test"
STORE = "artifact-store"
CLIENT = "artifact-client"
STORE_IMAGE = "docker.io/chrislusf/seaweedfs:4.53@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0"
CLIENT_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
BUCKETS = {"a": "saf0904014-stage-a", "b": "saf0904014-stage-b"}
CONFIGMAP = "artifact-store-fixtures"
FED_CONFIGMAP = "federated-identity-fixtures"
JWKS_FIXTURE_MAP = "oidc-jwks-snapshot-fixtures"
JWKS_SNAPSHOT = "oidc-jwks-snapshot"
FED_IAM_CONFIG = None
FED_ISSUER = None
FED_JWKS_URI = None
FED_DISCOVERY = None
FED_SNAPSHOT_CA = None
FED_AUDIENCE = "saf-0904-014-seaweed-s3"

SCOPE = (
    "One fresh Kind v1.36.1 cluster runs the digest-pinned SeaweedFS 4.53 mini S3 backend "
    "with emptyDir data and a standard-library SigV4 client. Two static stage identities "
    "first have broad Read/Write access to both stage buckets, then the mounted static IAM "
    "config changes only their action scopes and the same SeaweedFS container process restarts "
    "inside the same Pod. The case checks unchanged credentials, Pod UID, Service ClusterIP, "
    "image and S3 marker hashes, then verifies cross-bucket denies, own-stage reads/writes, and "
    "stage-specific lifecycle config readback. An additive phase uses native Kubernetes TokenRequest "
    "projected ServiceAccount tokens with the disposable API server's discovered OIDC issuer/JWKS, "
    "SeaweedFS STS and synthetic bucket-scoped roles; its short configured-default STS credentials "
    "are checked before and after actual elapsed expiry. No production controller/provider behavior "
    "is claimed. The case does not establish production storage, encryption, or backing-byte reclamation."
)


def read_fixture(name):
    return (FIXTURES / name).read_text()


def pod_security(user, group, *, read_only=False):
    result = {"allowPrivilegeEscalation": False,
              "capabilities": {"drop": ["ALL"]},
              "runAsNonRoot": True,
              "runAsUser": user,
              "runAsGroup": group,
              "seccompProfile": {"type": "RuntimeDefault"}}
    if read_only:
        result["readOnlyRootFilesystem"] = True
    return result


def config_map_object(config_text, iam_config=None):
    data = {
        "s3-config.json": config_text,
        "stage-a-marker.txt": read_fixture("stage-a-marker.txt"),
        "stage-b-marker.txt": read_fixture("stage-b-marker.txt"),
        "stage-a-lifecycle.xml": read_fixture("stage-a-lifecycle.xml"),
        "stage-b-lifecycle.xml": read_fixture("stage-b-lifecycle.xml"),
        "s3_probe.py": read_fixture("s3_probe.py"),
    }
    if iam_config is None:
        iam_config = FED_IAM_CONFIG
    if iam_config is not None:
        data["iam-config.json"] = json.dumps(iam_config, sort_keys=True)
    if FED_SNAPSHOT_CA is not None:
        data["snapshot-ca.crt"] = FED_SNAPSHOT_CA
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIGMAP, "namespace": NAMESPACE},
        "data": data,
    }


def projected_token_pod(name, service_account, audience=FED_AUDIENCE):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "labels": {"app": "artifact-federated-client"}},
        "spec": {
            "serviceAccountName": service_account,
            "automountServiceAccountToken": False,
            "restartPolicy": "Always",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534},
            "containers": [{
                "name": "client", "image": CLIENT_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", "import time; time.sleep(3600)"],
                "securityContext": pod_security(65534, 65534, read_only=True),
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "200m", "memory": "128Mi"}},
                "volumeMounts": [
                    {"name": "fixtures", "mountPath": "/fixture", "readOnly": True},
                    {"name": "workload-token", "mountPath": "/var/run/oidc", "readOnly": True},
                ],
            }],
            "volumes": [
                    {"name": "fixtures", "configMap": {"name": FED_CONFIGMAP}},
                {"name": "workload-token", "projected": {"sources": [{
                    "serviceAccountToken": {"path": "token", "audience": audience,
                                             "expirationSeconds": 600}}]}},
            ],
        },
    }


def oidc_iam_config(issuer, jwks_uri):
    def role(stage):
        bucket = BUCKETS[stage]
        sa = f"system:serviceaccount:{NAMESPACE}:stage-{stage}"
        name = f"stage-{stage}-federated"
        return {
            "roleName": name,
            "roleArn": f"arn:aws:iam::role/{name}",
            "attachedPolicies": [f"{name}-policy"],
            "trustPolicy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow", "Principal": {"Federated": "*"},
                    "Action": ["sts:AssumeRoleWithWebIdentity"],
                    "Condition": {"StringEquals": {
                        "oidc:iss": issuer, "oidc:sub": sa,
                    }},
                }],
            },
        }

    def policy(stage):
        bucket = BUCKETS[stage]
        name = f"stage-{stage}-federated"
        return {
            "name": f"{name}-policy",
            "document": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": [f"arn:aws:s3:::{bucket}/*"],
                }],
            },
        }

    return {
        "sts": {"tokenDuration": "30s", "maxSessionLength": "35s",
                "issuer": "saf-0904-014-local-sts"},
        "providers": [{
            "name": "kind-service-accounts", "type": "oidc", "enabled": True,
            "config": {"issuer": issuer, "clientId": FED_AUDIENCE,
                       "jwksUri": jwks_uri, "tlsCaCert": "/fixture/snapshot-ca.crt",
                       "tlsInsecureSkipVerify": False,
                       "jtiReplayProtectionEnabled": True},
        }],
        "policies": [policy("a"), policy("b")],
        "roles": [role("a"), role("b")],
    }


def identity_fixture_map():
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": FED_CONFIGMAP, "namespace": NAMESPACE},
        "data": {
            "identity_probe.py": read_fixture("identity_probe.py"),
            "stage-a-marker.txt": read_fixture("stage-a-marker.txt"),
            "stage-b-marker.txt": read_fixture("stage-b-marker.txt"),
            "snapshot-ca.crt": FED_SNAPSHOT_CA,
        },
    }


def discover_cluster_oidc(lab):
    """Read public API discovery through the runner's owned-cluster context."""
    discovery_result = lab.kubectl("get", "--raw", "/.well-known/openid-configuration",
                                   allow_failure=True)
    if discovery_result.returncode:
        lab.block("Owned Kubernetes API does not expose OIDC discovery")
    try:
        discovery = json.loads(discovery_result.stdout)
    except json.JSONDecodeError:
        lab.block("Owned Kubernetes OIDC discovery did not return JSON")
    issuer = discovery.get("issuer", "")
    api_jwks_uri = discovery.get("jwks_uri", "")
    issuer_url, jwks_url = urlsplit(issuer), urlsplit(api_jwks_uri)
    if (issuer_url.scheme != "https" or not issuer_url.hostname
            or api_jwks_uri != "https://kubernetes.default.svc/openid/v1/jwks"
            or jwks_url.scheme != "https" or jwks_url.path != "/openid/v1/jwks"
            or jwks_url.query or jwks_url.fragment):
        lab.block("Owned API discovery does not expose an HTTPS issuer and expected Kubernetes JWKS path")
    return issuer, discovery, "https://oidc-jwks-snapshot.saf-test.svc:8443/openid/v1/jwks"


def deploy_identity_clients(lab):
    if FED_IAM_CONFIG is None or FED_ISSUER is None or FED_JWKS_URI is None:
        lab.block("Federated identity config was not prepared before store creation")
    for name in ("stage-a", "stage-b", "outsider"):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                    "metadata": {"name": name, "namespace": NAMESPACE},
                    "automountServiceAccountToken": False})
    # A separate fresh TokenRequest-backed Pod is used for each comparison, so
    # the provider's single-use JWT replay protection stays enabled.
    clients = {
        "federated-stage-a": ("stage-a", FED_AUDIENCE),
        "federated-stage-b": ("stage-b", FED_AUDIENCE),
        "federated-a-cross": ("stage-a", FED_AUDIENCE),
        "federated-expiry": ("stage-a", FED_AUDIENCE),
        "federated-wrong-aud": ("stage-a", FED_AUDIENCE + "-wrong"),
        "federated-outsider": ("outsider", FED_AUDIENCE),
    }
    for name, (service_account, audience) in clients.items():
        lab.create(projected_token_pod(name, service_account, audience))
    for name in clients:
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=80s", timeout=90)
    return None


def deploy_oidc_snapshot(lab):
    """Use a bounded case-owned reader to relay only exact public API metadata."""
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": "oidc-jwks-reader", "namespace": NAMESPACE},
                "automountServiceAccountToken": False})
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": JWKS_FIXTURE_MAP, "namespace": NAMESPACE},
        "data": {
            "snapshot_from_apiserver.py": read_fixture("snapshot_from_apiserver.py"),
            "serve_jwks_snapshot.py": read_fixture("serve_jwks_snapshot.py"),
        },
    })
    lab.create({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": JWKS_SNAPSHOT},
        "spec": {"selector": {"app": JWKS_SNAPSHOT},
                 "ports": [{"name": "https", "port": 8443, "targetPort": 8443}]},
    })
    lab.create({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": JWKS_SNAPSHOT, "labels": {"app": JWKS_SNAPSHOT}},
        "spec": {
            "serviceAccountName": "oidc-jwks-reader",
            "automountServiceAccountToken": False,
            "restartPolicy": "Always",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534, "fsGroup": 65534},
            "initContainers": [{
                "name": "authenticated-api-snapshot",
                "image": CLIENT_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "/fixture/snapshot_from_apiserver.py"],
                "env": [{"name": "EXPECTED_ISSUER", "value": FED_ISSUER}],
                "securityContext": pod_security(65534, 65534, read_only=True),
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "200m", "memory": "128Mi"}},
                "volumeMounts": [
                    {"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                    {"name": "api-token", "mountPath": "/var/run/kubernetes", "readOnly": True},
                    {"name": "api-ca", "mountPath": "/var/run/kubernetes-ca", "readOnly": True},
                    {"name": "snapshot", "mountPath": "/snapshot"},
                ],
            }],
            "containers": [{
                "name": "https-snapshot",
                "image": CLIENT_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "/fixture/serve_jwks_snapshot.py"],
                "securityContext": pod_security(65534, 65534, read_only=True),
                "ports": [{"name": "https", "containerPort": 8443}],
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "200m", "memory": "128Mi"}},
                "readinessProbe": {"tcpSocket": {"port": 8443}, "periodSeconds": 2,
                                   "timeoutSeconds": 1, "failureThreshold": 20},
                "volumeMounts": [
                    {"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                    {"name": "tls", "mountPath": "/tls", "readOnly": True},
                    {"name": "snapshot", "mountPath": "/snapshot", "readOnly": True},
                ],
            }],
            "volumes": [
                {"name": "fixture", "configMap": {"name": JWKS_FIXTURE_MAP}},
                {"name": "tls", "secret": {"secretName": "oidc-jwks-snapshot-tls"}},
                {"name": "api-token", "projected": {"sources": [{
                    "serviceAccountToken": {"path": "token", "expirationSeconds": 600}}]}},
                {"name": "api-ca", "configMap": {"name": "kube-root-ca.crt",
                                                       "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                {"name": "snapshot", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}},
            ],
        },
    })
    ready = lab.kubectl("wait", "--for=condition=Ready", f"pod/{JWKS_SNAPSHOT}",
                        "--timeout=70s", timeout=80, allow_failure=True)
    if ready.returncode:
        lab.kubectl("logs", f"pod/{JWKS_SNAPSHOT}", "-c", "authenticated-api-snapshot",
                    "--tail=3", allow_failure=True)
        lab.kubectl("logs", f"pod/{JWKS_SNAPSHOT}", "-c", "https-snapshot",
                    "--tail=3", allow_failure=True)
        lab.kubectl("get", f"pod/{JWKS_SNAPSHOT}", "-o",
                    "jsonpath={.status.initContainerStatuses[0].state}:{.status.containerStatuses[0].state}",
                    allow_failure=True)
        lab.block("Case-owned public key snapshot did not become ready; fixed diagnostics retained")


def create_ephemeral_snapshot_tls(lab):
    """Create per-run HTTPS credentials privately; retain only the public CA."""
    with tempfile.TemporaryDirectory(prefix="saf-0904-014-jwks-") as temporary:
        directory = Path(temporary)
        ca_config = directory / "ca.cnf"
        server_config = directory / "server.cnf"
        ca_config.write_text("""[req]
distinguished_name=dn
x509_extensions=ca_ext
prompt=no
[dn]
CN=SAF-0904-014 ephemeral JWKS CA
[ca_ext]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
""")
        server_config.write_text("""[req]
distinguished_name=dn
req_extensions=request_ext
prompt=no
[dn]
CN=oidc-jwks-snapshot.saf-test.svc
[request_ext]
subjectAltName=DNS:oidc-jwks-snapshot.saf-test.svc
[server_ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:oidc-jwks-snapshot.saf-test.svc
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
""")
        ca_key = directory / "ca.key"
        ca_cert = directory / "ca.crt"
        server_key = directory / "server.key"
        server_csr = directory / "server.csr"
        server_cert = directory / "server.crt"
        lab.command("openssl", "genrsa", "-out", str(ca_key), "2048")
        os.chmod(ca_key, 0o600)
        lab.command("openssl", "req", "-x509", "-new", "-key", str(ca_key),
                    "-sha256", "-days", "2", "-config", str(ca_config),
                    "-out", str(ca_cert))
        lab.command("openssl", "genrsa", "-out", str(server_key), "2048")
        os.chmod(server_key, 0o600)
        lab.command("openssl", "req", "-new", "-key", str(server_key),
                    "-config", str(server_config), "-out", str(server_csr))
        lab.command("openssl", "x509", "-req", "-in", str(server_csr),
                    "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
                    "-days", "2", "-sha256", "-extfile", str(server_config),
                    "-extensions", "server_ext", "-out", str(server_cert))
        lab.command("openssl", "verify", "-x509_strict", "-purpose", "sslserver",
                    "-CAfile", str(ca_cert), str(server_cert))
        tls_ca = ca_cert.read_text()
        lab.kubectl("create", "secret", "generic", "oidc-jwks-snapshot-tls",
                    f"--from-file=ca.crt={ca_cert}",
                    f"--from-file=server.crt={server_cert}",
                    f"--from-file=server.key={server_key}")
        return tls_ca


def identity_probe(lab, pod, operation, *arguments):
    result = lab.kubectl("exec", f"pod/{pod}", "--", "python", "-B",
                         "/fixture/identity_probe.py", operation, *arguments,
                         timeout=65 if operation == "positive-expiry" else 40,
                         allow_failure=True)
    if result.returncode:
        lab.block(f"Federated S3 probe did not complete ({operation}); see sanitized case process status")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"Federated S3 probe returned no sanitized JSON result: {error}")
    expected_operation = ("positive" if operation in ("positive-a", "positive-b")
                          else "deny" if operation.startswith("deny-") else operation)
    if value.get("operation") != expected_operation:
        lab.block(f"Federated S3 probe returned an unexpected operation result: {value}")
    return value


def deploy(lab):
    global FED_IAM_CONFIG, FED_ISSUER, FED_JWKS_URI, FED_DISCOVERY, FED_SNAPSHOT_CA
    broad_config = read_fixture("s3-config-broad.json")
    FED_ISSUER, FED_DISCOVERY, FED_JWKS_URI = discover_cluster_oidc(lab)
    FED_SNAPSHOT_CA = create_ephemeral_snapshot_tls(lab)
    FED_IAM_CONFIG = oidc_iam_config(FED_ISSUER, FED_JWKS_URI)
    lab.create(config_map_object(broad_config, FED_IAM_CONFIG))
    lab.create(identity_fixture_map())
    deploy_oidc_snapshot(lab)
    lab.create({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": STORE, "labels": {"app": STORE}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Always",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                "runAsGroup": 1000, "fsGroup": 1000},
            "containers": [{
                "name": "seaweedfs", "image": STORE_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["weed", "mini", "-s3.config=/fixture/s3-config.json",
                            "-s3.iam.config=/fixture/iam-config.json", "-dir=/data",
                            "-webdav=false", "-admin.ui=false", "-master.telemetry=false"],
                "securityContext": pod_security(1000, 1000),
                "ports": [{"name": "s3", "containerPort": 8333}],
                "resources": {"requests": {"cpu": "250m", "memory": "512Mi"},
                              "limits": {"cpu": "1500m", "memory": "1536Mi"}},
                "readinessProbe": {"tcpSocket": {"port": 8333}, "periodSeconds": 2,
                                   "timeoutSeconds": 1, "failureThreshold": 45},
                "volumeMounts": [
                    {"name": "fixtures", "mountPath": "/fixture", "readOnly": True},
                    {"name": "data", "mountPath": "/data"},
                ],
            }],
            "volumes": [
                {"name": "fixtures", "configMap": {"name": CONFIGMAP}},
                {"name": "data", "emptyDir": {"sizeLimit": "512Mi"}},
            ],
        },
    })
    lab.create({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": STORE},
        "spec": {"selector": {"app": STORE},
                 "ports": [{"name": "s3", "port": 8333, "targetPort": 8333}]},
    })
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{STORE}", "--timeout=150s", timeout=160)
    lab.create({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": CLIENT, "labels": {"app": CLIENT}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Always",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534},
            "containers": [{
                "name": "client", "image": CLIENT_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", "import time; time.sleep(3600)"],
                "securityContext": pod_security(65534, 65534, read_only=True),
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "200m", "memory": "128Mi"}},
                "volumeMounts": [{"name": "fixtures", "mountPath": "/fixture", "readOnly": True}],
            }],
            "volumes": [{"name": "fixtures", "configMap": {"name": CONFIGMAP}}],
        },
    })
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{CLIENT}", "--timeout=80s", timeout=90)
    deploy_identity_clients(lab)
    assert_owned_s3_endpoint(lab)
    store = pod_json(lab, STORE)
    if store.get("spec", {}).get("containers", [{}])[0].get("image") != STORE_IMAGE:
        lab.block("SeaweedFS Pod image does not match the exact approved digest")
    if not any(v.get("name") == "data" and "emptyDir" in v for v in store["spec"].get("volumes", [])):
        lab.block("SeaweedFS fixture must use the case-owned emptyDir backing")


def pod_json(lab, name):
    return json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)


def assert_owned_s3_endpoint(lab):
    svc = json.loads(lab.kubectl("get", "service", STORE, "-o", "json").stdout)
    endpoints = json.loads(lab.kubectl(
        "get", "endpointslice", "-l", f"kubernetes.io/service-name={STORE}", "-o", "json").stdout)["items"]
    ready = [ep for row in endpoints for ep in (row.get("endpoints") or [])
             if ep.get("conditions", {}).get("ready") is True]
    if (not svc.get("spec", {}).get("clusterIP") or len(ready) != 1
            or ready[0].get("targetRef", {}).get("name") != STORE):
        lab.block("S3 Service does not resolve to exactly the Ready case-owned SeaweedFS Pod")


def probe(lab, operation):
    timeout = 100 if operation == "scoped" else 40
    result = lab.kubectl("exec", f"pod/{CLIENT}", "--", "python", "-B",
                         "/fixture/s3_probe.py", operation, timeout=timeout, allow_failure=True)
    if result.returncode:
        lab.block(f"S3 fixture probe {operation} failed to execute: {result.stderr.strip()}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"S3 fixture emitted no structured result for {operation}: {error}")
    if value.get("operation") != operation:
        lab.block(f"S3 fixture returned an unexpected operation result: {value}")
    return value


def credential_map(config):
    return {row["name"]: tuple((c["accessKey"], c["secretKey"]) for c in row.get("credentials", []))
            for row in config["identities"]}


def config_without_actions(config):
    return [{k: v for k, v in row.items() if k != "actions"} for row in config["identities"]]


def await_projected_config(lab, expected_sha, timeout=60):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        observed = probe(lab, "config-hash").get("sha256")
        store_mount = lab.kubectl("exec", f"pod/{STORE}", "--", "cat",
                                  "/fixture/s3-config.json")
        backend_sha = hashlib.sha256(store_mount.stdout.encode()).hexdigest()
        if observed == expected_sha == backend_sha:
            return observed
        last = f"client={observed}; backend={backend_sha}"
        time.sleep(0.5)
    lab.block(f"Scoped config did not propagate to the fixture volume; observed sha256={last}")


def await_same_pod_restart(lab, original_pod, service_ip, timeout=150):
    old_count = original_pod["status"]["containerStatuses"][0]["restartCount"]
    old_uid = original_pod["metadata"]["uid"]
    deadline = time.monotonic() + timeout
    last = "restart pending"
    while time.monotonic() < deadline:
        pod = pod_json(lab, STORE)
        status = pod.get("status", {})
        containers = status.get("containerStatuses", [])
        count = containers[0].get("restartCount", -1) if containers else -1
        ready = bool(containers and containers[0].get("ready"))
        last = f"uid-same={pod.get('metadata', {}).get('uid') == old_uid}; restartCount={count}; ready={ready}"
        if count == old_count + 1 and ready and pod.get("metadata", {}).get("uid") == old_uid:
            current_service = json.loads(lab.kubectl("get", "service", STORE, "-o", "json").stdout)
            current_ip = current_service.get("spec", {}).get("clusterIP")
            image = pod.get("spec", {}).get("containers", [{}])[0].get("image")
            if current_ip != service_ip or image != STORE_IMAGE:
                lab.block(f"Endpoint or backend image changed during scoped config reload: {last}")
            return pod, last
        if count > old_count + 1:
            lab.block(f"SeaweedFS container restarted more than once during config transition: {last}")
        time.sleep(0.5)
    lab.block(f"SeaweedFS did not restart exactly once in the same Pod: {last}")


def run(lab):
    broad = json.loads(read_fixture("s3-config-broad.json"))
    scoped = json.loads(read_fixture("s3-config-scoped.json"))
    if credential_map(broad) != credential_map(scoped):
        lab.block("Broad and scoped policy fixtures changed identity credentials")
    if config_without_actions(broad) != config_without_actions(scoped):
        lab.block("Broad and scoped config differs outside the identity action grants")

    deploy(lab)
    seeded = probe(lab, "seed")
    expected_hashes = {
        BUCKETS["a"]: hashlib.sha256(read_fixture("stage-a-marker.txt").encode()).hexdigest(),
        BUCKETS["b"]: hashlib.sha256(read_fixture("stage-b-marker.txt").encode()).hexdigest(),
    }
    lab.check("red", "Fresh store creates both stage buckets and round-trips both fixed artifact markers",
              seeded.get("buckets_created") == {BUCKETS["a"]: 200, BUCKETS["b"]: 200}
              and seeded.get("markers_seeded") == {BUCKETS["a"]: 200, BUCKETS["b"]: 200}
              and seeded.get("marker_sha256") == expected_hashes, seeded)

    broad_result = probe(lab, "broad")
    broad_ok = True
    for identity in ("stage-a", "stage-b"):
        row = broad_result.get("identities", {}).get(identity, {})
        broad_ok = broad_ok and row.get("gets") == {
            BUCKETS["a"]: {"status": 200, "sha256": expected_hashes[BUCKETS["a"]]},
            BUCKETS["b"]: {"status": 200, "sha256": expected_hashes[BUCKETS["b"]]},
        } and row.get("cross_put_status") == 200
    lab.check("red", "Under broad fixture IAM, both stage identities read both stage artifacts and write across stage buckets",
              broad_ok, broad_result)

    service_before = json.loads(lab.kubectl("get", "service", STORE, "-o", "json").stdout)
    service_ip = service_before["spec"]["clusterIP"]
    pod_before = pod_json(lab, STORE)
    configmap = config_map_object(read_fixture("s3-config-scoped.json"))
    lab.kubectl("apply", "-f", "-", payload=json.dumps(configmap))
    scoped_config_sha = hashlib.sha256(read_fixture("s3-config-scoped.json").encode()).hexdigest()
    for pod in (STORE, CLIENT):
        lab.kubectl("annotate", "pod", pod, f"saf.example.test/config-revision={scoped_config_sha}", "--overwrite")
    projected = await_projected_config(lab, scoped_config_sha, timeout=110)
    lab.check("green", "Same mounted config contains the scoped policy snapshot before process restart",
              projected == scoped_config_sha, {"sha256": projected})

    # Restart the same process/container inside the same Pod so the static S3 config is reread.
    # The emptyDir and service remain tied to the same Pod; no replacement backend is introduced.
    lab.kubectl("exec", f"pod/{STORE}", "--", "/bin/sh", "-c", "kill -TERM 1",
                allow_failure=True, timeout=15)
    pod_after, restart_observation = await_same_pod_restart(lab, pod_before, service_ip)
    assert_owned_s3_endpoint(lab)

    post_restart_data = probe(lab, "verify-admin-data").get("markers", {})
    data_preserved = post_restart_data == {
        BUCKETS["a"]: {"status": 200, "sha256": expected_hashes[BUCKETS["a"]]},
        BUCKETS["b"]: {"status": 200, "sha256": expected_hashes[BUCKETS["b"]]},
    }
    lab.check("positive", "Policy reload preserved static credentials, SeaweedFS image, Pod, Service endpoint, and seeded S3 data",
              credential_map(broad) == credential_map(scoped)
              and config_without_actions(broad) == config_without_actions(scoped)
              and pod_after.get("metadata", {}).get("uid") == pod_before.get("metadata", {}).get("uid")
              and pod_after.get("spec", {}).get("containers", [{}])[0].get("image") == STORE_IMAGE
              and service_ip == service_before["spec"].get("clusterIP")
              and data_preserved,
              {"same_pod_restarted_once": True, "service_endpoint_unchanged": True,
               "marker_readback": post_restart_data})
    (lab.evidence / "stage-policy-restart.raw.json").write_text(json.dumps({
        "container_restart": restart_observation, "before_pod_uid": pod_before["metadata"]["uid"],
        "after_pod_uid": pod_after["metadata"]["uid"], "service_cluster_ip": service_ip,
        "stage_marker_readback": post_restart_data, "scoped_config_sha256": projected,
    }, indent=2, sort_keys=True) + "\n")

    scoped_result = probe(lab, "scoped")
    scoped_ok = True
    for stage in ("a", "b"):
        row = scoped_result.get("identities", {}).get("stage-" + stage, {})
        own_bucket = BUCKETS[stage]
        other_bucket, other_key, other_payload = {
            "a": (BUCKETS["b"], "artifacts/stage-b/from-stage-a.txt",
                  b"SAF-K8S-0904-014 inert cross-stage write by A v1\n"),
            "b": (BUCKETS["a"], "artifacts/stage-a/from-stage-b.txt",
                  b"SAF-K8S-0904-014 inert cross-stage write by B v1\n"),
        }[stage]
        allowed_payload = {
            "a": b"SAF-K8S-0904-014 allowed stage-a write v1\n",
            "b": b"SAF-K8S-0904-014 allowed stage-b write v1\n",
        }[stage]
        scoped_ok = scoped_ok and row.get("own_get_status") == 200
        scoped_ok = scoped_ok and row.get("own_get_sha256") == expected_hashes[own_bucket]
        scoped_ok = scoped_ok and row.get("cross_get_status") == 403
        scoped_ok = scoped_ok and row.get("cross_put_status") == 403
        scoped_ok = scoped_ok and row.get("cross_put_preserved_status") == 200
        scoped_ok = scoped_ok and row.get("cross_put_preserved_sha256") == hashlib.sha256(other_payload).hexdigest()
        scoped_ok = scoped_ok and row.get("allowed_put_status") == 200
        scoped_ok = scoped_ok and row.get("allowed_readback_status") == 200
        scoped_ok = scoped_ok and row.get("allowed_readback_sha256") == hashlib.sha256(allowed_payload).hexdigest()
        scoped_ok = scoped_ok and row.get("cross_put_target") == f"{other_bucket}/{other_key}"
    lab.check("green", "Same stage credentials now receive S3 403 for the exact cross-stage reads and writes",
              scoped_ok, {"identities": scoped_result.get("identities")})
    lab.check("positive", "Each scoped stage still reads its own artifact and writes/readbacks an own-stage marker",
              scoped_ok, {"identities": scoped_result.get("identities")})

    lifecycle = scoped_result.get("lifecycle", [])
    lifecycle_ok = len(lifecycle) == 2 and all(
        item.get("put_status") in (200, 204) and item.get("get_status") == 200
        and item.get("matches") is True for item in lifecycle)
    lab.check("positive", "SeaweedFS stores and reads back distinct stage-bucket lifecycle rules",
              lifecycle_ok, lifecycle)

    # Native Kubernetes TokenRequest projection feeds SeaweedFS 4.53 STS. The
    # probe prints only fixed statuses/digests/booleans; bearer and session
    # values remain in Pod memory and never enter kubectl output or evidence.
    token_a = identity_probe(lab, "federated-stage-a", "inspect",
                             "system:serviceaccount:saf-test:stage-a", FED_AUDIENCE, FED_ISSUER)
    token_b = identity_probe(lab, "federated-stage-b", "inspect",
                             "system:serviceaccount:saf-test:stage-b", FED_AUDIENCE, FED_ISSUER)
    token_a_pod = pod_json(lab, "federated-stage-a")
    token_b_pod = pod_json(lab, "federated-stage-b")

    def projected_spec_matches(pod, service_account):
        spec = pod.get("spec", {})
        token_sources = [source.get("serviceAccountToken", {})
                         for volume in spec.get("volumes", [])
                         for source in volume.get("projected", {}).get("sources", [])]
        return (spec.get("serviceAccountName") == service_account
                and spec.get("automountServiceAccountToken") is False
                and token_sources == [{"path": "token", "audience": FED_AUDIENCE,
                                      "expirationSeconds": 600}]
                and any(volume.get("name") == "fixtures"
                        and volume.get("configMap", {}).get("name") == FED_CONFIGMAP
                        for volume in spec.get("volumes", [])))

    projected_identities_ok = all(
        row.get("subject_matches") and row.get("audience_matches")
        and row.get("issuer_matches") and row.get("expiration_window_matches")
        and row.get("snapshot_tls_verified") and row.get("snapshot_issuer_matches")
        and row.get("snapshot_discovery_path_matches")
        and row.get("snapshot_jwks_digest_matches")
        and row.get("snapshot_public_keys_only")
        for row in (token_a, token_b))
    projected_identities_ok = (projected_identities_ok
                               and projected_spec_matches(token_a_pod, "stage-a")
                               and projected_spec_matches(token_b_pod, "stage-b"))
    lab.check("positive", "Kubernetes projects distinct stage ServiceAccount tokens with the exact issuer and audience",
              projected_identities_ok,
              {"stage_a": token_a, "stage_b": token_b,
               "issuer_configured": FED_ISSUER,
               "jwks_discovery_configured": FED_JWKS_URI,
               "service_accounts_case_owned": True,
               "projected_token_ttl_seconds": 600})

    federated_a = identity_probe(lab, "federated-stage-a", "positive-a")
    stage_a_ok = (federated_a.get("sts_status") == 200
                  and federated_a.get("subject_matches") is True
                  and federated_a.get("token_claims_match") is True
                  and federated_a.get("get_digest_matches") is True
                  and federated_a.get("write_digest_matches") is True
                  and federated_a.get("short_session_window") is True)
    lab.check("positive", "Stage-A Kubernetes identity obtains short-lived STS credentials for only its fixed bucket marker",
              stage_a_ok, federated_a)

    federated_b = identity_probe(lab, "federated-stage-b", "positive-b")
    stage_b_ok = (federated_b.get("sts_status") == 200
                  and federated_b.get("subject_matches") is True
                  and federated_b.get("token_claims_match") is True
                  and federated_b.get("get_digest_matches") is True
                  and federated_b.get("write_digest_matches") is True
                  and federated_b.get("short_session_window") is True)
    lab.check("positive", "Stage-B Kubernetes identity obtains short-lived STS credentials for only its fixed bucket marker",
              stage_b_ok, federated_b)

    cross_role = identity_probe(lab, "federated-a-cross", "deny-stage-b-role")
    lab.check("green", "Stage-A ServiceAccount token cannot assume the stage-B SeaweedFS role",
              cross_role.get("denied") is True and cross_role.get("no_session_issued") is True,
              cross_role)

    wrong_audience = identity_probe(lab, "federated-wrong-aud", "deny-stage-a-role")
    lab.check("green", "SeaweedFS STS refuses the otherwise valid ServiceAccount token with the wrong audience",
              wrong_audience.get("denied") is True and wrong_audience.get("no_session_issued") is True,
              wrong_audience)

    wrong_subject = identity_probe(lab, "federated-outsider", "deny-stage-a-role")
    lab.check("green", "SeaweedFS trust policy refuses an unapproved ServiceAccount subject",
              wrong_subject.get("denied") is True and wrong_subject.get("no_session_issued") is True,
              wrong_subject)

    expiry_probe = identity_probe(lab, "federated-expiry", "positive-expiry")
    expiry_before_ok = (expiry_probe.get("sts_status") == 200
                        and expiry_probe.get("before_expiry_status") == 200
                        and expiry_probe.get("short_session_window") is True)
    lab.check("positive", "The same STS session remains usable before its returned expiry",
              expiry_before_ok,
              {key: expiry_probe.get(key) for key in (
                  "sts_status", "before_expiry_status", "short_session_window")})
    lab.check("green", "SeaweedFS refuses the same STS credentials after real elapsed expiry",
              expiry_probe.get("expired_denied") is True,
              {"after_expiry_status": expiry_probe.get("after_expiry_status"),
               "expired_denied": expiry_probe.get("expired_denied")})
