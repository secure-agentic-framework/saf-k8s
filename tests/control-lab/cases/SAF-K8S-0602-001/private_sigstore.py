"""Provision the published test services with ClusterIP networking and private roots."""
import base64
from hashlib import sha256
import json
import secrets
import shutil
from pathlib import Path

import yaml

RELEASE = "v0.7.42"
ASSETS = {
    "release-ctlog.yaml": "11f4eea67f11a22ce8ad8d6364d8c575e71771c5281d5b19072a214d9fa6282d",
    "release-fulcio.yaml": "acd6c70978e668f533e73e693aa841dc58586639436cd4c04b852eae2ef6f581",
    "release-rekor-tiles.yaml": "bd3483f047f9d7efa92041c8ef83923bd4913b655e6d459574ffc2bd3e40a75a",
    "release-tsa.yaml": "6bfb70304280aa449b149766340c600577733b84d70702dad3196a0074504358",
    "release-tuf.yaml": "b4f03fe8b0d42ba947f595787cfa026d85e3fb7d2ac86eb5a45c7a00cee4d050",
}
ISSUER = "https://kubernetes.default.svc.cluster.local"
MIRROR = "http://tuf.tuf-system.svc"
PUBLIC_KEYS = (("ctlog-system", "ctlog-public-key"), ("fulcio-system", "fulcio-pub-key"),
               ("rekor-system", "rekor-pub-key"), ("tsa-system", "tsa-cert-chain"))


def apply(lab, obj):
    args = []
    if ns := obj["metadata"].get("namespace"):
        args.extend(("-n", ns))
    lab.kubectl(*args, "apply", "-f", "-", payload=json.dumps(obj))


def openssl_binary(lab):
    for candidate in (shutil.which("openssl"), "/opt/homebrew/opt/openssl@3/bin/openssl",
                      "/usr/local/opt/openssl@3/bin/openssl"):
        if candidate and Path(candidate).is_file():
            report = lab.command(candidate, "version").stdout
            if report.startswith(("OpenSSL 3.", "OpenSSL 4.")):
                return candidate
    lab.block("The private Sigstore fixture requires OpenSSL 3 or later")


def private_material(lab, work):
    openssl = openssl_binary(lab)
    folders = {}
    materials = {}
    for service in ("fulcio", "ctlog", "rekor"):
        item = work / service
        item.mkdir(mode=0o700)
        folders[service] = item
        key, public = item / "private", item / "public"
        if service == "rekor":
            lab.command(openssl, "genpkey", "-algorithm", "ED25519", "-out", str(key))
            lab.command(openssl, "pkey", "-in", str(key), "-pubout", "-out", str(public))
        else:
            lab.command(openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
            lab.command(openssl, "ec", "-in", str(key), "-pubout", "-out", str(public))
        password = item / "password"
        password.write_text(secrets.token_hex(24))
        password.chmod(0o600)
        key.chmod(0o600)
        materials[service] = {"<password-placeholder>": password, "<public-placeholder>": public,
                              "<private-placeholder>": key}

    cert = folders["fulcio"] / "ca.crt"
    plain_key = materials["fulcio"]["<private-placeholder>"]
    lab.command(openssl, "req", "-x509", "-new", "-key", str(plain_key), "-out", str(cert),
                "-sha256", "-days", "2", "-subj", "/CN=SAF fixture Fulcio root",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    encrypted = folders["fulcio"] / "encrypted"
    password = materials["fulcio"]["<password-placeholder>"]
    lab.command(openssl, "pkcs8", "-topk8", "-in", str(plain_key), "-out", str(encrypted),
                "-v2", "aes-256-cbc", "-passout", f"file:{password}")
    encrypted.chmod(0o600)
    materials["fulcio"]["<private-placeholder>"] = encrypted
    for service in ("fulcio", "ctlog"):
        materials[service]["<cert-placeholder>"] = cert
    return materials


def documents(lab, work, name):
    source = work / name
    url = f"https://github.com/sigstore/scaffolding/releases/download/{RELEASE}/{name}"
    lab.command("curl", "--fail", "--silent", "--show-error", "--location", "--retry", "2",
                "--output", str(source), url, timeout=60)
    content = source.read_bytes()
    if sha256(content).hexdigest() != ASSETS[name]:
        lab.block(f"Checksum mismatch in pinned Sigstore manifest {name}")
    return [item for item in yaml.safe_load_all(content) if item]


def component_service(lab, obj):
    metadata = obj["metadata"]
    name, namespace = metadata["name"], metadata["namespace"]
    pod = obj["spec"]["template"]["spec"]
    if name == "fulcio-grpc":
        return
    for volume in pod.get("volumes", []):
        if volume.get("persistentVolumeClaim", {}).get("claimName") == "rekor-tiles-storage":
            volume.pop("persistentVolumeClaim")
            volume["emptyDir"] = {"sizeLimit": "64Mi"}
    container, = pod["containers"]
    port, = container["ports"]
    port = port["containerPort"]
    if name == "fulcio":
        container.setdefault("env", []).append({"name": "SSL_CERT_FILE", "value": "/var/run/fulcio/ca.crt"})
    if name == "tsa":
        container["args"].extend(("--host=0.0.0.0", f"--port={port}", "--disable-ntp-monitoring=true"))
    container["readinessProbe"] = {"tcpSocket": {"port": port}, "periodSeconds": 2}
    container["resources"] = {"requests": {"cpu": "25m", "memory": "48Mi"},
                              "limits": {"cpu": "1", "memory": "512Mi"}}
    labels = {"app": name}
    apply(lab, {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": metadata,
                "spec": {"selector": {"matchLabels": labels},
                         "template": {"metadata": {"labels": labels}, "spec": pod}}})
    apply(lab, {"apiVersion": "v1", "kind": "Service", "metadata": metadata,
                "spec": {"selector": labels, "ports": [{"name": "http", "port": 80, "targetPort": port}]}})


def install(lab, work, service, filename, materials):
    generated = set()
    for obj in documents(lab, work, filename):
        kind = obj["kind"]
        ns = obj["metadata"].get("namespace")
        name = obj["metadata"]["name"]
        if kind == "PersistentVolumeClaim" or (kind, ns, name) in generated:
            continue
        generated.add((kind, ns, name))
        if kind == "Secret":
            files = [f"--from-file={field}={materials[service][placeholder]}"
                     for field, placeholder in obj["data"].items()]
            lab.kubectl("-n", ns, "create", "secret", "generic", name, *files)
        elif kind == "Service" and obj["apiVersion"] == "serving.knative.dev/v1":
            component_service(lab, obj)
        else:
            if kind == "ConfigMap" and name == "fulcio-config":
                upstream = yaml.safe_load(obj["data"]["config.yaml"])
                obj["data"]["config.yaml"] = yaml.safe_dump({
                    "oidc-issuers": {ISSUER: upstream["oidc-issuers"][ISSUER]}
                })
            apply(lab, obj)


def wait(lab, namespace, component, kind="Deployment"):
    operation = ("rollout", "status", f"deployment/{component}") if kind == "Deployment" else (
        "wait", "--for=condition=Complete", f"job/{component}")
    result = lab.kubectl("-n", namespace, *operation, "--timeout=175s", timeout=185, allow_failure=True)
    if result.returncode:
        lab.kubectl("-n", namespace, "get", "pods", "-o", "wide", allow_failure=True)
        lab.kubectl("-n", namespace, "logs", f"{kind.lower()}/{component}", "--tail=45", allow_failure=True)
        lab.block(f"Private Sigstore {component} is unavailable")


def public_data(lab, namespace, name, field):
    escaped = field.replace(".", "\\.")
    result = lab.kubectl("-n", namespace, "get", "secret", name,
                         "-o", f"jsonpath={{.data.{escaped}}}")
    return base64.b64decode(result.stdout, validate=True)


def public_copy(lab, work, namespace, name, fields):
    files = []
    for field in fields:
        path = work / f"public-{name}-{field}"
        path.write_bytes(public_data(lab, namespace, name, field))
        files.append(f"--from-file={field}={path}")
    lab.kubectl("-n", "tuf-system", "create", "secret", "generic", name, *files)


def provision(lab):
    document = json.loads(lab.kubectl("get", "--raw", "/.well-known/openid-configuration").stdout)
    node = f"{lab.cluster}-control-plane"
    node_ip = lab.command("docker", "inspect", node, "--format",
                          "{{.NetworkSettings.Networks.kind.IPAddress}}").stdout.strip()
    allowed = {ISSUER + "/openid/v1/jwks", "https://kubernetes.default.svc/openid/v1/jwks",
               f"https://{node_ip}:6443/openid/v1/jwks"}
    if document["issuer"] != ISSUER or document["jwks_uri"] not in allowed:
        lab.block("The disposable Kubernetes issuer does not match the private signing fixture")
    apply(lab, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
        "metadata": {"name": "saf-0602-001-public-oidc-discovery"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                    "name": "system:service-account-issuer-discovery"},
        "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group",
                      "name": "system:unauthenticated"}],
    })
    work = lab.kubeconfig.parent / "private-sigstore"
    work.mkdir(mode=0o700)
    materials = private_material(lab, work)
    order = (("ctlog", "release-ctlog.yaml"), ("rekor", "release-rekor-tiles.yaml"),
             ("fulcio", "release-fulcio.yaml"), ("tsa", "release-tsa.yaml"),
             ("tuf", "release-tuf.yaml"))
    for name, manifest in order:
        install(lab, work, name, manifest, materials)
    for namespace, name, fields in (
        (*PUBLIC_KEYS[0], ("public",)), (*PUBLIC_KEYS[1], ("cert",)),
        (*PUBLIC_KEYS[2], ("public",)), (*PUBLIC_KEYS[3], ("cert-chain",)),
    ):
        if namespace == "tsa-system":
            wait(lab, namespace, "createcertchain", "Job")
        public_copy(lab, work, namespace, name, fields)
    for namespace, component in (("ctlog-system", "ctlog"), ("rekor-system", "rekor"),
                                 ("fulcio-system", "fulcio"), ("tsa-system", "tsa")):
        wait(lab, namespace, component)
    wait(lab, "tuf-system", "createsecret", "Job")
    wait(lab, "tuf-system", "tuf")
    return public_data(lab, "tuf-system", "tuf-root", "root")
