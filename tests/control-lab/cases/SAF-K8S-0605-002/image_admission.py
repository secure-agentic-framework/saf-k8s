"""Verify Kyverno's image policy with a disposable TLS OCI registry."""
from contextlib import contextmanager
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import ssl
import tarfile
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlsplit


HERE = Path(__file__).resolve().parent
COSIGN_IMAGE = "ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d"
REGISTRY_IMAGE = "docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
FIXTURE_SIGNING = ("--yes", "--key", "/work/cosign.key", "--use-signing-config=false",
                   "--tlog-upload=false", "--new-bundle-format=true")
NS = "saf-0605-image-validation"
OUTSIDE_NS = "saf-0605-image-validation-outside"
POLICY = "saf-0605-002-owned-image-verification"
PREDICATE_TYPE = "https://saf-k8s.example/attestations/harmless-build-record/v1"
REPOSITORIES = {
    "approved": "fixture/inert-approved",
    "missing-attestation": "fixture/inert-no-attestation",
    "unrelated-signer": "fixture/inert-untrusted",
}
DENIALS = {
    "missing-attestation": "image must carry a valid harmless-build-record attestation",
    "unrelated-signer": "image must have a valid signature from the enrolled operator key",
}


class FixtureError(RuntimeError):
    pass


class RegistryFixture:
    def __init__(self, lab):
        self.lab = lab
        self.work = lab.kubeconfig.parent / "image-admission"
        self.work.mkdir(mode=0o700)
        self.registry_container = f"saf-0605-registry-{lab.cluster.removeprefix('saf-lab-')}"
        self.registry_volume = self.registry_container + "-data"
        self.registry = self.registry_container + ".kyverno.svc.cluster.local:5000"
        self.registry_ca = self.work / "registry-ca.crt"
        self.docker_config = self.work / "docker-config"
        self.docker_config.mkdir(mode=0o700)
        self.endpoint = lab.command("docker", "context", "inspect", lab.context, "--format",
                                    "{{.Endpoints.docker.Host}}").stdout.strip()
        if not self.endpoint.startswith("unix://"):
            raise FixtureError("the Docker context must use a local Unix socket")

    def docker(self, *args, **kwargs):
        return self.lab.command(
            "env", "-u", "DOCKER_CONTEXT", "-u", "DOCKER_HOST", "docker",
            "--config", str(self.docker_config), "--host", self.endpoint, *args, **kwargs,
        )

    def kube(self, *args, timeout=50, allow_failure=False, input_text=None):
        return self.lab.command(
            "kubectl", "--kubeconfig", str(self.lab.kubeconfig), "--context", f"kind-{self.lab.cluster}",
            f"--request-timeout={max(5, timeout - 5)}s", *args,
            payload=input_text, timeout=timeout, allow_failure=allow_failure,
        )

    def cosign(self, directory, *args, **kwargs):
        return self.docker(
            "run", "--rm", "--network", "kind", "--volume", f"{directory}:/work",
            "--workdir", "/work", "--user", f"{os.getuid()}:{os.getgid()}",
            "--env", "COSIGN_PASSWORD=", "--env", "SSL_CERT_FILE=/saf-ca.crt",
            "--volume", f"{self.registry_ca}:/saf-ca.crt:ro", COSIGN_IMAGE,
            *args, timeout=120, **kwargs,
        )

    def clean(self):
        container = self.docker("rm", "--force", self.registry_container, allow_failure=True)
        volume = self.docker("volume", "rm", self.registry_volume, allow_failure=True)
        if container.returncode and "no such container" not in container.stderr.lower():
            raise FixtureError("disposable registry container removal failed")
        if volume.returncode and "no such volume" not in volume.stderr.lower():
            raise FixtureError("disposable registry volume removal failed")


def _start_registry(r):
    tls = r.work / "registry-tls"
    tls.mkdir(mode=0o700)
    ca_key = r.work / "registry-ca.key"
    leaf_key, leaf = tls / "tls.key", tls / "tls.crt"
    csr, extension = r.work / "registry.csr", r.work / "registry.ext"
    alias = r.registry.split(":", 1)[0]
    extension.write_text(
        f"subjectAltName=DNS:{alias},IP:127.0.0.1\n"
        "basicConstraints=critical,CA:FALSE\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
        encoding="ascii",
    )
    r.lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
          "-subj", "/CN=SAF fixture registry CA", "-keyout", str(ca_key), "-out", str(r.registry_ca),
          "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectKeyIdentifier=hash",
          "-addext", "authorityKeyIdentifier=keyid:always", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    r.lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={alias}",
          "-keyout", str(leaf_key), "-out", str(csr))
    r.lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(r.registry_ca), "-CAkey", str(ca_key),
          "-CAcreateserial", "-extfile", str(extension), "-days", "2", "-out", str(leaf))
    r.docker("pull", REGISTRY_IMAGE, timeout=300)
    r.docker("volume", "create", r.registry_volume)
    # Host publication uses the allocated loopback port. The private alias
    # serves Cosign and the case's admission controller.
    r.docker("run", "--detach", "--name", r.registry_container, "--network", "kind",
             "--network-alias", r.registry.split(":", 1)[0], "--publish", "127.0.0.1::5000",
             "--env", "REGISTRY_HTTP_TLS_CERTIFICATE=/saf-tls/tls.crt",
             "--env", "REGISTRY_HTTP_TLS_KEY=/saf-tls/tls.key",
             "--volume", f"{tls}:/saf-tls:ro",
             "--volume", f"{r.registry_volume}:/var/lib/registry", REGISTRY_IMAGE)
    data = json.loads(r.docker("inspect", r.registry_container, "--format", "{{json .NetworkSettings.Networks.kind}}").stdout)
    ip = data["IPAddress"]
    port = r.docker("inspect", r.registry_container, "--format", "{{(index (index .NetworkSettings.Ports \"5000/tcp\") 0).HostPort}}").stdout.strip()
    return ip, port


def _registry_digest(host_port: str, repository: str, ca_file: Path) -> str:
    request = urllib.request.Request(
        f"https://127.0.0.1:{host_port}/v2/{repository}/manifests/case", method="HEAD",
        headers={"Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"},
    )
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)),
        )
        with opener.open(request, timeout=8) as response:
            digest = response.headers.get("Docker-Content-Digest", "")
    except (urllib.error.URLError, TimeoutError) as error:
        raise FixtureError(f"local registry could not resolve {repository} ({type(error).__name__})") from error
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise FixtureError(f"registry returned an invalid digest for {repository}")
    return digest


def _assert_remote_digest(r, reference):
    pinned = reference.rsplit("@sha256:", 1)[-1]
    repo_digests = json.loads(r.docker("inspect", "--format", "{{json .RepoDigests}}", reference).stdout)
    if not any(digest.endswith("@sha256:" + pinned) for digest in (repo_digests or [])):
        raise FixtureError("container utility image did not resolve to its requested digest")


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _build_and_push(r, host_port):
    registry = f"https://127.0.0.1:{host_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(
        context=ssl.create_default_context(cafile=r.registry_ca)))

    def request(path, method, body=None, content_type=None):
        headers = {"Content-Type": content_type} if content_type else {}
        return opener.open(urllib.request.Request(registry + path, data=body, method=method,
                                                 headers=headers), timeout=10)

    deadline = time.monotonic() + 20
    while True:
        try:
            with request("/v2/", "GET") as response:
                if response.status == 200:
                    break
        except (urllib.error.URLError, TimeoutError):
            if time.monotonic() >= deadline:
                raise FixtureError("the disposable registry did not become ready")
        time.sleep(0.25)

    marker = b"harmless synthetic SAF-K8S fixture\n"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as image_tar:
        info = tarfile.TarInfo("case/marker")
        info.size = len(marker)
        info.mode = 0o444
        image_tar.addfile(info, io.BytesIO(marker))
    layer_tar = stream.getvalue()
    layer = gzip.compress(layer_tar, mtime=0)
    machine = platform.machine().lower()
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(machine)
    if arch is None:
        raise FixtureError(f"unsupported local fixture architecture: {machine}")
    config = json.dumps({"architecture": arch, "os": "linux", "config": {"User": "65532:65532"},
                         "rootfs": {"type": "layers", "diff_ids": [_digest(layer_tar)]}},
                        separators=(",", ":")).encode()
    media = "application/vnd.oci.image.manifest.v1+json"
    manifest = json.dumps({
        "schemaVersion": 2, "mediaType": media,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": _digest(config), "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": _digest(layer), "size": len(layer)}],
    }, separators=(",", ":")).encode()
    expected = _digest(manifest)
    for repository in REPOSITORIES.values():
        for blob in (config, layer):
            stem = f"/v2/{repository}/blobs/uploads/"
            with request(stem, "POST", b"") as begin:
                location = urlsplit(begin.headers["Location"])
            if not location.path.startswith(stem):
                raise FixtureError("registry upload location differs from the fixture repository")
            params = parse_qsl(location.query) + [("digest", _digest(blob))]
            with request(location.path + "?" + urlencode(params), "PUT", blob, "application/octet-stream") as upload:
                if upload.status != 201:
                    raise FixtureError("local registry did not accept the exact image blob")
        with request(f"/v2/{repository}/manifests/case", "PUT", manifest, media) as published:
            if published.status != 201:
                raise FixtureError("local registry did not accept the fixture manifest")
        if _registry_digest(host_port, repository, r.registry_ca) != expected:
            raise FixtureError("stored fixture manifest digest differs from the assembled image")
    return {case: f"{r.registry}/{repo}@{expected}" for case, repo in REPOSITORIES.items()}


def _policy(public_key: str, registry: str) -> str:
    template = (HERE / "image-validating-policy.yaml").read_text(encoding="utf-8")
    if template.count("__CASE_RUN_PUBLIC_KEY__") != 1:
        raise FixtureError("policy template does not contain exactly one public-key placeholder")
    key_lines = public_key.rstrip().splitlines()
    if not key_lines or key_lines[0] != "-----BEGIN PUBLIC KEY-----" or key_lines[-1] != "-----END PUBLIC KEY-----":
        raise FixtureError("unexpected public signing-key format")
    key_block = "\n            ".join(key_lines)
    return template.replace("__CASE_RUN_PUBLIC_KEY__", key_block).replace("saf-0605-registry-*:5000", registry)


def _pod(name: str, image: str, namespace: str) -> dict:
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace,
            "labels": {"saf-k8s.example/case": "0605-002-image-validation"}},
            "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                      "containers": [{"name": "inert", "image": image, "imagePullPolicy": "IfNotPresent",
                                      "resources": {"requests": {"cpu": "10m", "memory": "8Mi"},
                                                    "limits": {"cpu": "50m", "memory": "32Mi"}}}]}}


def _probe(r, name, image, namespace):
    return r.kube("-n", namespace, "create", "-f", "-", "--dry-run=server", "-o", "json",
                  input_text=json.dumps(_pod(name, image, namespace)), timeout=35, allow_failure=True)


def _admitted(result, name, image, namespace):
    if result.returncode:
        return False
    pod = json.loads(result.stdout)
    return (pod["kind"] == "Pod" and pod["metadata"]["name"] == name
            and pod["metadata"]["namespace"] == namespace
            and [container["image"] for container in pod["spec"]["containers"]] == [image])


def _publish_signatures(r, images):
    operator, other = r.work / "operator", r.work / "other"
    for directory in (operator, other):
        directory.mkdir(mode=0o700)
        r.cosign(directory, "generate-key-pair")
        (directory / "predicate.json").write_text(
            '{"case":"saf-lab-0605-002.2","classification":"inert"}\n', encoding="ascii",
        )

    for case, image in images.items():
        signer = other if case == "unrelated-signer" else operator
        r.cosign(signer, "sign", *FIXTURE_SIGNING, image)
        r.cosign(signer, "verify", "--key", "/work/cosign.pub", "--insecure-ignore-tlog=true", image)
        if case != "missing-attestation":
            r.cosign(signer, "attest", *FIXTURE_SIGNING, "--type", PREDICATE_TYPE,
                     "--predicate", "/work/predicate.json", image)
            r.cosign(signer, "verify-attestation", "--key", "/work/cosign.pub",
                     "--insecure-ignore-tlog=true", "--type", PREDICATE_TYPE, image)

    signature_only = r.cosign(operator, "verify-attestation", "--key", "/work/cosign.pub",
                              "--insecure-ignore-tlog=true", "--type", PREDICATE_TYPE,
                              images["missing-attestation"], allow_failure=True)
    missing = (f"none of the attestations matched the predicate type: {PREDICATE_TYPE}, "
               "found: https://sigstore.dev/cosign/sign/v1")
    if not signature_only.returncode or missing not in signature_only.stderr.lower():
        raise FixtureError("Cosign did not confirm the exact signature-only comparison")
    operator_key = (operator / "cosign.pub").read_text(encoding="ascii")
    if operator_key == (other / "cosign.pub").read_text(encoding="ascii"):
        raise FixtureError("the two fixture signers returned an identical public key")
    return operator_key


def _registry_chart_values(r, registry_ip):
    r.kube("create", "namespace", "kyverno")
    service = {"apiVersion": "v1", "kind": "Service",
               "metadata": {"name": r.registry_container, "namespace": "kyverno"},
               "spec": {"ports": [{"name": "registry", "port": 5000, "protocol": "TCP"}]}}
    endpoint = {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
                "metadata": {"name": r.registry_container + "-owned", "namespace": "kyverno",
                             "labels": {"kubernetes.io/service-name": r.registry_container,
                                        "endpointslice.kubernetes.io/managed-by": "saf-k8s.example"}},
                "addressType": "IPv4", "endpoints": [{"addresses": [registry_ip], "conditions": {"ready": True}}],
                "ports": [{"name": "registry", "port": 5000, "protocol": "TCP"}]}
    for obj in (service, endpoint):
        r.kube("-n", "kyverno", "create", "-f", "-", input_text=json.dumps(obj))
    r.kube("-n", "kyverno", "create", "configmap", "saf-fixture-registry-ca",
           f"--from-file=registry-ca.crt={r.registry_ca}")
    values = {"admissionController": {
        "container": {"extraEnvVars": [{"name": "SSL_CERT_FILE", "value": "/saf-ca/registry-ca.crt"}]},
        "extraVolumeMounts": [{"name": "saf-registry-ca", "mountPath": "/saf-ca", "readOnly": True}],
        "extraVolumes": [{"name": "saf-registry-ca", "configMap": {"name": "saf-fixture-registry-ca"}}],
    }}
    path = r.work / "registry-helm-values.json"
    path.write_text(json.dumps(values))
    return path


def _wait_policy(r):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        state = r.kube("get", "imagevalidatingpolicy", POLICY, "-o", "json", allow_failure=True)
        if not state.returncode:
            if json.loads(state.stdout).get("status", {}).get("conditionStatus", {}).get("ready") is True:
                return
        time.sleep(.5)
    raise FixtureError("Kyverno did not report the ImageValidatingPolicy Ready")


@contextmanager
def registry(lab):
    r = RegistryFixture(lab)
    try:
        r.docker("pull", COSIGN_IMAGE, timeout=300)
        _assert_remote_digest(r, COSIGN_IMAGE)
        registry_ip, host_port = _start_registry(r)
        _assert_remote_digest(r, REGISTRY_IMAGE)
        yield r, host_port, _registry_chart_values(r, registry_ip)
    except FixtureError as error:
        lab.block(str(error))
    finally:
        r.clean()
    lab.check("positive", "The disposable registry container and volume were removed",
              True, {"registry_cleanup": "complete"})


def run(lab, r, host_port):
    images = _build_and_push(r, host_port)
    operator_key = _publish_signatures(r, images)
    unchanged = all(_registry_digest(host_port, repo, r.registry_ca) == images[case].rsplit("@", 1)[1]
                    for case, repo in REPOSITORIES.items())
    lab.check("positive", "Cosign verifies signatures and exact predicate presence and preserves OCI subjects",
              unchanged, {"registry_subjects_unchanged": unchanged, "distinct_signers": True,
                          "signature_only_comparison_verified": True, "cosign": COSIGN_IMAGE,
                          "registry": REGISTRY_IMAGE})
    r.kube("create", "namespace", NS)
    r.kube("create", "namespace", OUTSIDE_NS)
    r.kube("label", "namespace", NS, "saf-k8s.example/image-validation=enrolled")

    baseline = {case: _admitted(_probe(r, f"probe-{case}", image, NS), f"probe-{case}", image, NS)
                for case, image in images.items()}
    lab.check("red", "All three exact image fixtures are admitted before applying the image policy",
              all(baseline.values()), baseline)

    r.kube("apply", "-f", "-", input_text=_policy(operator_key, r.registry))
    _wait_policy(r)
    approved = _admitted(_probe(r, "probe-approved", images["approved"], NS),
                         "probe-approved", images["approved"], NS)
    lab.check("green", "Kyverno admits the trusted image with the required attestation and payload",
              approved, {"admitted": approved})
    for case, reason in DENIALS.items():
        image = images[case]
        result = _probe(r, f"probe-{case}", image, NS)
        detail = (f"required predicate type {PREDICATE_TYPE} not found" if case == "missing-attestation"
                  else "accepted signatures do not match threshold")
        webhook = f'admission webhook "ivpol.validate.kyverno.svc-fail-finegrained-{POLICY}" denied'
        denied = bool(result.returncode and all(marker in result.stderr for marker in (webhook, reason, image, detail)))
        lab.check("green", f"Kyverno denies {case} with its exact image verification failure",
                  denied, {"admitted": result.returncode == 0, "matched_policy_reason": denied})
    untrusted = images["unrelated-signer"]
    outside = _admitted(_probe(r, "probe-unrelated-signer", untrusted, OUTSIDE_NS),
                        "probe-unrelated-signer", untrusted, OUTSIDE_NS)
    lab.check("positive", "The same unrelated-signer image is admitted outside the enrolled namespace",
              outside, {"admitted": outside})
