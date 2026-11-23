"""Verify Notation trust roots and signed identity independently."""
from hashlib import sha256
from http.client import HTTPConnection
import json
from pathlib import Path
import platform
import re
import tarfile
import time

from fixtures import BUSYBOX_IMAGE

REGISTRY = (
    "docker.io/library/registry:3.0.0@sha256:"
    "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
SKOPEO = (
    "quay.io/skopeo/stable:v1.20.0@sha256:"
    "47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4"
)
IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
SCOPE = (
    "One disposable Kubernetes v1.36.1 cluster and pinned Distribution registry. "
    "Three owned manifest digests have real Notation 1.3.2 signatures: the approved identity "
    "from the approved CA, another identity from the same CA, and the approved subject name "
    "from a separate CA. All verify with both roots and unrestricted identities; the scoped "
    "policy then accepts only the approved root and identity. A Ready Deployment runs that "
    "exact verified image. Production identity issuance, rotation and coverage remain separate."
)
APPROVED_NAME = "saf-approved"
OTHER_NAME = "saf-other"


def request(port, method, path, data=None, headers=None):
    connection = HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, path, body=data, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read(2**22), dict(response.getheaders())
    finally:
        connection.close()


def content_digest(data):
    return "sha256:" + sha256(data).hexdigest()


def registry_port(lab, registry):
    address = lab.command("docker", "port", registry, "5000/tcp").stdout.strip()
    match = re.fullmatch(r"127\.0\.0\.1:(\d+)", address)
    if not match:
        lab.block("The owned registry did not have a loopback-only published port")
    port = int(match[1])
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            if request(port, "GET", "/v2/")[0] == 200:
                return port
        except OSError:
            pass
        time.sleep(0.4)
    lab.block("The owned registry did not become ready")


def seed_image(lab, node, network, alias):
    temporary = lab.kubeconfig.parent
    host = temporary / "hosts.toml"
    host.write_text(f'[host."http://{alias}:5000"]\ncapabilities = ["pull", "resolve"]\n')
    settings = f"/etc/containerd/certs.d/{alias}:5000"
    lab.command("docker", "exec", node, "mkdir", "-p", settings)
    lab.command("docker", "cp", str(host), f"{node}:{settings}/hosts.toml")
    staging = temporary / alias
    staging.mkdir(mode=0o700)
    archive = staging / "fixture.tar"
    lab.command("docker", "image", "save", "--output", str(archive), BUSYBOX_IMAGE, timeout=110)
    digest = staging / "image-digest"
    lab.command("docker", "run", "--rm", "--network", network, "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--volume", f"{staging}:/fixture",
                SKOPEO, "copy", "--format", "oci", "--dest-tls-verify=false",
                "--digestfile", "/fixture/image-digest", "docker-archive:/fixture/fixture.tar",
                f"docker://{alias}:5000/releases/images:deployed", timeout=110)
    return {"repository": "releases/images", "digest": digest.read_text().strip(), "type": "image"}


def deploy(lab, alias, record):
    image = f"{alias}:5000/{record['repository']}@{record['digest']}"
    selector = {"app": "retained-release"}
    lab.create({
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "retained-release"},
        "spec": {"replicas": 1, "selector": {"matchLabels": selector}, "template": {
            "metadata": {"labels": selector},
            "spec": {"containers": [{
                "name": "marker", "image": image, "imagePullPolicy": "Always",
                "command": ["sh", "-ec", "printf retained-release; sleep 600"],
            }]},
        }},
    })
    ready = lab.kubectl("rollout", "status", "deployment/retained-release", "--timeout=90s",
                        timeout=100, allow_failure=True)
    if ready.returncode:
        lab.kubectl("describe", "pods", "-l", "app=retained-release", allow_failure=True)
        lab.block("The deployment did not pull and run the exact fixture digest")
    pod = json.loads(lab.kubectl("get", "po", "-l", "app=retained-release", "-o", "json").stdout)["items"][0]
    statuses = pod["status"]["containerStatuses"]
    matched = len(statuses) == 1 and statuses[0]["ready"] and statuses[0]["imageID"].endswith(record["digest"])
    evidence = {"ready": len(statuses) == 1 and statuses[0]["ready"], "exact_digest_used": matched}
    lab.check("positive", "A Ready deployment runs the registry's exact immutable digest", matched, evidence)




def notation_binary(lab):
    sha = {
        ("Darwin", "arm64"): "054bf6e9fb2619390dab9c74e5d6c511bde7609f3a060ee512c6aead2440c214",
        ("Darwin", "amd64"): "72fade2ccb0765e2ff26b53c9ca663dd33dc4f2020b2b8493e703a9ccf6174a2",
        ("Linux", "arm64"): "34143c7b816a50104824278080a5cf12bbf855488e003f62e6acf27ed25c423c",
        ("Linux", "amd64"): "e1a0f060308086bf8020b2d31defb7c5348f133ca0dba6a1a7820ef3cbb6dfe5",
    }
    platform_alias = {"aarch64": "arm64", "x86_64": "amd64"}
    system = platform.system()
    machine = platform.machine().lower()
    architecture = platform_alias.get(machine, machine)
    expected = sha.get((system, architecture))
    if not expected:
        lab.block("No approved Notation digest for this host architecture")
    name = f"notation_1.3.2_{system.lower()}_{architecture}.tar.gz"
    archive = lab.kubeconfig.parent / name
    lab.command("curl", "--fail", "--location", "--retry", "2", "--output", str(archive),
                f"https://github.com/notaryproject/notation/releases/download/v1.3.2/{name}", timeout=130)
    if sha256(archive.read_bytes()).hexdigest() != expected:
        lab.block("The Notation archive did not match its release checksum")
    with tarfile.open(archive, "r:gz") as bundle:
        members = [entry for entry in bundle.getmembers() if entry.name.removeprefix("./") == "notation" and entry.isfile()]
        if len(members) != 1:
            lab.block("Expected only the pinned Notation executable in the release archive")
        data = bundle.extractfile(members[0])
        if data is None:
            lab.block("Unable to read the pinned executable")
        binary = lab.kubeconfig.parent / "notation"
        binary.write_bytes(data.read())
    binary.chmod(0o700)
    return binary


def notation(lab, binary, settings, *args, **kwargs):
    return lab.command("env", "-u", "NOTATION_USERNAME", "-u", "NOTATION_PASSWORD",
                       f"NOTATION_CONFIG={settings}", f"NOTATION_LIBEXEC={settings / 'plugins'}",
                       f"NOTATION_CACHE={settings / 'cache'}", f"DOCKER_CONFIG={settings / 'docker'}",
                       str(binary), *args, **kwargs)


def registry_manifest(port, record):
    repository, digest = record["repository"], record["digest"]
    return request(port, "GET", f"/v2/{repository}/manifests/{digest}",
                   headers={"Accept": IMAGE_MANIFEST})


def authority(lab, directory, name):
    key, cert = directory / f"{name}.key", directory / f"{name}.crt"
    config = directory / "root.cnf"
    config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=v3\n[dn]\n"
                      "[v3]\nbasicConstraints=critical,CA:true,pathlen:0\n"
                      "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-subj", f"/CN={name}", "-x509", "-days", "1", "-config", str(config),
                "-keyout", str(key), "-out", str(cert))
    key.chmod(0o600)
    return key, cert


def signer(lab, directory, label, subject, root):
    key = directory / f"{label}.key"
    csr = directory / f"{label}.csr"
    leaf = directory / f"{label}.crt"
    ext = directory / f"{label}.ext"
    ext.write_text("basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n"
                   "extendedKeyUsage=critical,codeSigning\n"
                   "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-subj", f"/C=US/ST=Oregon/O=SAF Fixture/CN={subject}", "-keyout", str(key), "-out", str(csr))
    key.chmod(0o600)
    lab.command("openssl", "x509", "-req", "-sha256", "-days", "1", "-in", str(csr),
                "-CA", str(root[1]), "-CAkey", str(root[0]), "-CAcreateserial",
                "-extfile", str(ext), "-out", str(leaf))
    chain = directory / f"{label}-chain.pem"
    chain.write_bytes(leaf.read_bytes() + root[1].read_bytes())
    return key, chain


def store_variant(lab, port, source, label):
    status, raw, _ = registry_manifest(port, source)
    if status != 200 or content_digest(raw) != source["digest"]:
        lab.block("The exact source manifest could not be read")
    manifest = json.loads(raw)
    manifest["annotations"] = {"org.opencontainers.image.description": f"Fixture image {label}"}
    content = json.dumps(manifest, sort_keys=True).encode()
    status, _, _ = request(port, "PUT", f"/v2/{source['repository']}/manifests/{label}",
                           content, {"Content-Type": IMAGE_MANIFEST})
    if status != 201:
        lab.block("Unable to seed the distinct owned manifest")
    return {**source, "digest": content_digest(content)}


def apply_policy(lab, binary, settings, scope, stores, identities):
    policy = settings / "policy-source.json"
    policy.write_text(json.dumps({"version": "1.0", "trustPolicies": [{
        "name": "scoped-fixture", "registryScopes": [scope],
        "signatureVerification": {"level": "strict"}, "trustStores": [f"ca:{store}" for store in stores],
        "trustedIdentities": identities,
    }]}))
    notation(lab, binary, settings, "policy", "import", "--force", str(policy))


def results(lab, binary, settings, refs):
    return {label: notation(lab, binary, settings, "verify", "--insecure-registry", ref,
                             allow_failure=True) for label, ref in refs.items()}


def exercise(lab, binary, registry, node, network):
    port = registry_port(lab, registry)
    source = seed_image(lab, node, network, registry)
    settings = lab.kubeconfig.parent / "trust-state"
    settings.mkdir(mode=0o700)
    directory = lab.kubeconfig.parent / "signing-fixture"
    directory.mkdir(mode=0o700)
    roots = {name: authority(lab, directory, name) for name in ("fixture-trusted", "fixture-other")}
    for name, (_, cert) in roots.items():
        notation(lab, binary, settings, "cert", "add", "--type", "ca", "--store", name, str(cert))
    identities = {
        "approved": (APPROVED_NAME, roots["fixture-trusted"]),
        "different-subject": (OTHER_NAME, roots["fixture-trusted"]),
        "different-root": (APPROVED_NAME, roots["fixture-other"]),
    }
    manifests, refs = {}, {}
    scope = f"127.0.0.1:{port}/{source['repository']}"
    local_keys = []
    for label, (subject, root) in identities.items():
        key, chain = signer(lab, directory, label, subject, root)
        local_keys.append({"name": label, "keyPath": str(key), "certPath": str(chain)})
        manifest = store_variant(lab, port, source, label)
        manifests[label] = manifest
        refs[label] = f"{scope}@{manifest['digest']}"
    (settings / "signingkeys.json").write_text(json.dumps({"keys": local_keys}))
    for label, ref in refs.items():
        notation(lab, binary, settings, "sign", "--key", label, "--insecure-registry",
                 "--force-referrers-tag=true", ref)

    absent = notation(lab, binary, settings, "verify", "--insecure-registry", refs["approved"],
                      allow_failure=True)
    absent_output = (absent.stdout + absent.stderr).lower()
    missing_policy_denied = absent.returncode != 0 and (
        "trust policy" in absent_output or "trustpolicy" in absent_output
    )
    lab.check("positive", "A genuinely signed digest cannot verify without a trust policy",
              missing_policy_denied, {"missing_trust_policy_denied": missing_policy_denied})

    apply_policy(lab, binary, settings, scope, tuple(roots), ["*"])
    baseline = {label: result.returncode == 0 for label, result in results(lab, binary, settings, refs).items()}
    lab.check("red", "Each real signature verifies when both issuers and all subjects are trusted",
              all(baseline.values()), baseline)

    pinned_identity = f"x509.subject: C=US,ST=Oregon,O=SAF Fixture,CN={APPROVED_NAME}"
    apply_policy(lab, binary, settings, scope, ("fixture-trusted",), [pinned_identity])
    enforced = results(lab, binary, settings, refs)
    subject_failure = enforced["different-subject"]
    root_failure = enforced["different-root"]
    subject_text = (subject_failure.stdout + subject_failure.stderr).lower()
    root_text = (root_failure.stdout + root_failure.stderr).lower()
    # The same three cryptographic signatures passed the baseline. Each
    # rejected fixture differs from the accepted one on only one trust axis.
    verification_error = "signature verification failed for all the signatures"
    subject_denied = (subject_failure.returncode != 0 and verification_error in subject_text
                      and refs["different-subject"].lower() in subject_text)
    root_denied = (root_failure.returncode != 0 and verification_error in root_text
                   and refs["different-root"].lower() in root_text)
    lab.check("green", "The trusted CA is insufficient for a different signing subject", subject_denied,
              {"different_subject_denied": subject_denied})
    lab.check("green", "The exact subject name is insufficient under a different root", root_denied,
              {"different_root_denied": root_denied})
    approved = enforced["approved"].returncode == 0
    lab.check("positive", "The approved identity and valid root still verify the exact digest", approved,
              {"approved_subject_and_root_verified": approved})
    deploy(lab, registry, manifests["approved"])
    (lab.evidence / "notation-trust-observations.json").write_text(
        json.dumps({"baseline": baseline, "approved": approved, "different_subject_denied": subject_denied,
                    "different_root_denied": root_denied}, indent=2, sort_keys=True) + "\n")


def run(lab):
    binary = notation_binary(lab)
    node = f"{lab.cluster}-control-plane"
    network = f"{lab.cluster}-trust-network"
    registry = f"{lab.cluster}-trust-registry"
    lab.command("docker", "network", "create", network)
    started = False
    try:
        lab.command("docker", "network", "connect", network, node)
        lab.command("docker", "run", "--detach", "--name", registry, "--network", network,
                    "--network-alias", registry, "--publish", "127.0.0.1::5000", REGISTRY)
        started = True
        exercise(lab, binary, registry, node, network)
    finally:
        removed = not started or lab.command("docker", "rm", "-fv", registry, allow_failure=True).returncode == 0
        lab.command("docker", "network", "disconnect", "-f", network, node, allow_failure=True)
        removed &= lab.command("docker", "network", "rm", network, allow_failure=True).returncode == 0
        lab.check("positive", "The owned registry and its network were removed", removed,
                  {"fixture_resources_removed": removed})
