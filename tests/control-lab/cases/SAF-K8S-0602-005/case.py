"""Observe exact OCI signature storage and discovery with released Notation."""
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
ZOT = "ghcr.io/project-zot/zot-minimal:v2.1.23@sha256:59cb5740832970818903c5ce104425762664c7880835ee566506aad397cd3458"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
SIGNATURE_ARTIFACT = "application/vnd.cncf.notary.signature"
SCOPE = (
    "One owned Kubernetes v1.36.1 Kind cluster, Notation 1.3.2, and pinned disposable Zot "
    "and OCI Distribution registries. Both seeded image manifests begin unsigned. The test "
    "signs one exact digest and checks genuine OCI referrers discovery, subject association "
    "and cryptographic verification on both backend types. The unrelated digest stays "
    "unsigned. The native-mode subject is used by a live Kubernetes deployment. Replication, "
    "production trust policy, and cluster admission remain separate."
)

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


def unrelated_image(lab, port, subject):
    status, original, _ = registry_manifest(port, subject)
    if status != 200 or content_digest(original) != subject["digest"]:
        lab.block("The stored subject does not match its exact image digest")
    variant = json.loads(original)
    variant.setdefault("annotations", {})["org.opencontainers.image.description"] = "Unrelated fixture manifest"
    payload = json.dumps(variant, sort_keys=True).encode()
    status, _, _ = request(port, "PUT", f"/v2/{subject['repository']}/manifests/unrelated",
                           payload, {"Content-Type": IMAGE_MANIFEST})
    if status != 201:
        lab.block("Unable to seed the distinct, unsigned fixture image")
    return {**subject, "digest": content_digest(payload)}


def list_descriptors(lab, port, record, native):
    repository, digest = record["repository"], record["digest"]
    headers = {"Accept": OCI_INDEX}
    status, data, _ = request(port, "GET", f"/v2/{repository}/referrers/{digest}", headers=headers)
    if not native and status == 404:
        tag = digest.replace(":", "-", 1)
        status, data, _ = request(port, "GET", f"/v2/{repository}/manifests/{tag}", headers=headers)
        if status == 404:
            return []
    if status != 200:
        lab.block("The registry did not return the expected signature discovery method")
    document = json.loads(data)
    if document.get("mediaType") != OCI_INDEX:
        lab.block("The registry referrers response was not an OCI index")
    return document["manifests"]


def setup_trust(lab, binary, settings, scope):
    settings.mkdir(mode=0o700)
    (settings / "docker").mkdir(mode=0o700)
    notation(lab, binary, settings, "cert", "generate-test", "--default", "saf-fixture")
    if not (settings / "localkeys" / "saf-fixture.key").is_file():
        lab.block("The Notation fixture did not isolate its generated signing identity")
    policy = settings / "trustpolicy-source.json"
    policy.write_text(json.dumps({"version": "1.0", "trustPolicies": [{
        "name": "isolated-fixtures", "registryScopes": [scope],
        "signatureVerification": {"level": "strict"}, "trustStores": ["ca:saf-fixture"],
        "trustedIdentities": ["*"],
    }]}))
    notation(lab, binary, settings, "policy", "import", str(policy))


def verify_case(lab, binary, label, repo, network, node, native):
    port = registry_port(lab, repo)
    subject = seed_image(lab, node, network, repo)
    other = unrelated_image(lab, port, subject)
    if native:
        deploy(lab, repo, subject)
    scope = f"127.0.0.1:{port}/{subject['repository']}"
    settings = lab.kubeconfig.parent / label
    setup_trust(lab, binary, settings, scope)
    signed_ref, other_ref = (f"{scope}@{record['digest']}" for record in (subject, other))

    api_status = request(port, "GET", f"/v2/{subject['repository']}/referrers/{subject['digest']}",
                         headers={"Accept": OCI_INDEX})[0]
    blank_subject = list_descriptors(lab, port, subject, native)
    blank_other = list_descriptors(lab, port, other, native)
    before = notation(lab, binary, settings, "verify", "--insecure-registry", signed_ref, allow_failure=True)
    unused = not blank_subject and not blank_other and subject["digest"] != other["digest"]
    expected_status = 200 if native else 404
    lab.check("red", f"{label} discovers neither signature before signing either subject",
              unused and api_status == expected_status and before.returncode != 0,
              {"api_status": api_status, "distinct_unsigned_subjects": unused,
               "initial_verify_rejected": before.returncode != 0})
    flag = "--force-referrers-tag=false" if native else "--force-referrers-tag=true"
    notation(lab, binary, settings, "sign", "--insecure-registry", flag, signed_ref)
    entries = [entry for entry in list_descriptors(lab, port, subject, native)
               if entry.get("artifactType") == SIGNATURE_ARTIFACT]
    if len(entries) != 1:
        lab.block("The registry did not report exactly one Notation signature for the subject")
    entry = entries[0]
    status, signature_manifest, _ = registry_manifest(port, {**subject, "digest": entry["digest"]})
    artifact = json.loads(signature_manifest) if status == 200 else {}
    bound = status == 200 and content_digest(signature_manifest) == entry["digest"] and (
        artifact.get("subject", {}).get("digest") == subject["digest"]
    )
    shown = notation(lab, binary, settings, "list", "--insecure-registry", signed_ref).stdout
    verified = notation(lab, binary, settings, "verify", "--insecure-registry", signed_ref,
                        allow_failure=True)
    evidence = {"registry_subject_digest_matches": bound, "notation_lists_signature": entry["digest"] in shown,
                "notation_verified_digest": verified.returncode == 0}
    lab.check("green", f"{label} stores and verifies the signature for the exact image digest",
              all(evidence.values()), evidence)
    other_verify = notation(lab, binary, settings, "verify", "--insecure-registry", other_ref,
                            allow_failure=True)
    other_unsigned = not list_descriptors(lab, port, other, native) and other_verify.returncode != 0
    after_status, raw, _ = registry_manifest(port, subject)
    stable = after_status == 200 and content_digest(raw) == subject["digest"]
    lab.check("positive", f"{label} retains the unchanged signed image and the unrelated unsigned image",
              stable and other_unsigned, {"image_digest_unchanged": stable, "unrelated_stays_unsigned": other_unsigned})
    return {"mode": label, "api_status_before_signing": api_status, **evidence,
            "image_digest_unchanged": stable, "unrelated_stays_unsigned": other_unsigned}


def run(lab):
    binary = notation_binary(lab)
    node = f"{lab.cluster}-control-plane"
    network = f"{lab.cluster}-signature-network"
    lab.command("docker", "network", "create", network)
    registries = []
    try:
        lab.command("docker", "network", "connect", network, node)
        receipts = []
        for label, image, native in (("native-referrers", ZOT, True), ("tag-fallback", REGISTRY, False)):
            repo = f"{lab.cluster}-{label}"
            lab.command("docker", "run", "--detach", "--name", repo, "--network", network,
                        "--network-alias", repo, "--publish", "127.0.0.1::5000", image, timeout=180)
            registries.append(repo)
            receipts.append(verify_case(lab, binary, label, repo, network, node, native))
        (lab.evidence / "notation-observations.json").write_text(
            json.dumps(receipts, indent=2, sort_keys=True) + "\n")
    finally:
        removed = True
        for repo in reversed(registries):
            removed &= lab.command("docker", "rm", "-fv", repo, allow_failure=True).returncode == 0
        lab.command("docker", "network", "disconnect", "-f", network, node, allow_failure=True)
        removed &= lab.command("docker", "network", "rm", network, allow_failure=True).returncode == 0
        lab.check("positive", "Both temporary registries and their private network were removed", removed,
                  {"fixture_resources_removed": removed})
