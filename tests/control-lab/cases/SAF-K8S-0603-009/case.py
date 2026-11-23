"""Generate provenance during a pinned BuildKit build, sign it and verify its OCI subject."""
import base64
from datetime import datetime
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import platform
import re
import ssl
import tarfile
import time
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlsplit

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
BUILDKIT = ("docker.io/moby/buildkit:v0.28.0@sha256:"
            "37539dd4d60fc70968d164d3850d903a2c56f6402214a1953fbf9fcb81ada731")
SKOPEO = ("quay.io/skopeo/stable:v1.20.0@sha256:"
          "47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4")
BUILDER_ID = "https://saf-k8s.example/lab/buildkit/v0.28.0"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
REPOSITORY = "fixture/saf-provenance"
MARKER = "SAF-K8S-0603-009 build output"
SCOPE = (
    "A single-platform BuildKit v0.28.0 build using a pinned BusyBox input and a disposable "
    "TLS OCI registry with an ephemeral fixture Cosign key. The attestation is bound to the exact "
    "platform image digest; the test verifies signed claims and runs the exact image in Kind. "
    "Production builder identity, independent attestation generation and SLSA level remain separate."
)


def load_registry():
    location = HERE.parent / "SAF-K8S-0605-002" / "image_admission.py"
    spec = importlib.util.spec_from_file_location("saf_provenance_registry", location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(data):
    return "sha256:" + sha256(data).hexdigest()


def oci_blob(archive, descriptor):
    algorithm, expected = descriptor["digest"].split(":", 1)
    if algorithm != "sha256":
        raise ValueError("fixture expects OCI SHA-256 descriptors")
    data = archive.extractfile(f"blobs/{algorithm}/{expected}").read()
    if digest(data) != descriptor["digest"] or len(data) != descriptor["size"]:
        raise ValueError("OCI blob does not match its descriptor")
    return data


def build(registry):
    lab = registry.lab
    staging = registry.work / "build"
    context = staging / "context"
    context.mkdir(parents=True, mode=0o700)
    (context / "Dockerfile").write_text(
        f'FROM {BUSYBOX_IMAGE}\nARG SAF_MARKER\nLABEL org.opencontainers.image.title="$SAF_MARKER"\n'
         "COPY marker.txt /fixture-marker\nUSER 65534:65534\n"
    )
    (context / "marker.txt").write_text(MARKER + "\n")
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(platform.machine())
    if not arch:
        lab.block("No pinned local BusyBox platform for this architecture")
    name = f"{lab.cluster}-provenance-buildkit"
    registry.docker("run", "--detach", "--name", name, "--privileged",
                    "--volume", f"{staging}:/io", BUILDKIT,
                    "--addr", "unix:///run/buildkit/buildkitd.sock", timeout=160)
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if registry.docker("exec", name, "buildctl", "debug", "workers", allow_failure=True).returncode == 0:
                break
            time.sleep(0.5)
        else:
            lab.block("Owned BuildKit daemon could not start")
        registry.docker(
            "exec", name, "buildctl", "build", "--frontend", "dockerfile.v0",
            "--local", "context=/io/context", "--local", "dockerfile=/io/context",
            "--opt", f"platform=linux/{arch}", "--opt", f"build-arg:SAF_MARKER={MARKER}",
            "--opt", f"attest:provenance=mode=max,version=v1,builder-id={BUILDER_ID}",
            "--output", f"type=oci,name={registry.registry}/{REPOSITORY}:case,dest=/io/build.tar",
            timeout=180,
        )
    finally:
        registry.docker("rm", "-fv", name)
    return staging / "build.tar", arch


class Registry:
    def __init__(self, registry, port):
        self.url = f"https://127.0.0.1:{port}/v2/{REPOSITORY}/"
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=registry.registry_ca)),
        )

    def call(self, suffix, method, content=None, headers=None):
        request = urllib.request.Request(self.url + suffix, data=content, method=method, headers=headers or {})
        return self.opener.open(request, timeout=10)

    def upload_blob(self, media, data):
        with self.call("blobs/uploads/", "POST", b"") as start:
            prefix = f"/v2/{REPOSITORY}/"
            location = urlsplit(start.headers["Location"])
            if not location.path.startswith(prefix + "blobs/uploads/"):
                raise ValueError("registry blob upload escaped the fixture repository")
        query = urlencode(parse_qsl(location.query) + [("digest", digest(data))])
        with self.call(location.path.removeprefix(prefix) + "?" + query, "PUT", data,
                       {"Content-Type": "application/octet-stream"}) as upload:
            if upload.status != 201:
                raise ValueError(f"registry did not accept the fixture blob {media}")


def image_descriptors(archive, index):
    for entry in index["manifests"]:
        if entry["mediaType"] == "application/vnd.oci.image.index.v1+json":
            yield from image_descriptors(archive, json.loads(oci_blob(archive, entry)))
        else:
            yield entry


def publish_layout(registry, port, location, arch):
    upload = Registry(registry, port)
    with tarfile.open(location, "r") as archive:
        index = json.load(archive.extractfile("index.json"))
        entries = list(image_descriptors(archive, index))
        image, = (entry for entry in entries
                  if entry.get("platform", {}).get("architecture") == arch
                  and entry.get("platform", {}).get("os") == "linux")
        manifests = [entry for entry in entries if
                     entry.get("annotations", {}).get("vnd.docker.reference.digest") == image["digest"]]
        if not manifests:
            registry.lab.block("No BuildKit provenance descriptor for the immutable output")
        statement = None
        for descriptor in manifests:
            attestation = json.loads(oci_blob(archive, descriptor))
            for layer in attestation["layers"]:
                if layer.get("annotations", {}).get("in-toto.io/predicate-type") == PREDICATE_TYPE:
                    statement = json.loads(oci_blob(archive, layer))
        if statement is None:
            registry.lab.block("No SLSA Provenance v1 statement in the BuildKit export")
        manifest_bytes = oci_blob(archive, image)
        manifest = json.loads(manifest_bytes)
        for blob in [manifest["config"], *manifest["layers"]]:
            upload.upload_blob(blob["mediaType"], oci_blob(archive, blob))
        with upload.call("manifests/case", "PUT", manifest_bytes, {"Content-Type": image["mediaType"]}) as response:
            stored = response.headers.get("Docker-Content-Digest")
            if response.status != 201 or stored != image["digest"]:
                registry.lab.block("Registry did not retain the exact BuildKit manifest digest")
    return f"{registry.registry}/{REPOSITORY}@{stored}", statement, manifest_bytes


def digest_matches(statement, ref):
    value = ref.rsplit("@sha256:", 1)[1]
    return bool(statement.get("subject")) and all(
        subject.get("digest", {}).get("sha256") == value for subject in statement["subject"]
    )


def provenance_claims(statement, ref, base_digest):
    if statement.get("_type") != STATEMENT_TYPE or statement.get("predicateType") != PREDICATE_TYPE:
        return False
    predicate = statement["predicate"]
    definition = predicate["buildDefinition"]
    info = predicate["runDetails"]
    metadata = info["metadata"]
    start, end = (datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", metadata[field]).replace("Z", "+00:00"))
                  for field in ("startedOn", "finishedOn"))
    return (
        digest_matches(statement, ref)
        and info["builder"]["id"] == BUILDER_ID
        and bool(metadata["invocationId"]) and start <= end
        and definition["externalParameters"]["request"]["frontend"] == "dockerfile.v0"
        and definition["externalParameters"]["request"]["args"].get("build-arg:SAF_MARKER") == MARKER
        and any("busybox" in dep.get("uri", "") and dep.get("digest", {}).get("sha256") in base_digest
                for dep in definition["resolvedDependencies"])
    )


def cosign_verify(registry, signer, ref):
    return registry.cosign(signer, "verify-attestation", "--key", "/work/cosign.pub",
                           "--insecure-ignore-tlog=true", "--type", PREDICATE_TYPE, ref,
                           allow_failure=True)


def decoded_statements(result):
    return [json.loads(base64.b64decode(json.loads(line)["payload"], validate=True))
            for line in result.stdout.splitlines() if line.strip()]


def run_image(registry, ref):
    lab = registry.lab
    host = registry.registry
    node = f"{lab.cluster}-control-plane"
    directory = f"/etc/containerd/certs.d/{host}"
    hosts = registry.work / "image-hosts.toml"
    hosts.write_text(f'[host."https://{host}"]\ncapabilities = ["pull", "resolve"]\nca = "{directory}/ca.crt"\n')
    registry.docker("exec", node, "mkdir", "-p", directory)
    registry.docker("cp", str(hosts), f"{node}:{directory}/hosts.toml")
    registry.docker("cp", str(registry.registry_ca), f"{node}:{directory}/ca.crt")
    created = lab.create({
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": "saf-build-output"},
        "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                 "containers": [{"name": "build-output", "image": ref, "imagePullPolicy": "Always",
                                 "command": ["/bin/cat", "/fixture-marker"]}]},
    })
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/saf-build-output",
                "--timeout=90s", timeout=100)
    live = json.loads(lab.kubectl("get", "pod", "saf-build-output", "-o", "json").stdout)
    exact = (live["metadata"]["uid"] == created["metadata"]["uid"]
             and live["status"]["containerStatuses"][0]["imageID"].endswith(ref.rsplit("@", 1)[1]))
    observed = lab.kubectl("logs", "saf-build-output").stdout.strip()
    lab.check("positive", "Kind ran the exact provenance-verified build output",
              exact and observed == MARKER, {"immutable_runtime_reference": exact, "build_output_marker": observed})


def run(lab):
    fixture = load_registry()
    with fixture.registry(lab) as (registry, port, _):
        layout, arch = build(registry)
        ref, statement, manifest = publish_layout(registry, port, layout, arch)
        tagged_base, pinned_base = BUSYBOX_IMAGE.split("@", 1)
        untagged_base = tagged_base.rsplit(":", 1)[0]
        base = json.loads(registry.docker("run", "--rm", "--cap-drop=ALL",
                                         "--security-opt=no-new-privileges", SKOPEO, "inspect",
                                         "--raw", f"docker://{untagged_base}@{pinned_base}", timeout=100).stdout)
        base_platform, = (entry["digest"].removeprefix("sha256:") for entry in base["manifests"]
                          if entry.get("platform", {}).get("architecture") == arch
                          and entry.get("platform", {}).get("os") == "linux")
        base_digests = {BUSYBOX_IMAGE.rsplit("@sha256:", 1)[1], base_platform}
        (lab.evidence / "build-provenance.json").write_text(json.dumps({
            "image_manifest_sha256": digest(manifest), "buildkit_statement": statement,
            "expected_busybox_digests": sorted(base_digests), "builder_image": BUILDKIT,
        }, indent=2, sort_keys=True) + "\n")
        signer = registry.work / "saf-provenance-signer"
        signer.mkdir(mode=0o700)
        registry.cosign(signer, "generate-key-pair")
        first = cosign_verify(registry, signer, ref)
        absence = first.stderr.lower()
        absent = first.returncode != 0 and "no matching attestations" in absence
        lab.check("red", "The exact registry subject has no signed provenance before publication",
                  absent, {"signed_attestation_absent": absent})
        lab.check("green", "BuildKit generated SLSA v1 claims for the exact exported manifest",
                  provenance_claims(statement, ref, base_digests),
                  {"exact_subject": digest_matches(statement, ref), "statement_type": statement.get("_type"),
                   "predicate_type": PREDICATE_TYPE,
                   "builder": BUILDER_ID, "declared_input": "pinned BusyBox"})
        path = signer / "buildkit-predicate.json"
        path.write_text(json.dumps(statement["predicate"], sort_keys=True))
        registry.cosign(signer, "attest", *fixture.FIXTURE_SIGNING, "--type", PREDICATE_TYPE,
                        "--predicate", "/work/buildkit-predicate.json", ref)
        result = cosign_verify(registry, signer, ref)
        verified = [] if result.returncode else decoded_statements(result)
        same = len(verified) == 1 and verified[0].get("predicate") == statement["predicate"]
        exact = same and digest_matches(verified[0], ref)
        lab.check("green", "Cosign verifies the registry-stored attestation for the exact build and digest",
                  exact, {"exact_signed_subject": exact, "builder_predicate_unmodified": same})
        different = registry.work / "unrelated-signing-key"
        different.mkdir(mode=0o700)
        registry.cosign(different, "generate-key-pair")
        rejected = cosign_verify(registry, different, ref)
        wrong_verifier = rejected.returncode != 0 and any(
            marker in rejected.stderr.lower() for marker in ("signature", "no matching attestations", "verification failed")
        )
        lab.check("green", "A different public key cannot authenticate the genuine signed provenance",
                  wrong_verifier, {"unrelated_key_rejected": wrong_verifier})
        run_image(registry, ref)
        (lab.evidence / "build-provenance.json").write_text(json.dumps({
            "image_manifest_sha256": digest(manifest), "buildkit_statement": statement,
            "signed_predicate_matches": same, "signed_subject_matches": exact,
            "expected_busybox_digests": sorted(base_digests),
            "builder_image": BUILDKIT,
        }, indent=2, sort_keys=True) + "\n")
