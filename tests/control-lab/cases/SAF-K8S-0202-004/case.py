"""Exercise PSA hostPath denial and a daemonless, socket-free benign build."""
import hashlib
import json
from pathlib import Path
import re
import time

SCOPE = (
    "Kind v1.36 Pod Security Admission rejects server dry-run Pods with inert hostPath declarations. "
    "A benign compliant Pod reaches Ready and a pinned daemonless Kaniko fixture builds and verifies a "
    "single-file OCI image and Docker archive without hostPath or a mounted runtime socket."
)

NAMESPACE = "saf-test"
BUSYBOX_IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
KANIKO_IMAGE = ("ghcr.io/osscontainertools/kaniko:v1.28.5@sha256:"
                "738807f0e31daf07743f89260a95956dcc6ee4f62553f4f6344c990cabab8675")
PYTHON_IMAGE = ("docker.io/library/python:3.13.2-alpine@sha256:"
                "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
FIXTURE_TEXT = "socket-free build fixture"
OCI_INSPECT = r'''
import gzip, hashlib, io, json, re, tarfile
from pathlib import Path

ROOT = Path("/build-out/oci")
EXPECTED = "socket-free build fixture"
def digest(raw): return "sha256:" + hashlib.sha256(raw).hexdigest()
def read_json(path): return json.loads(path.read_bytes())
def descriptor(root, item):
    assert item["mediaType"] and item["size"] >= 0
    algorithm, encoded = item["digest"].split(":", 1)
    assert algorithm == "sha256" and re.fullmatch(r"[0-9a-f]{64}", encoded)
    raw = (root / "blobs" / algorithm / encoded).read_bytes()
    assert len(raw) == item["size"] and digest(raw) == item["digest"]
    return raw

layout = read_json(ROOT / "oci-layout")
assert layout.get("imageLayoutVersion") == "1.0.0"
index_raw = (ROOT / "index.json").read_bytes()
index = json.loads(index_raw)
assert index["schemaVersion"] == 2
assert index["mediaType"] == "application/vnd.oci.image.index.v1+json"
assert len(index["manifests"]) == 1
manifest_desc = index["manifests"][0]
manifest_raw = descriptor(ROOT, manifest_desc)
manifest = json.loads(manifest_raw)
assert manifest["schemaVersion"] == 2
assert manifest["mediaType"] in (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
config_raw = descriptor(ROOT, manifest["config"])
config = json.loads(config_raw)
layers = manifest["layers"]
assert len(layers) == 1
layer_raw = descriptor(ROOT, layers[0])
assert len(config["rootfs"]["diff_ids"]) == len(layers) == 1
# DiffIDs hash the uncompressed layer tar.
uncompressed = gzip.decompress(layer_raw) if layer_raw.startswith(b"\x1f\x8b") else layer_raw
actual_diff_id = digest(uncompressed)
with tarfile.open(fileobj=io.BytesIO(layer_raw), mode="r:*") as layer:
    payload = layer.extractfile("fixture.txt")
    assert payload is not None and payload.read().decode() == EXPECTED
    members = layer.getmembers()
    assert len(members) == 1 and members[0].name == "fixture.txt"
assert config["rootfs"]["diff_ids"] == [actual_diff_id]

# Preserve and independently inspect the original docker-save archive proof.
with tarfile.open("/build-out/image.tar") as archive:
    docker_manifest = json.load(archive.extractfile("manifest.json"))
    assert len(docker_manifest) == 1 and len(docker_manifest[0]["Layers"]) == 1
    with tarfile.open(fileobj=archive.extractfile(docker_manifest[0]["Layers"][0]), mode="r:*") as layer:
        payload = layer.extractfile("fixture.txt")
        assert payload is not None and payload.read().decode() == EXPECTED

assert not any(Path(name).is_socket() for name in (
    "/var/run/docker.sock", "/run/containerd/containerd.sock", "/var/run/crio/crio.sock",
))
digest_file = Path("/build-out/digest").read_text().strip()
assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest_file)
assert digest_file == manifest_desc["digest"]
print(json.dumps({
  "verified": {
    "oci_layout_version": layout["imageLayoutVersion"],
    "index_media_type": index["mediaType"],
    "one_manifest": len(index["manifests"]) == 1,
    "manifest_media_type": manifest["mediaType"],
    "config_media_type": manifest["config"]["mediaType"],
    "one_layer": len(layers) == 1,
    "all_descriptor_bytes_match_digest_and_size": True,
    "oci_payload_matches": True,
    "inspector_has_no_standard_runtime_socket": True,
    "docker_archive_payload_matches": True,
    "digest_file_matches_manifest": True
  },
  "measurements": {
    "kaniko_digest_file": digest_file,
    "index_sha256": digest(index_raw),
    "manifest_digest": manifest_desc["digest"],
    "manifest_size": len(manifest_raw),
    "config_digest": manifest["config"]["digest"],
    "config_size": len(config_raw),
    "layer_digest": layers[0]["digest"],
    "layer_size": len(layer_raw),
    "layer_diff_id": config["rootfs"]["diff_ids"][0],
    "config_created": config.get("created"),
    "history_created": [entry.get("created") for entry in config.get("history", [])],
    "layer_tar_members": [{"name": m.name, "size": m.size, "mtime": m.mtime,
                           "mode": m.mode, "uid": m.uid, "gid": m.gid} for m in members]
  }
}, sort_keys=True))
'''


def pod(name, containers, *, init_containers=None, volumes=None, **spec):
    pod_spec = {"restartPolicy": "Never", "containers": containers, **spec}
    if init_containers:
        pod_spec["initContainers"] = init_containers
    if volumes:
        pod_spec["volumes"] = volumes
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": pod_spec}


def compliant_pod():
    return pod("compliant-no-hostpath", [{
        "name": "probe", "image": BUSYBOX_IMAGE,
        "command": ["sh", "-c", "sleep 3600"],
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
    }], automountServiceAccountToken=False)


def build_without_socket(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "saf-daemonless-build-context"},
                "data": {"Dockerfile": "FROM scratch\nCOPY fixture.txt /fixture.txt\n",
                         "fixture.txt": FIXTURE_TEXT}})
    security = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                "seccompProfile": {"type": "RuntimeDefault"}}
    output = {"name": "out", "mountPath": "/build-out"}
    build = {"name": "build", "image": KANIKO_IMAGE, "command": ["/kaniko/executor"],
             "args": ["--context=dir:///build-input", "--dockerfile=/build-input/Dockerfile",
                      "--destination=example.invalid/saf/control:local", "--no-push",
                      "--no-push-cache", "--cache=false", "--reproducible",
                      "--tar-path=/build-out/image.tar", "--oci-layout-path=/build-out/oci",
                      "--digest-file=/build-out/digest"],
             "volumeMounts": [{"name": "input", "mountPath": "/build-input", "readOnly": True}, output],
             "securityContext": {**security, "runAsUser": 0, "runAsGroup": 65534}}
    inspect = {"name": "inspect", "image": PYTHON_IMAGE, "command": ["python", "-c", OCI_INSPECT],
               "volumeMounts": [{**output, "readOnly": True}], "securityContext": security}
    stage = {"name": "stage", "image": BUSYBOX_IMAGE,
             "command": ["sh", "-c", "cp -L /source/Dockerfile /source/fixture.txt /staged"],
             "securityContext": {**security, "runAsUser": 0, "runAsGroup": 65534},
             "volumeMounts": [{"name": "source", "mountPath": "/source", "readOnly": True},
                              {"name": "input", "mountPath": "/staged"}]}
    resource = pod("daemonless-ci-build", [inspect], init_containers=[stage, build],
                   automountServiceAccountToken=False, securityContext={"fsGroup": 65534},
                   volumes=[{"name": "source", "configMap": {"name": "saf-daemonless-build-context"}},
                            {"name": "input", "emptyDir": {}}, {"name": "out", "emptyDir": {}}])
    rendered = lab.create(resource)
    host_paths = [volume["name"] for volume in rendered["spec"]["volumes"] if "hostPath" in volume]
    builder = next(container for container in rendered["spec"]["initContainers"]
                   if container["name"] == "build")
    mount_paths = [mount["mountPath"] for mount in builder.get("volumeMounts", [])]
    no_runtime_socket_mounts = not any(
        path == "/run" or path.startswith("/run/") or path == "/var/run"
        or path.startswith("/var/run/") for path in mount_paths)
    deadline = time.monotonic() + 120
    while True:
        current = json.loads(lab.kubectl("get", "pod/daemonless-ci-build", "-o", "json").stdout)
        phase = current["status"].get("phase")
        if phase in ("Failed", "Succeeded") or time.monotonic() >= deadline:
            break
        time.sleep(1)
    if phase != "Succeeded":
        for name in ("stage", "build", "inspect"):
            lab.kubectl("logs", "daemonless-ci-build", "-c", name, allow_failure=True)
        lab.block("The synthetic daemonless build did not reach Succeeded")
    proof_text = lab.kubectl("logs", "daemonless-ci-build", "-c", "inspect").stdout.strip()
    try:
        proof = json.loads(proof_text)
    except json.JSONDecodeError as error:
        lab.block(f"Image inspection did not produce valid structured evidence: {error}")
    # Retain actual digests, sizes, timestamps, and layer metadata before creating
    # the stable observation stored in result.json.
    (lab.evidence / "kaniko-image-measurements.raw.json").write_text(
        json.dumps(proof, indent=2, sort_keys=True) + "\n")
    checks = proof.get("verified", {})
    required = ("one_manifest", "one_layer", "all_descriptor_bytes_match_digest_and_size",
                "oci_payload_matches", "docker_archive_payload_matches",
                "digest_file_matches_manifest", "inspector_has_no_standard_runtime_socket")
    passed = (all(checks.get(key) is True for key in required)
              and checks.get("oci_layout_version") == "1.0.0"
              and checks.get("index_media_type") == "application/vnd.oci.image.index.v1+json"
              and not host_paths and no_runtime_socket_mounts)
    stable = {"valid_oci_layout": checks.get("oci_layout_version") == "1.0.0",
              "single_manifest_and_layer": checks.get("one_manifest") is True and checks.get("one_layer") is True,
              "descriptor_digests_and_sizes_verified": checks.get("all_descriptor_bytes_match_digest_and_size") is True,
              "oci_and_docker_archive_payload_verified": checks.get("oci_payload_matches") is True and checks.get("docker_archive_payload_matches") is True,
              "digest_file_matches_manifest": checks.get("digest_file_matches_manifest") is True,
              "builder_has_no_runtime_socket_mounts": no_runtime_socket_mounts,
              "inspector_has_no_standard_runtime_socket": checks.get("inspector_has_no_standard_runtime_socket") is True,
              "no_hostpath_volumes": not host_paths}
    lab.check("positive", "Pinned daemonless build produces verified OCI and archive payloads without hostPath",
              passed, stable)


def run(lab):
    fixtures = json.loads((Path(__file__).parent / "fixtures.json").read_text())
    # Both deliberately violating Pods are server dry-run requests. No probe is
    # created, scheduled, or run, and paths are harmless nonexistent examples.
    for fixture in fixtures:
        before = lab.create(fixture, dry_run=True, allow_failure=True)
        lab.check("red", f"{fixture['metadata']['name']} is admitted before PSA enforcement",
                  before.returncode == 0, before.stderr.strip() or "server dry-run admitted")

    lab.kubectl("label", "namespace", NAMESPACE,
                "pod-security.kubernetes.io/enforce=baseline",
                "pod-security.kubernetes.io/enforce-version=v1.36", "--overwrite")
    for fixture in fixtures:
        rejected = lab.create(fixture, dry_run=True, allow_failure=True)
        denied = (rejected.returncode != 0 and "(Forbidden)" in rejected.stderr
                  and "violates PodSecurity" in rejected.stderr
                  and "hostPath volumes" in rejected.stderr)
        lab.check("green", f"{fixture['metadata']['name']} is denied by PSA Baseline",
                  denied, rejected.stderr.strip() or "unexpected admission success")

    benign = compliant_pod()
    admitted = lab.create(benign, dry_run=True, allow_failure=True)
    lab.check("positive", "A benign no-hostPath Pod passes server admission dry-run",
              admitted.returncode == 0, admitted.stderr.strip() or "server dry-run admitted")
    lab.create(benign)
    lab.kubectl("wait", "--for=condition=Ready", "pod/compliant-no-hostpath",
                "--timeout=95s", timeout=105)
    lab.check("positive", "The benign no-hostPath Pod reaches Ready", True,
              "Pod/compliant-no-hostpath Ready")
    build_without_socket(lab)
