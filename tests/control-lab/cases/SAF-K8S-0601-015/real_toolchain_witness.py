"""Additive real-toolchain/minimal-runtime witness for SAF-K8S-0601-015."""
import hashlib
import gzip
import io
import json
import re
import struct
import tarfile
import tempfile
import time
from pathlib import Path

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
IMAGE_SOURCE_LABEL = "saf-k8s.example/image-source-sha256"
IMAGE_TARGET_LABEL = "saf-k8s.example/image-target"
IMAGE = "docker.io/library/saf-0601-015-go"
BUILDER = "docker.io/library/golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab"
READY = "saf-0601-015 real minimal image ready v1"


def block(lab, message):
    lab.block(message)


def inspect_elf_static(binary, expected_machine):
    def require(ok, why):
        if not ok:
            raise ValueError(why)
    require(binary[:4] == b"\x7fELF", "runtime executable is not ELF")
    cls, encoding = binary[4], binary[5]
    require(cls in (1, 2) and encoding in (1, 2), "unknown ELF class/endianness")
    endian = "<" if encoding == 1 else ">"
    if cls == 2:
        require(len(binary) >= 64, "truncated ELF64 header")
        machine = struct.unpack_from(endian + "H", binary, 18)[0]
        phoff = struct.unpack_from(endian + "Q", binary, 32)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", binary, 54)
    else:
        require(len(binary) >= 52, "truncated ELF32 header")
        machine = struct.unpack_from(endian + "H", binary, 18)[0]
        phoff = struct.unpack_from(endian + "I", binary, 28)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", binary, 42)
    require(machine == expected_machine, "ELF architecture differs from local target")
    interp = False
    dynamic = False
    for i in range(phnum):
        at = phoff + i * phentsize
        ptype = struct.unpack_from(endian + "I", binary, at)[0]
        interp |= ptype == 3  # PT_INTERP
        dynamic |= ptype == 2  # PT_DYNAMIC
    require(not interp and not dynamic, "runtime executable has dynamic loader/dependencies")
    return {"machine": machine, "elf_class": cls, "interpreter": interp, "dynamic_segment": dynamic}


def verify_oci_descriptor(lab, archive, image, docker_id, arch, config_digest, layer_bytes):
    """Connect Docker's stored image ID to the exact image config and layer."""
    if docker_id == config_digest:
        return  # A classic Docker store identifies the image by its config digest.

    def read_descriptor(descriptor):
        digest = descriptor["digest"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            block(lab, "OCI archive descriptor is not SHA-256 qualified")
        data = archive.extractfile("blobs/sha256/" + digest.split(":", 1)[1]).read()
        if len(data) != descriptor["size"] or "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            block(lab, "OCI archive descriptor does not match its exact bytes")
        return json.loads(data)

    index = json.load(archive.extractfile("index.json"))
    matches = [item for item in index["manifests"] if item["digest"] == docker_id
               and item.get("annotations", {}).get("io.containerd.image.name") == image]
    if len(matches) != 1:
        block(lab, "Saved OCI index does not identify the exact owned Docker image reference")
    manifest = read_descriptor(matches[0])
    if "manifests" in manifest:
        platform = [item for item in manifest["manifests"]
                    if item.get("platform", {}).get("os") == "linux"
                    and item.get("platform", {}).get("architecture") == arch]
        if len(platform) != 1:
            block(lab, "The owned OCI index does not select exactly one local Linux platform")
        manifest = read_descriptor(platform[0])
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    manifest_layers = manifest.get("layers", [])
    if (manifest.get("config", {}).get("digest") != config_digest
            or len(manifest_layers) != 1 or manifest_layers[0].get("digest") != layer_digest
            or manifest_layers[0].get("size") != len(layer_bytes)):
        block(lab, "The selected OCI platform manifest does not bind the saved config and layer")


def build_and_inspect(lab):
    source_hash = hashlib.sha256(b"\0".join(
        path.read_bytes() for path in (HERE / "Dockerfile.go", HERE / "go.mod", HERE / "server.go")
    )).hexdigest()
    image = f"{IMAGE}:{source_hash[:12]}-{lab.cluster[-8:]}"
    # A bounded direct observation binds tool availability to this exact index
    # on every run, independent of whether Docker later reuses a build cache.
    tool_observation = lab.command(
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "/bin/sh", BUILDER,
        "-ceu", 'go version; arch=$(go env GOARCH); test -x "/usr/local/go/pkg/tool/linux_${arch}/compile"; \
          "/usr/local/go/pkg/tool/linux_${arch}/compile" -V; test -x /sbin/apk; apk --version',
        timeout=60,
    )
    build = lab.command("docker", "build", "--no-cache", "--network=none", "--progress=plain",
                        "--target", "go-runtime", "--tag", image,
                        "--label", f"{IMAGE_SOURCE_LABEL}={source_hash}",
                        "--label", f"{IMAGE_TARGET_LABEL}=go-runtime",
                        "--file", str(HERE / "Dockerfile.go"), str(HERE), timeout=900)
    build_output = build.stdout + build.stderr
    if "go version go" not in build_output or "/out/server" not in build_output:
        block(lab, "No-cache real toolchain build log lacks Go version/build output")
    inspected = lab.command("docker", "image", "inspect", image)
    record, = json.loads(inspected.stdout)
    config = record.get("Config", {})
    labels = config.get("Labels") or {}
    layers = record.get("RootFS", {}).get("Layers", [])
    if labels.get(IMAGE_SOURCE_LABEL) != source_hash or labels.get(IMAGE_TARGET_LABEL) != "go-runtime":
        block(lab, "Real-toolchain image is not bound to exact fixture source/target")
    if config.get("User") != "65532:65532" or config.get("Entrypoint") != ["/server"]:
        block(lab, "Final scratch OCI config is not numeric non-root with only /server entrypoint")
    env = config.get("Env") or []
    allowed_path = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    if env not in ([], [allowed_path]):
        block(lab, "Final scratch OCI config unexpectedly declares non-default environment dependencies")
    if not layers or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in layers):
        block(lab, "Docker did not return digest-qualified runtime rootfs diff IDs")

    # Save only the final (small) image once and inspect the exact layer tar.
    # This validates the actual exported image filesystem, unlike docker export,
    # which synthesizes container runtime files such as /etc/hosts and .dockerenv.
    with tempfile.TemporaryDirectory(prefix="saf-go-runtime-oci-") as directory:
        archive_path = Path(directory) / "runtime-image.tar"
        lab.command("docker", "image", "save", "--output", str(archive_path), image, timeout=90)
        with tarfile.open(archive_path, "r:*") as saved:
            manifest_rows = json.load(saved.extractfile("manifest.json"))
            if len(manifest_rows) != 1:
                block(lab, "Final OCI export did not resolve exactly one platform image")
            manifest = manifest_rows[0]
            if len(manifest.get("Layers", [])) != 1:
                block(lab, "Final scratch image must consist of one content layer")
            config_bytes = saved.extractfile(manifest["Config"]).read()
            config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
            if image.removeprefix("docker.io/library/") not in manifest.get("RepoTags", []):
                block(lab, "Docker archive did not save the exact uniquely tagged fixture")
            saved_config = json.loads(config_bytes)
            if saved_config.get("rootfs", {}).get("diff_ids") != layers:
                block(lab, "Saved OCI config diff IDs differ from local image inspection")
            layer_bytes = saved.extractfile(manifest["Layers"][0]).read()
            verify_oci_descriptor(lab, saved, image, record.get("Id"), record.get("Architecture"),
                                  config_digest, layer_bytes)
        uncompressed_layer = gzip.decompress(layer_bytes) if layer_bytes[:2] == b"\x1f\x8b" else layer_bytes
        if "sha256:" + hashlib.sha256(uncompressed_layer).hexdigest() != layers[0]:
            block(lab, "Saved OCI layer bytes do not match the exact uncompressed diff ID")
        with tarfile.open(fileobj=io.BytesIO(uncompressed_layer), mode="r:") as layer:
            members = [m for m in layer.getmembers() if m.isfile() or m.issym() or m.islnk()]
            names = sorted(m.name.lstrip("./").lstrip("/") for m in members)
            server_member = next((m for m in members if m.name.lstrip("./").lstrip("/") == "server"), None)
            server = layer.extractfile(server_member).read() if server_member is not None else b""
            if names != ["server"] or server_member is None or not (server_member.mode & 0o111):
                block(lab, "Final scratch OCI layer must contain only executable /server")
            if server_member.uid != 65532 or server_member.gid != 65532:
                block(lab, "Final OCI server file is not owned by numeric UID/GID 65532")
    lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=180)
    architecture = record.get("Architecture")
    expected_machine = {"amd64": 62, "arm64": 183}.get(architecture)
    if expected_machine is None:
        block(lab, "Runtime image reports an unsupported local architecture")
    try:
        elf = inspect_elf_static(server, expected_machine)
    except (ValueError, struct.error) as error:
        block(lab, f"Runtime executable failed static ELF inspection ({type(error).__name__})")
    return {"reference": image, "source_sha256": source_hash, "image_id": config_digest, "docker_reference_id": record.get("Id"),
            "architecture": architecture, "config_user": config.get("User"),
            "entrypoint": config.get("Entrypoint"), "rootfs_diff_ids": layers,
            "runtime_regular_files": names, "server_sha256": hashlib.sha256(server).hexdigest(),
            "elf_static": elf, "builder": BUILDER,
            "build_log_has_go_version": "go version" in build_output,
            "toolchain_probe_stdout": tool_observation.stdout.strip(),
            "build_log_sha256": hashlib.sha256(build_output.encode()).hexdigest(),
            "toolchain_proof": "Every run executes the exact pinned builder with networking disabled and checks Go, compiler and apk; a no-cache offline image build then compiles the fixture."}


def runtime_probe(lab, image_record, busybox_image, namespace):
    name = "fixture-go-minimal-readiness"
    probe = (
        "set -eu; n=0; while [ \"$n\" -lt 90 ]; do "
        f"body=$(/bin/busybox wget -qO- http://127.0.0.1:8080/healthz 2>/dev/null || true); "
        f"identity=$(/bin/busybox wget -qO- http://127.0.0.1:8080/identity 2>/dev/null || true); "
        f"if [ \"$body\" = {json.dumps(READY)} ] && [ \"$identity\" = '65532:65532' ]; then printf '%s|%s\\n' \"$body\" \"$identity\"; exit 0; fi; "
        "n=$((n+1)); sleep 1; done; exit 1"
    )
    server = container("server", image=image_record["reference"], imagePullPolicy="Never",
                       ports=[{"name": "http", "containerPort": 8080}],
                       resources={"requests": {"cpu": "10m", "memory": "16Mi"},
                                  "limits": {"cpu": "50m", "memory": "32Mi"}},
                       securityContext={"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                                        "allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]}})
    # The shared fixture helper supplies a shell sleep command by default;
    # remove it so this image's sole /server entrypoint actually runs.
    server.pop("command", None)
    observer = container("observer", image=busybox_image, imagePullPolicy="IfNotPresent",
                         command=["/bin/busybox", "sh", "-c", probe],
                         resources={"requests": {"cpu": "10m", "memory": "16Mi"},
                                    "limits": {"cpu": "50m", "memory": "32Mi"}})
    resource = pod(name, [server, observer], automountServiceAccountToken=False)
    resource["spec"].update({"restartPolicy": "Never",
                             "securityContext": {"runAsNonRoot": True,
                                                 "seccompProfile": {"type": "RuntimeDefault"}}})
    lab.create(resource)
    deadline = time.monotonic() + 110
    observed = None
    while time.monotonic() < deadline:
        observed = json.loads(lab.kubectl("get", f"pod/{name}", "-o", "json").stdout)
        statuses = {item["name"]: item for item in observed.get("status", {}).get("containerStatuses", [])}
        if statuses.get("observer", {}).get("state", {}).get("terminated"):
            break
        if observed.get("status", {}).get("phase") == "Failed":
            break
        time.sleep(1)
    statuses = {item["name"]: item for item in observed.get("status", {}).get("containerStatuses", [])}
    observer_status = statuses.get("observer", {})
    server_status = statuses.get("server", {})
    observer_logs = lab.kubectl("logs", f"pod/{name}", "-c", "observer", allow_failure=True)
    node_name = observed.get("spec", {}).get("nodeName", "")
    if not node_name.startswith(lab.cluster + "-"):
        block(lab, "Readiness witness Pod was not scheduled on an owned Kind node")
    if observer_status.get("state", {}).get("terminated", {}).get("exitCode") != 0 or \
       observer_logs.stdout.strip() != READY + "|65532:65532":
        block(lab, "Owned Kind Pod did not observe the exact fixed HTTP health marker")
    if not server_status.get("ready") or not re.search(r"sha256:[0-9a-f]{64}$", server_status.get("imageID", "")):
        block(lab, "The running server container is not ready or its runtime image ID is not digest-qualified")
    node = node_name
    cri = json.loads(lab.command("docker", "exec", node, "crictl", "inspecti", image_record["reference"], timeout=25).stdout)
    image_spec = cri["info"]["imageSpec"]
    if isinstance(image_spec, str):
        image_spec = json.loads(image_spec)
    cri_config_id = cri["status"].get("id", "")
    if cri_config_id != image_record["image_id"] or image_spec.get("rootfs", {}).get("diff_ids") != image_record["rootfs_diff_ids"]:
        block(lab, "Owned Kind CRI config ID/diff IDs do not match the locally inspected image")
    observation = {"pod": name, "pod_uid": observed["metadata"]["uid"], "node": node_name,
                   "requested_image": image_record["reference"], "server_image_id": server_status.get("imageID"),
                   "observer_exit_code": observer_status.get("state", {}).get("terminated", {}).get("exitCode"),
                   "health_marker_and_identity": observer_logs.stdout.strip(), "observed_process_uid_gid": "65532:65532",
                   "security_context_run_as_non_root": True, "run_as_uid": 65532, "run_as_gid": 65532,
                   "cri_config_id": cri_config_id,
                   "cri_diff_ids_match": True}
    lab.kubectl("delete", "pod", name, "--wait=true", timeout=45)
    return observation


def run(lab, busybox_image, namespace):
    source_hash = hashlib.sha256(b"\0".join(
        path.read_bytes() for path in (HERE / "Dockerfile.go", HERE / "go.mod", HERE / "server.go")
    )).hexdigest()
    transient_image = f"{IMAGE}:{source_hash[:12]}-{lab.cluster[-8:]}"
    image = None
    try:
        image = build_and_inspect(lab)
        runtime = runtime_probe(lab, image, busybox_image, namespace)
        predicates = {
            "pinned_multiplatform_real_go_builder_declared": image["builder"] == BUILDER,
            "builder_compiler_checks_and_offline_build_completed": bool(image["toolchain_probe_stdout"]) and image["build_log_has_go_version"],
            "final_scratch_rootfs_contains_only_executable_server": image["runtime_regular_files"] == ["server"],
            "final_config_uses_numeric_nonroot_uid_and_server_entrypoint": (
                image["config_user"] == "65532:65532" and image["entrypoint"] == ["/server"]
            ),
            "final_binary_is_static_for_reported_architecture": image["elf_static"]["interpreter"] is False and image["elf_static"]["dynamic_segment"] is False,
            "owned_kind_runtime_serves_exact_health_marker_and_reports_actual_uid_gid": runtime["health_marker_and_identity"] == READY + "|65532:65532",
            "runtime_server_is_ready_and_cri_matches_config_and_layers": runtime["cri_diff_ids_match"],
        "actual_uid_gid_match_numeric_oci_identity": runtime["health_marker_and_identity"] == READY + "|65532:65532",
        }
        lab.check("positive", "Pinned Go builder produces a minimal non-root image that serves its fixed marker",
                  all(predicates.values()), predicates)
        evidence = {"scope": "scratch fixture only; local builder and one owned Kind node",
                    "builder_image": BUILDER, "image": image, "runtime": runtime,
                    "predicates": predicates,
                    "limitations": ["does not qualify production inference images",
                                    "does not establish GPU/CUDA/driver compatibility",
                                    "does not establish signed provenance, registry promotion, or adoption"]}
        (lab.evidence / "real-toolchain-minimal-image.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    finally:
        # The cluster has its own loaded copy; remove the unique host tag on both
        # success and failure so concurrent cases cannot leave shared state.
        lab.command("docker", "image", "rm", transient_image, timeout=45, allow_failure=True)
