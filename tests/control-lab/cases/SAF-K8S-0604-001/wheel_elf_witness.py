"""Additive pinned wheel/native ELF and Syft file-inventory witness."""
import base64
import gzip
import hashlib
import importlib.util
import json
import platform
import re
import tarfile
from pathlib import Path

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
PYTHON = ("docker.io/library/python:3.13-slim@sha256:"
          "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
SYFT = ("ghcr.io/anchore/syft:v1.57.1@sha256:"
        "03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060")
SKOPEO = ("quay.io/skopeo/stable:v1.20.0@sha256:"
          "47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4")
WHEELS = {
    "arm64": {
        "filename": "psutil-7.2.2-cp36-abi3-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64.whl",
        "url": "https://files.pythonhosted.org/packages/63/65/37648c0c158dc222aba51c089eb3bdfa238e621674dc42d48706e639204f/psutil-7.2.2-cp36-abi3-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64.whl",
        "sha256": "b0726cecd84f9474419d67252add4ac0cd9811b04d61123054b9fb6f57df6e9e",
        "machine": 183,
    },
    "amd64": {
        "filename": "psutil-7.2.2-cp36-abi3-manylinux2010_x86_64.manylinux_2_12_x86_64.manylinux_2_28_x86_64.whl",
        "url": "https://files.pythonhosted.org/packages/b5/70/5d8df3b09e25bce090399cf48e452d25c935ab72dad19406c77f4e828045/psutil-7.2.2-cp36-abi3-manylinux2010_x86_64.manylinux_2_12_x86_64.manylinux_2_28_x86_64.whl",
        "sha256": "076a2d2f923fd4821644f5ba89f059523da90dc9014e85f8e45a5774ca5bc6f9",
        "machine": 62,
    },
}


def _descriptor_bytes(lab, archive, descriptor):
    digest = descriptor.get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        lab.block("Docker OCI archive descriptor is not SHA-256 qualified")
    member = archive.extractfile("blobs/sha256/" + digest.split(":", 1)[1])
    if member is None:
        lab.block("Docker OCI archive is missing a referenced descriptor blob")
    data = member.read()
    if len(data) != descriptor.get("size") or "sha256:" + hashlib.sha256(data).hexdigest() != digest:
        lab.block("Docker OCI descriptor does not match its exact bytes")
    return data


def _layer_diff_id(layer_bytes):
    raw = gzip.decompress(layer_bytes) if layer_bytes[:2] == b"\x1f\x8b" else layer_bytes
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def verify_oci_descriptor(lab, archive, image, docker_id, arch, config_digest,
                          config_diff_ids, archive_layers):
    """Link modern containerd Docker Id/index identity to exact saved image config and layers."""
    if docker_id == config_digest:
        relation = "classic-config-digest"
        selected_manifest_digest = None
    else:
        try:
            index = json.load(archive.extractfile("index.json"))
        except (KeyError, TypeError, json.JSONDecodeError):
            lab.block("Docker image ID is not its config digest and no OCI index explains it")
        matches = [item for item in index.get("manifests", [])
                   if item.get("digest") == docker_id
                   and item.get("annotations", {}).get("io.containerd.image.name") == image]
        if len(matches) != 1:
            lab.block("Saved OCI index does not bind the Docker image ID to the exact local tag")
        top = matches[0]
        top_bytes = _descriptor_bytes(lab, archive, top)
        top_obj = json.loads(top_bytes)
        selected = top
        manifest = top_obj
        if "manifests" in top_obj:
            platforms = [item for item in top_obj["manifests"]
                         if item.get("platform", {}).get("os") == "linux"
                         and item.get("platform", {}).get("architecture") == arch]
            if len(platforms) != 1:
                lab.block("Docker image index does not select exactly one local Linux platform")
            selected = platforms[0]
            manifest = json.loads(_descriptor_bytes(lab, archive, selected))
        elif top.get("platform") and (top["platform"].get("os") != "linux"
                                       or top["platform"].get("architecture") != arch):
            lab.block("Docker image descriptor platform differs from the local architecture")
        selected_manifest_digest = selected.get("digest")
        relation = "containerd-image-index"
        if manifest.get("config", {}).get("digest") != config_digest:
            lab.block("Selected Docker OCI platform manifest points at a different image config")
        descriptors = manifest.get("layers", [])
        if len(descriptors) != len(archive_layers) or len(descriptors) != len(config_diff_ids):
            lab.block("Selected Docker OCI platform manifest layer count differs from config/archive")
        for descriptor, layer_bytes, expected_diff_id in zip(descriptors, archive_layers, config_diff_ids):
            _descriptor_bytes(lab, archive, descriptor)
            if "sha256:" + hashlib.sha256(layer_bytes).hexdigest() != descriptor.get("digest"):
                lab.block("Docker archive layer bytes differ from the selected OCI manifest layer")
            if _layer_diff_id(layer_bytes) != expected_diff_id:
                lab.block("Docker archive layer bytes differ from the config diff ID")
    if len(archive_layers) != len(config_diff_ids):
        lab.block("Docker image archive layers differ in count from its config diff IDs")
    if any(_layer_diff_id(layer) != expected
           for layer, expected in zip(archive_layers, config_diff_ids)):
        lab.block("Docker image archive bytes do not reproduce the exact config diff IDs")
    return {"docker_id_relation": relation,
            "docker_reference_id": docker_id,
            "selected_platform_manifest_digest": selected_manifest_digest,
            "config_digest": config_digest,
            "config_diff_ids": config_diff_ids,
            "layer_count": len(archive_layers)}


def _layout_blob_path(layout, digest):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("unqualified OCI blob digest")
    return layout / "blobs" / "sha256" / digest.split(":", 1)[1]


def _write_exact_docker_oci_layout(lab, archive, layout, image, docker_id, arch,
                                   config_digest, config_diff_ids, archive_layers):
    """Reconstruct an OCI layout from Docker's verified native index chain and bytes."""
    try:
        index = json.load(archive.extractfile("index.json"))
    except (KeyError, TypeError, json.JSONDecodeError):
        lab.block("Docker image save did not include its native OCI index")
    matches = [entry for entry in index.get("manifests", [])
               if entry.get("digest") == docker_id
               and entry.get("annotations", {}).get("io.containerd.image.name") == image]
    if len(matches) != 1:
        lab.block("Docker native OCI index does not identify the exact tagged image")
    top = matches[0]
    top_obj = json.loads(_descriptor_bytes(lab, archive, top))
    if "manifests" in top_obj:
        platforms = [entry for entry in top_obj.get("manifests", [])
                     if entry.get("platform", {}).get("os") == "linux"
                     and entry.get("platform", {}).get("architecture") == arch]
        if len(platforms) != 1:
            lab.block("Docker native OCI index does not select exactly one local Linux platform")
        selected = platforms[0]
        manifest_bytes = _descriptor_bytes(lab, archive, selected)
        manifest = json.loads(manifest_bytes)
    else:
        if top.get("platform") and (top["platform"].get("os") != "linux"
                                     or top["platform"].get("architecture") != arch):
            lab.block("Docker native OCI descriptor platform differs from the local architecture")
        selected = top
        manifest_bytes = _descriptor_bytes(lab, archive, selected)
        manifest = json.loads(manifest_bytes)
        if "manifests" in manifest:
            lab.block("Docker native OCI descriptor did not resolve to a platform manifest")
    if manifest.get("config", {}).get("digest") != config_digest:
        lab.block("Selected native OCI manifest does not point to the exact saved image config")
    config_bytes = _descriptor_bytes(lab, archive, manifest["config"])
    config = json.loads(config_bytes)
    if "sha256:" + hashlib.sha256(config_bytes).hexdigest() != config_digest:
        lab.block("Native OCI image config bytes do not match Docker's config digest")
    layers = manifest.get("layers", [])
    if len(layers) != len(archive_layers) or len(layers) != len(config_diff_ids):
        lab.block("Native OCI manifest, Docker archive, and config layer counts differ")
    layer_bytes = []
    for descriptor, archived_layer, expected_diff_id in zip(layers, archive_layers, config_diff_ids):
        data = _descriptor_bytes(lab, archive, descriptor)
        if data != archived_layer:
            lab.block("Native OCI layer differs from the exact Docker archive layer")
        if _layer_diff_id(data) != expected_diff_id:
            lab.block("Native OCI layer bytes differ from Docker config diff ID")
        layer_bytes.append(data)
    if config.get("rootfs", {}).get("diff_ids") != config_diff_ids:
        lab.block("Native OCI config diff IDs differ from Docker image inspection")

    layout.mkdir(mode=0o700, parents=False, exist_ok=False)
    blob_dir = layout / "blobs" / "sha256"
    blob_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    payloads = [(selected.get("digest"), manifest_bytes),
                (manifest["config"].get("digest"), config_bytes)]
    payloads.extend((descriptor.get("digest"), data) for descriptor, data in zip(layers, layer_bytes))
    for digest, data in payloads:
        path = _layout_blob_path(layout, digest)
        if ("sha256:" + hashlib.sha256(data).hexdigest()) != digest:
            lab.block("Native Docker OCI blob failed digest validation before layout write")
        path.write_bytes(data)

    descriptor = dict(selected)
    annotations = dict(descriptor.get("annotations") or {})
    annotations["org.opencontainers.image.ref.name"] = "wheel"
    descriptor["annotations"] = annotations
    layout_index = {"schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [descriptor]}
    (layout / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"},
                                                    sort_keys=True, separators=(",", ":")) + "\n")
    (layout / "index.json").write_text(json.dumps(layout_index, sort_keys=True,
                                                    separators=(",", ":")) + "\n")
    return selected["digest"], manifest, config


def _verify_native_layout(layout, manifest_digest, config_digest, config_diff_ids):
    index = json.loads((layout / "index.json").read_text())
    entries = index.get("manifests", [])
    if len(entries) != 1 or entries[0].get("digest") != manifest_digest:
        raise ValueError("Reconstructed OCI index does not identify its exact selected manifest")
    if entries[0].get("annotations", {}).get("org.opencontainers.image.ref.name") != "wheel":
        raise ValueError("Reconstructed OCI index lacks its exact wheel reference annotation")
    def read(descriptor):
        digest = descriptor.get("digest", "")
        path = _layout_blob_path(layout, digest)
        data = path.read_bytes()
        if len(data) != descriptor.get("size", len(data)) or "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Reconstructed OCI blob differs from its descriptor")
        return data
    manifest_bytes = read(entries[0])
    manifest = json.loads(manifest_bytes)
    config_descriptor = manifest.get("config", {})
    if config_descriptor.get("digest") != config_digest:
        raise ValueError("Reconstructed OCI manifest changed the exact config descriptor")
    config = json.loads(read(config_descriptor))
    if config.get("rootfs", {}).get("diff_ids") != config_diff_ids:
        raise ValueError("Reconstructed OCI config differs from saved Docker diff IDs")
    layers = manifest.get("layers", [])
    if len(layers) != len(config_diff_ids):
        raise ValueError("Reconstructed OCI manifest layer count differs from config")
    for descriptor, expected in zip(layers, config_diff_ids):
        if _layer_diff_id(read(descriptor)) != expected:
            raise ValueError("Reconstructed OCI layer does not reproduce exact config diff ID")
    return manifest

def _write_fixture(root, wheel):
    dockerfile = root / "Containerfile"
    wheel_sha = wheel["sha256"]
    wheel_url = wheel["url"]
    filename = wheel_url.rsplit("/", 1)[-1]
    if not re.fullmatch(r"psutil-[0-9.]+-[A-Za-z0-9_.-]+\.whl", filename):
        raise ValueError("Pinned wheel URL does not have a valid official filename")
    dockerfile.write_text(f"""# syntax=docker/dockerfile:1.7
FROM {PYTHON}
ADD --checksum=sha256:{wheel_sha} {wheel_url} /tmp/{filename}
COPY wheel_probe.py /fixture/wheel_probe.py
RUN python -m pip install --no-index --no-deps --disable-pip-version-check /tmp/{filename} && rm -f /tmp/{filename}
ENV PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
CMD ["python", "/fixture/wheel_probe.py"]
""")
    (root / "wheel_probe.py").write_bytes((HERE / "wheel_probe.py").read_bytes())
    return dockerfile


def _runtime_probe(registry, image, manifest_digest, expected):
    lab = registry.lab
    name = "saf-0604-001-wheel-native"
    container_spec = container(
        "workload", image=image, imagePullPolicy="Always",
        command=["python", "/fixture/wheel_probe.py"],
        resources={"requests": {"cpu": "10m", "memory": "24Mi"},
                   "limits": {"cpu": "100m", "memory": "96Mi"}},
        securityContext={"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                         "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                         "capabilities": {"drop": ["ALL"]}},
    )
    resource = pod(name, [container_spec], automountServiceAccountToken=False)
    resource["spec"]["securityContext"] = {
        "runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    lab.create(resource)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                "--timeout=85s", timeout=95)
    status = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)["status"]
    image_id = status["containerStatuses"][0].get("imageID", "")
    exact = image_id.endswith(manifest_digest)
    try:
        observed = json.loads(lab.kubectl("logs", name).stdout.strip())
    except json.JSONDecodeError:
        lab.block("Wheel native-extension runtime did not produce its bounded JSON observation")
    lab.kubectl("delete", "pod", name, "--wait=true", timeout=45)
    comparable = {
        "distribution": observed.get("distribution") == expected.get("distribution"),
        "version": observed.get("version") == expected.get("version"),
        "native_module": observed.get("native_module") == expected.get("native_module"),
        "record_hash_algorithm": observed.get("record_hash_algorithm") == expected.get("record_hash_algorithm"),
        "native_elf_machine": observed.get("native_elf", {}).get("machine") == expected.get("native_elf", {}).get("machine"),
        "native_elf_is_dynamic_shared_object": observed.get("native_elf", {}).get("has_dynamic_segment") is True
            and observed.get("native_elf", {}).get("has_interpreter") is False,
    }
    valid = (exact and all(comparable.values()) and observed.get("native_loaded") is True
             and observed.get("safe_runtime_result", {}).get("current_process_name_nonempty") is True
             and observed.get("safe_runtime_result", {}).get("thread_count_positive") is True)
    observation = {"requested_image": image, "runtime_image_id": image_id,
                   "exact_manifest_runtime": exact, "same_native_extension_evidence": comparable,
                   "native_loaded": observed.get("native_loaded"),
                   "safe_runtime_result": observed.get("safe_runtime_result"),
                   "native_sha256": observed.get("native_elf", {}).get("sha256"),
                   "record_to_elf_match": observed.get("record_hash_value") is not None
                       and observed.get("record_hash_algorithm") == "sha256"
                       and observed.get("native_elf", {}).get("sha256") is not None}
    return valid, observation, observed


def run(registry, host_port):
    lab = registry.lab
    arch_text = registry.docker("info", "--format", "{{.Architecture}}").stdout.strip().lower()
    arch = {"aarch64": "arm64", "arm64": "arm64",
            "x86_64": "amd64", "amd64": "amd64"}.get(arch_text)
    if arch not in WHEELS:
        lab.block("No pinned psutil ABI3 wheel is staged for the active Docker architecture")
    wheel = WHEELS[arch]
    root = registry.work / "wheel-native"
    root.mkdir(mode=0o700)
    dockerfile = _write_fixture(root, wheel)
    probe_bytes = (root / "wheel_probe.py").read_bytes()
    source_hash = hashlib.sha256(dockerfile.read_bytes() + b"\0" + probe_bytes).hexdigest()
    tag = f"docker.io/library/{registry.lab.cluster}-wheel-native:{source_hash[:16]}"
    repo = f"{registry.registry}/fixture/wheel-native"
    target = f"{repo}:case"
    try:
        registry.docker("build", "--network", "none", "--tag", tag, "--file", str(dockerfile), str(root), timeout=300)
        docker_record, = json.loads(registry.docker("image", "inspect", tag).stdout)
        docker_reference_id = docker_record.get("Id", "")
        docker_arch = docker_record.get("Architecture", "")
        docker_rootfs_diff_ids = docker_record.get("RootFS", {}).get("Layers", [])
        registry.docker("image", "save", "--output", str(root / "image.tar"), tag, timeout=90)
        with tarfile.open(root / "image.tar", "r:*") as saved:
            manifest_rows = json.load(saved.extractfile("manifest.json"))
            if len(manifest_rows) != 1:
                lab.block("Docker archive did not resolve exactly one platform image")
            docker_manifest = manifest_rows[0]
            saved_tags = docker_manifest.get("RepoTags", [])
            if tag not in saved_tags and tag.removeprefix("docker.io/library/") not in saved_tags:
                lab.block("Docker archive did not save the exact uniquely tagged wheel image")
            docker_config_bytes = saved.extractfile(docker_manifest["Config"]).read()
            docker_config_digest = "sha256:" + hashlib.sha256(docker_config_bytes).hexdigest()
            docker_config = json.loads(docker_config_bytes)
            archive_layers = [saved.extractfile(name).read() for name in docker_manifest.get("Layers", [])]
            docker_config_diff_ids = docker_config.get("rootfs", {}).get("diff_ids", [])
            if docker_config_diff_ids != docker_rootfs_diff_ids:
                lab.block("Saved image config diff IDs differ from modern Docker image inspection")
            docker_identity = verify_oci_descriptor(
                lab, saved, tag, docker_reference_id, docker_arch, docker_config_digest,
                docker_config_diff_ids, archive_layers)
            layout = root / "layout"
            manifest_digest, manifest, image_config = _write_exact_docker_oci_layout(
                lab, saved, layout, tag, docker_reference_id, docker_arch,
                docker_config_digest, docker_config_diff_ids, archive_layers)
            if manifest_digest != docker_identity.get("selected_platform_manifest_digest"):
                lab.block("Reconstructed OCI layout selected a different native platform manifest")
        (root / "image.tar").unlink()
        config_digest = docker_config_digest
        diff_ids = image_config.get("rootfs", {}).get("diff_ids", [])
        docker_rootfs_diff_ids = docker_record.get("RootFS", {}).get("Layers", [])
        if diff_ids != docker_rootfs_diff_ids or diff_ids != docker_identity.get("config_diff_ids"):
            lab.block("Reconstructed OCI diff IDs differ from Docker's exact config and image inspection")
        try:
            verified_manifest = _verify_native_layout(
                layout, manifest_digest, docker_config_digest, docker_config_diff_ids)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            lab.block(f"Reconstructed native Docker OCI layout failed descriptor validation: {error}")
        if verified_manifest != manifest:
            lab.block("Reconstructed OCI layout manifest differs from the exact selected Docker manifest")
        scan = registry.docker(
            "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL",
            "--env", "SYFT_FILE_METADATA_SELECTION=all",
            "--env", "SYFT_FILE_METADATA_DIGESTS=sha256",
            "--tmpfs", "/tmp:rw,nosuid,nodev", "--volume", f"{root / 'layout'}:/scan:ro",
            SYFT, "scan", "oci-dir:/scan", "--output", "syft-json", timeout=150,
        )
        syft = json.loads(scan.stdout)
        if syft.get("source", {}).get("metadata", {}).get("manifestDigest") != manifest_digest:
            lab.block("Syft did not inventory the exact pinned wheel image manifest")
        artifacts = [row for row in syft.get("artifacts", [])
                     if row.get("name", "").lower() == "psutil" and row.get("version") == "7.2.2"]
        if len(artifacts) != 1:
            lab.block("Syft did not report exactly one psutil 7.2.2 installed package")
        files = syft.get("files", [])
        native_files = [row for row in files
                        if row.get("location", {}).get("path", "").replace("\\", "/")
                        .endswith("psutil/_psutil_linux.abi3.so")]
        if len(native_files) != 1:
            lab.block("Syft did not report exactly one psutil wheel-bundled ELF file")
        native_file = native_files[0]
        executable = native_file.get("executable") or {}
        file_sha = next((item.get("value") for item in native_file.get("digests", [])
                         if item.get("algorithm", "").lower() == "sha256"), None)
        if str(executable.get("format", "")).casefold() != "elf" or file_sha is None:
            lab.block("Syft full-file inventory omitted ELF classification or a SHA-256 digest")
        (lab.evidence / "wheel-native-syft.json").write_text(
            json.dumps(syft, sort_keys=True, indent=2) + "\n")
        bom_result = registry.docker(
            "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL",
            "--env", "SYFT_FILE_METADATA_SELECTION=all",
            "--env", "SYFT_FILE_METADATA_DIGESTS=sha256",
            "--tmpfs", "/tmp:rw,nosuid,nodev", "--volume", f"{root / 'layout'}:/scan:ro",
            SYFT, "scan", "oci-dir:/scan", "--output", "cyclonedx-json", timeout=150,
        )
        bom = json.loads(bom_result.stdout)
        bom_packages = [row for row in bom.get("components", [])
                        if row.get("name", "").lower() == "psutil" and row.get("version") == "7.2.2"]
        if len(bom_packages) != 1:
            lab.block("CycloneDX did not include the exact psutil wheel package version")
        (lab.evidence / "wheel-native-cyclonedx.json").write_text(
            json.dumps(bom, sort_keys=True, indent=2) + "\n")

        (root / "ca.crt").write_bytes(registry.registry_ca.read_bytes())
        registry.docker("run", "--rm", "--network", "kind", "--cap-drop=ALL",
                        "--security-opt=no-new-privileges", "--volume", f"{root}:/io",
                        SKOPEO, "copy", "--preserve-digests", "--dest-cert-dir", "/io",
                        "--digestfile", "/io/published.digest", "oci:/io/layout:wheel",
                        f"docker://{target}", timeout=140)
        if (root / "published.digest").read_text().strip() != manifest_digest:
            lab.block("Published local-registry manifest differs from the Syft-scanned wheel image")
        runtime_ref = f"{repo}@{manifest_digest}"
        runtime_ok, runtime_observation, runtime_data = _runtime_probe(
            registry, runtime_ref, manifest_digest,
            {"distribution": "psutil", "version": "7.2.2",
             "native_module": "psutil/_psutil_linux.abi3.so",
             "record_hash_algorithm": "sha256", "native_elf": {"machine": wheel["machine"]}})
        record_value = runtime_data.get("record_hash_value", "")
        record_bytes = base64.urlsafe_b64decode(record_value + "=" * (-len(record_value) % 4))
        runtime_elf_sha = runtime_data.get("native_elf", {}).get("sha256")
        record_matches = (record_bytes.hex() == runtime_elf_sha == file_sha)
        evidence = {
            "scope": "pinned third-party wheel fixture; native file inventory for one exact local OCI image",
            "builder_platform": arch_text,
            "python_image": PYTHON, "scanner": SYFT,
            "wheel": {"project": "psutil", "version": "7.2.2", "filename": wheel["filename"],
                      "url": wheel["url"], "sha256": wheel["sha256"],
                      "pypi_provenance_attestation": False},
            "image": {"reference": runtime_ref, "manifest_digest": manifest_digest,
                      "docker_reference_id": docker_reference_id,
                      "docker_id_relation": docker_identity["docker_id_relation"],
                      "docker_archive_platform_manifest_digest": docker_identity["selected_platform_manifest_digest"],
                      "docker_config_digest": docker_config_digest, "oci_config_digest": config_digest,
                      "rootfs_diff_ids": diff_ids,
                      "docker_inspected_rootfs_diff_ids": docker_rootfs_diff_ids,
                      "fixture_source_sha256": source_hash},
            "syft_package": artifacts[0], "syft_native_file": native_file,
            "syft_native_file_interpretation": (
                "Syft reports the exact extension as a file with ELF metadata and SHA-256 under full-file selection; "
                "Syft did not identify this file itself as a package-owned artifact. The wheel RECORD path and hash "
                "plus the runtime-loaded module independently associate it with psutil."
            ),
            "cyclonedx_component": bom_packages[0],
            "runtime": runtime_observation,
            "wheel_RECORD_to_runtime_ELF": {
                "record_algorithm": runtime_data.get("record_hash_algorithm"),
                "record_hash_value": record_value,
                "record_sha256_hex": record_bytes.hex(),
                "runtime_elf_sha256": runtime_elf_sha,
                "syft_file_sha256": file_sha, "all_match": record_matches},
            "limitations": ["PyPI metadata reports no provenance attestation for this wheel",
                            "does not establish organizational wheel allowlisting or production image adoption",
                            "does not replace platform-specific production SBOM and artifact provenance evidence"],
        }
        lab.check("positive", "Pinned wheel RECORD and runtime ELF digest match Syft's exact file inventory",
                  runtime_ok and record_matches,
                  {"runtime_exact_digest": runtime_observation.get("exact_manifest_runtime"),
                   "Syft_reports_psutil_package": len(artifacts) == 1,
                   "Syft_reports_native_ELF_and_digest": str(executable.get("format", "")).casefold() == "elf" and
                       file_sha == runtime_data.get("native_elf", {}).get("sha256"),
                   "wheel_RECORD_to_native_hash_match": record_matches,
                   "CycloneDX_reports_psutil": len(bom_packages) == 1,
                   "native_runtime_call_succeeded": runtime_data.get("native_loaded")})
        lab.evidence.joinpath("wheel-native-sbom.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n")
        retention_spec = importlib.util.spec_from_file_location(
            "saf_0604_001_sbom_retention", HERE / "sbom_retention.py"
        )
        if retention_spec is None or retention_spec.loader is None:
            lab.block("Could not load the CycloneDX retention witness")
        retention_module = importlib.util.module_from_spec(retention_spec)
        retention_spec.loader.exec_module(retention_module)
        bom_bytes = (lab.evidence / "wheel-native-cyclonedx.json").read_bytes()
        retained, retention_evidence = retention_module.retain_exact_bom(
            lab, registry, host_port, repo.split("/", 1)[1], layout, manifest_digest,
            manifest, bom_bytes
        )
        lab.check(
            "positive",
            "The exact generated wheel CycloneDX bytes are retained as a subject-bound OCI artifact",
            retained,
            {"subject_digest_matches_scanned_manifest":
                 retention_evidence["subject_descriptor"]["digest"] == manifest_digest,
             "referrer_index_contains_artifact":
                 retention_evidence["readback"]["referrers_index_contains_exact_artifact_descriptor"],
             "subject_manifest_readback_matches_exact_scan_subject":
                 retention_evidence["readback"]["subject_manifest_bytes_identical"]
                 and retention_evidence["readback"]["subject_manifest_digest_matches"],
             "artifact_manifest_subject_matches":
                 retention_evidence["readback"]["subject_descriptor_matches"],
             "registry_readback_matches_exact_bom_bytes":
                 retention_evidence["readback"]["sbom_blob_bytes_identical"],
             "registry_readback_digest_matches":
                 retention_evidence["readback"]["sbom_blob_digest_matches"]}
        )
    finally:
        registry.docker("image", "rm", tag, allow_failure=True)
