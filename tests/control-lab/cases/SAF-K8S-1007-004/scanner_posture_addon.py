"""Bounded OSV scan to exact live-Pod subject witness for SAF-K8S-1007-004."""
from hashlib import sha256
import gzip
import importlib.util
import json
from pathlib import Path
import tarfile

OSV_SCANNER = ("ghcr.io/google/osv-scanner:v2.7.1@sha256:"
               "a70ffffc2bfd33482953e5d6b64c6fcdb30239717a07b0f0d3ab2859ce3e4cde")
SKOPEO = ("quay.io/skopeo/stable:v1.20.0@sha256:"
          "47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4")
PACKAGE = "saf-fixture-root"
VERSION = "1.0.0"
ADVISORY = "TEST-SAF-IMAGE-0001"
NAMESPACE = "saf-1007-004-owned"
POD_NAME = "saf-1007-004-scanned-image"


def load_verified(cases_root, relative, expected_sha, module_name):
    path = cases_root / relative
    actual = sha256(path.read_bytes()).hexdigest()
    if actual != expected_sha:
        raise RuntimeError("published companion source differs from the staged SHA-256 pin")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load hash-verified published companion")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def safe_member(tf, name):
    from pathlib import PurePosixPath
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise RuntimeError("unexpected Docker archive member path")
    member = tf.getmember(name)
    if not member.isfile():
        raise RuntimeError("expected a regular Docker archive member")
    stream = tf.extractfile(member)
    if stream is None:
        raise RuntimeError("Docker archive member is unreadable")
    return stream.read()


def sha256_descriptor(value):
    return "sha256:" + sha256(value).hexdigest()


def bind_scanner_input_to_subject(root, archive_path, subject, scan_result):
    """Check scanner diffIDs, Docker archive bytes, and every published OCI descriptor."""
    with tarfile.open(archive_path, "r:*") as tf:
        entries = json.loads(safe_member(tf, "manifest.json"))
        if len(entries) != 1 or not entries[0].get("Layers"):
            raise RuntimeError("scanner archive must have one image entry with layers")
        config_bytes = safe_member(tf, entries[0]["Config"])
        config = json.loads(config_bytes)
        docker_layers = [safe_member(tf, name) for name in entries[0]["Layers"]]

    unpacked_docker_layers = [gzip.decompress(layer) if layer.startswith(b"\x1f\x8b") else layer
                              for layer in docker_layers]
    diff_ids = [sha256_descriptor(layer) for layer in unpacked_docker_layers]
    if config.get("rootfs", {}).get("diff_ids") != diff_ids:
        raise RuntimeError("saved Docker layer bytes differ from the archive config diffIDs")
    image_metadata = scan_result.get("image_metadata")
    if not isinstance(image_metadata, dict) or not isinstance(image_metadata.get("layer_metadata"), list):
        raise RuntimeError("pinned OSV output lacks its expected image layer metadata")
    scanner_layers = image_metadata["layer_metadata"]
    image_history = config.get("history", [])
    expected_empty = [row.get("empty_layer", False) for row in image_history]
    reported_empty = [row.get("is_empty") for row in scanner_layers]
    nonempty_diff_ids = [row.get("diff_id") for row in scanner_layers if row.get("is_empty") is False]
    if (reported_empty != expected_empty or nonempty_diff_ids != diff_ids
            or any(row.get("diff_id") for row in scanner_layers if row.get("is_empty") is True)):
        raise RuntimeError("OSV history and nonempty layer diffIDs do not match the exact image configuration")
    nonempty_positions = [i for i, empty in enumerate(reported_empty) if not empty]

    index = json.loads((root / "layout" / "index.json").read_text())
    descriptors = [d for d in index.get("manifests", []) if d.get("digest") == subject]
    if len(descriptors) != 1:
        raise RuntimeError("published OCI index does not identify the expected subject exactly once")
    manifest_bytes = (root / "layout" / "blobs" / "sha256" / subject.split(":", 1)[1]).read_bytes()
    if sha256_descriptor(manifest_bytes) != subject or len(manifest_bytes) != descriptors[0].get("size"):
        raise RuntimeError("published OCI manifest bytes differ from the exact subject descriptor")
    manifest = json.loads(manifest_bytes)
    config_desc = manifest.get("config", {})
    config_blob = (root / "layout" / "blobs" / "sha256" /
                   config_desc.get("digest", "").split(":", 1)[-1]).read_bytes()
    if (config_blob != config_bytes or sha256_descriptor(config_blob) != config_desc.get("digest")
            or len(config_blob) != config_desc.get("size")):
        raise RuntimeError("Docker archive config differs from the published OCI config descriptor")
    if json.loads(config_blob).get("rootfs", {}).get("diff_ids") != diff_ids:
        raise RuntimeError("published OCI config does not describe the exact scanner input layers")

    oci_layers = manifest.get("layers", [])
    if len(oci_layers) != len(docker_layers):
        raise RuntimeError("published OCI manifest layer count differs from scanner input")
    layer_digests = []
    for descriptor, docker_layer, diff_id in zip(oci_layers, docker_layers, diff_ids):
        blob = (root / "layout" / "blobs" / "sha256" /
                descriptor["digest"].split(":", 1)[-1]).read_bytes()
        if sha256_descriptor(blob) != descriptor.get("digest") or len(blob) != descriptor.get("size"):
            raise RuntimeError("published OCI layer blob fails its digest or size descriptor")
        media_type = descriptor.get("mediaType", "")
        unpacked = gzip.decompress(blob) if media_type.endswith("+gzip") else blob
        expected_unpacked = unpacked_docker_layers[len(layer_digests)]
        if unpacked != expected_unpacked or sha256_descriptor(unpacked) != diff_id:
            raise RuntimeError("published OCI layer content differs from OSV scanner input")
        layer_digests.append(descriptor["digest"])

    return {"subject_digest": subject, "config_digest": config_desc["digest"],
            "docker_layer_sha256": [sha256_descriptor(layer) for layer in docker_layers],
            "layer_digests": layer_digests, "layer_diff_ids": diff_ids,
            "scanner_empty_history_entries": reported_empty,
            "scanner_nonempty_history_indexes": nonempty_positions,
            "docker_archive_sha256": sha256(archive_path.read_bytes()).hexdigest()}


def run_osv(lab, inputs, archive_name):
    return lab.command("docker", "run", "--rm", "--network=none", "--cap-drop=ALL",
                       "--security-opt=no-new-privileges", "--env",
                       "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/fixture/db",
                       "--volume", f"{inputs}:/fixture:ro", OSV_SCANNER,
                       "scan", "image", "--offline", "--x-disable-plugins", "os/dpkg",
                       "--all-packages", "--format=json",
                       "--archive", "/fixture/" + archive_name, timeout=240, allow_failure=True)


def validate_scan(scan, result, subject_evidence):
    if scan.returncode not in (0, 1) or not isinstance(result.get("results"), list):
        return {"valid": False, "state": "failed", "subject": None, "findings": []}
    findings = []
    fixture_origin_exact = False
    for report in result["results"]:
        if not isinstance(report, dict) or not isinstance(report.get("packages"), list):
            return {"valid": False, "state": "unknown", "subject": None, "findings": []}
        for item in report["packages"]:
            package = item.get("package", {})
            if package.get("name") == PACKAGE and package.get("version") == VERSION:
                positions = subject_evidence["scanner_nonempty_history_indexes"]
                fixture_origin_exact = (bool(positions) and report.get("source", {}).get("path")
                                        == f"/fixture/saf_fixture_root-{VERSION}.dist-info/METADATA"
                                        and package.get("image_origin_details", {}).get("index") == positions[-1])
            for vuln in item.get("vulnerabilities", []):
                findings.append({"id": vuln.get("id"), "package": package.get("name"),
                                 "version": package.get("version")})
    expected = [{"id": ADVISORY, "package": PACKAGE, "version": VERSION}]
    valid = (scan.returncode == 1 and fixture_origin_exact and findings == expected
             and isinstance(result.get("image_metadata", {}).get("layer_metadata"), list)
             and bool(subject_evidence.get("subject_digest")))
    return {"valid": bool(valid), "state": "completed" if valid else "unknown",
            "subject": subject_evidence["subject_digest"] if valid else None,
            "findings": findings if valid else []}


def disposition(validated_scan, observed_image_id):
    if not validated_scan.get("valid") or validated_scan.get("state") != "completed":
        return "unknown"
    subject = validated_scan.get("subject")
    observed_digest = observed_image_id.rsplit("@", 1)[-1].removeprefix("containerd://")
    if not subject or observed_digest != subject:
        return "unknown"
    return "finding" if validated_scan.get("findings") else "no_fixture_match"


def run(lab, cases_root):
    pins = json.loads(Path(__file__).with_name("companion-sha256.json").read_text())
    image_case = load_verified(cases_root, "SAF-K8S-0604-001/case.py",
                               pins["SAF-K8S-0604-001/case.py"], "saf_0604_image_case")
    scanner_fixture = load_verified(cases_root, "SAF-K8S-0601-008/image_fixture.py",
                                    pins["SAF-K8S-0601-008/image_fixture.py"], "saf_0601_scanner_fixture")
    helper_path = cases_root / "SAF-K8S-0605-002/image_admission.py"
    if sha256(helper_path.read_bytes()).hexdigest() != pins["SAF-K8S-0605-002/image_admission.py"]:
        lab.block("Published disposable-registry helper source failed its SHA-256 pin")

    # The existing runnable image contains this harmless local module and package metadata.
    image_case.PACKAGES[PACKAGE] = VERSION
    scanner_fixture.ADVISORY_RECORD["affected"][0]["package"]["name"] = PACKAGE
    inputs = lab.kubeconfig.parent / "saf-1007-004-live-scan"
    inputs.mkdir(mode=0o700)
    scanner_fixture.database(inputs / "db")

    with image_case.load_registry()(lab) as (registry, host_port, _):
        root, subject = image_case.stage(registry, "complete", leaf_metadata=True)
        archive_path = root / "scanner-image.tar"
        registry.docker("run", "--rm", "--network=none", "--volume", f"{root}:/io",
                        SKOPEO, "copy", "--format", "v2s2", "oci:/io/layout:fixture",
                        "docker-archive:/io/scanner-image.tar:fixture", timeout=120)
        # The archive is staged into the scanner's read-only input directory without extraction.
        import shutil
        shutil.copy2(archive_path, inputs / "scanner-image.tar")
        scan = run_osv(lab, inputs, "scanner-image.tar")
        (lab.evidence / "1007-004-scanner-report.raw.json").write_text(scan.stdout)
        (lab.evidence / "1007-004-scanner-diagnostics.raw.log").write_text(scan.stderr)
        if (scan.returncode not in (0, 1) or "error during extraction" in scan.stderr.lower()
                or "could not load db" in scan.stderr.lower()):
            lab.block("Pinned offline OSV scanner returned an extraction or database error")
        raw_result = json.loads(scan.stdout)
        subject_evidence = bind_scanner_input_to_subject(root, archive_path, subject, raw_result)
        validated = validate_scan(scan, raw_result, subject_evidence)
        if not validated.get("valid"):
            lab.block("OSV output did not contain the one expected synthetic package/advisory result")
        (lab.evidence / "1007-004-scanner-subject.raw.json").write_text(
            json.dumps(subject_evidence, indent=2, sort_keys=True) + "\n")
        advisory_db = inputs / "db" / "osv-scalibr" / "PyPI" / "all.zip"
        scan_run = {"scanner": OSV_SCANNER, "exit_code": scan.returncode,
                    "advisory_db_sha256": sha256(advisory_db.read_bytes()).hexdigest(),
                    "subject_digest": subject, "report_sha256": sha256(scan.stdout.encode()).hexdigest()}
        (lab.evidence / "1007-004-scanner-run.raw.json").write_text(
            json.dumps(scan_run, indent=2, sort_keys=True) + "\n")

        inventory, observed_packages = image_case.scan(registry, root, subject)
        if observed_packages != image_case.PACKAGES:
            lab.block("Existing exact runnable image inventory gate did not recognize the built fixture")
        image_ref = image_case.release(registry, root, inventory, observed_packages)
        if image_ref is None:
            lab.block("Exact scanned subject could not be published to its owned registry")

        node = registry.lab.cluster + "-control-plane"
        certs = f"/etc/containerd/certs.d/{registry.registry}"
        hosts = registry.work / "saf-1007-hosts.toml"
        hosts.write_text(f'[host."https://{registry.registry}"]\n'
                         f'capabilities = ["pull", "resolve"]\nca = "{certs}/ca.crt"\n')
        registry.docker("exec", node, "mkdir", "-p", certs)
        registry.docker("cp", str(hosts), f"{node}:{certs}/hosts.toml")
        registry.docker("cp", str(registry.registry_ca), f"{node}:{certs}/ca.crt")
        pod = {"apiVersion": "v1", "kind": "Pod",
               "metadata": {"name": POD_NAME, "namespace": NAMESPACE},
               "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{"name": "workload", "image": image_ref,
                                        "imagePullPolicy": "Always",
                                        "command": ["python", "-c", image_case.RUNTIME_PROBE],
                                        "securityContext": {"allowPrivilegeEscalation": False,
                                                            "readOnlyRootFilesystem": True,
                                                            "capabilities": {"drop": ["ALL"]}}}]}}
        registry.kube("-n", NAMESPACE, "create", "-f", "-", input_text=json.dumps(pod))
        registry.kube("-n", NAMESPACE, "wait", "--for=jsonpath={.status.phase}=Succeeded",
                      f"pod/{POD_NAME}", "--timeout=85s", timeout=95)
        live = json.loads(registry.kube("-n", NAMESPACE, "get", "pod", POD_NAME, "-o", "json").stdout)
        statuses = live.get("status", {}).get("containerStatuses", [])
        image_id = statuses[0].get("imageID", "") if len(statuses) == 1 else ""
        lines = registry.kube("-n", NAMESPACE, "logs", POD_NAME).stdout.splitlines()
        marker = len(lines) == 2 and lines[0] == image_case.MARKER
        pod_image = live.get("spec", {}).get("containers", [{}])[0].get("image")
        request_exact = pod_image == image_ref and live.get("metadata", {}).get("namespace") == NAMESPACE
        decision = disposition(validated, image_id)
        exact = (decision == "finding" and marker and request_exact
                 and live.get("status", {}).get("phase") == "Succeeded")
        (lab.evidence / "1007-004-scanner-live-pod.raw.json").write_text(json.dumps(
            {"pod_uid": live.get("metadata", {}).get("uid"), "namespace": NAMESPACE,
             "image_ref": live.get("spec", {}).get("containers", [{}])[0].get("image"),
             "image_id": image_id, "phase": live.get("status", {}).get("phase"),
             "runtime_marker_seen": marker}, indent=2, sort_keys=True) + "\n")
        lab.check("positive", "Pinned OSV result is bound through the preserved OCI subject to a Pod that ran the image in the owned namespace",
                  exact, {"scanner_completed": True, "subject_chain_valid": True,
                          "pod_request_scoped_to_owned_namespace": request_exact,
                          "runtime_image_id_exact": decision != "unknown",
                          "expected_fixture_process_observed": marker,
                          "synthetic_finding_count": len(validated["findings"]),
                          "disposition": decision})

        counterfactuals = {
            "missing_report": disposition({"valid": False, "state": "missing"}, image_id),
            "scanner_failure": disposition({"valid": False, "state": "failed"}, image_id),
            "misbound_report": disposition({**validated, "subject": "sha256:" + "0" * 64}, image_id),
            "unknown_runtime_image_id": disposition(validated, ""),
        }
        lab.check("green", "Missing, failed, misbound and unknown scanner evidence never becomes a healthy posture result",
                  all(value == "unknown" for value in counterfactuals.values()), counterfactuals)
