"""Generate and check the observed software inventory of a runnable OCI image."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PYTHON = ("docker.io/library/python:3.13-slim@sha256:"
          "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
SKOPEO = ("quay.io/skopeo/stable:v1.20.0@sha256:"
          "47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4")
SYFT = ("ghcr.io/anchore/syft:v1.57.1@sha256:"
        "03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060")
PACKAGES = {"saf-fixture-root": "1.0", "saf-fixture-middle": "2.0", "saf-fixture-leaf": "3.0"}
MARKER = "saf-sbom-root-middle-leaf"
SCOPE = (
    "A pinned scanner catalogs Python package metadata from two runnable OCI images. A release "
    "check binds the CycloneDX inventory to the assembled image digest and holds an image "
    "when a required transitive dependency is absent from the inventory. This fixture leaves "
    "production SBOM retention, native package coverage and AI artifact inventory for separate review."
)


def load_registry():
    spec = importlib.util.spec_from_file_location(
        "saf_sbom_registry", HERE.parent / "SAF-K8S-0605-002" / "image_admission.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.registry


def stage(registry, variant, *, leaf_metadata):
    root = registry.work / variant
    root.mkdir(mode=0o755)
    (root / "Containerfile").write_text(f"""FROM {PYTHON}
COPY modules/ /fixture/
ENV PYTHONPATH=/fixture PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
CMD ["python", "-m", "saf_fixture_root"]
""")
    modules = root / "modules"
    modules.mkdir()
    source = {
        "saf-fixture-root": "from saf_fixture_middle import value\nprint('saf-sbom-root-' + value())\n",
        "saf-fixture-middle": "from saf_fixture_leaf import value as leaf\ndef value():\n    return 'middle-' + leaf()\n",
        "saf-fixture-leaf": "def value():\n    return 'leaf'\n",
    }
    requires = {"saf-fixture-root": "saf-fixture-middle", "saf-fixture-middle": "saf-fixture-leaf"}
    for name, version in PACKAGES.items():
        normalized = name.replace("-", "_")
        (modules / f"{normalized}.py").write_text(source[name])
        if name == "saf-fixture-leaf" and not leaf_metadata:
            continue
        metadata = modules / f"{normalized}-{version}.dist-info"
        metadata.mkdir()
        depends = requires.get(name)
        requirement = f"Requires-Dist: {depends} (=={PACKAGES[depends]})\n" if depends else ""
        (metadata / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n{requirement}"
        )
        (metadata / "RECORD").write_text(
            f"{normalized}.py,,\n{metadata.name}/METADATA,,\n{metadata.name}/RECORD,,\n"
        )
    tag = f"{registry.lab.cluster}-sbom:{variant}"
    try:
        registry.docker("build", "--network", "none", "-f", str(root / "Containerfile"),
                        "-t", tag, str(root), timeout=180)
        direct = registry.docker("run", "--rm", "--network", "none", "--read-only", tag)
        if direct.stdout.strip() != MARKER:
            registry.lab.block("The known Python dependency graph could not run in the image")
        registry.docker("image", "save", "-o", str(root / "image.tar"), tag, timeout=110)
        registry.docker("run", "--rm", "--network", "none", "--volume", f"{root}:/io",
                        SKOPEO, "copy", "--format", "oci", "--digestfile", "/io/manifest.digest",
                        "docker-archive:/io/image.tar", "oci:/io/layout:fixture", timeout=120)
    finally:
        registry.docker("image", "rm", tag, allow_failure=True)
    (root / "image.tar").unlink()
    return root, (root / "manifest.digest").read_text().strip()


def scan(registry, root, subject):
    def read_format(output):
        result = registry.docker(
            "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL",
            "--tmpfs", "/tmp:rw,nosuid,nodev", "--volume", f"{root / 'layout'}:/scan:ro", SYFT, "scan", "oci-dir:/scan",
            "--output", output, timeout=150,
        )
        return json.loads(result.stdout)
    scanned = read_format("syft-json")
    bom = read_format("cyclonedx-json")
    metadata = scanned.get("source", {}).get("metadata", {})
    if metadata.get("manifestDigest") != subject:
        registry.lab.block("Syft did not report the exact input OCI manifest digest")
    if scanned.get("descriptor", {}).get("version") != "1.57.1":
        registry.lab.block("Syft did not identify the pinned scanner version")
    if bom.get("bomFormat") != "CycloneDX" or not isinstance(bom.get("components"), list):
        registry.lab.block("Syft did not produce a machine-readable CycloneDX inventory")
    subject_component = bom.get("metadata", {}).get("component", {})
    hashes = subject_component.get("hashes", [])
    digest_bound = any(entry.get("alg") == "SHA-256" and entry.get("content") == subject.split(":", 1)[1]
                       for entry in hashes)
    # Some CycloneDX serializers do not put the OCI digest in the subject hash list.
    # Retain a companion scan receipt that binds the exact serialized BOM to Syft's image digest.
    bom_path = registry.lab.evidence / f"{root.name}.cdx.json"
    bom_path.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n")
    return {
        "manifest_digest": subject,
        "bom_sha256": sha256(bom_path.read_bytes()).hexdigest(),
        "cyclonedx_subject_hash_present": digest_bound,
        "generator": SYFT,
    }, {row["name"]: row["version"] for row in bom["components"]
        if row.get("name") in PACKAGES and "version" in row}


def release(registry, root, inventory, observed):
    if observed != PACKAGES:
        return None
    raw = registry.lab.evidence / f"{root.name}.cdx.json"
    if sha256(raw.read_bytes()).hexdigest() != inventory["bom_sha256"]:
        registry.lab.block("The inventory bytes changed between scanning and release")
    subject = inventory["manifest_digest"]
    (root / "ca.crt").write_bytes(registry.registry_ca.read_bytes())
    target = f"{registry.registry}/fixture/sbom:approved"
    registry.docker("run", "--rm", "--network", "kind", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--volume", f"{root}:/io",
                    SKOPEO, "copy", "--preserve-digests", "--dest-cert-dir", "/io",
                    "--digestfile", "/io/published.digest", "oci:/io/layout:fixture",
                    f"docker://{target}", timeout=140)
    if (root / "published.digest").read_text().strip() != subject:
        registry.lab.block("The published manifest digest differs from the scanned manifest")
    return f"{target.rsplit(':', 1)[0]}@{subject}"


def release_tag_absent(registry, root):
    (root / "ca.crt").write_bytes(registry.registry_ca.read_bytes())
    target = f"{registry.registry}/fixture/sbom:approved"
    result = registry.docker(
        "run", "--rm", "--network", "kind", "--cap-drop=ALL",
        "--volume", f"{root}:/io:ro", SKOPEO, "inspect", "--no-tags", "--cert-dir", "/io",
        f"docker://{target}", allow_failure=True, timeout=60,
    )
    diagnostic = result.stderr.lower()
    return result.returncode != 0 and ("manifest unknown" in diagnostic or "name unknown" in diagnostic)


def run_approved(registry, image, digest):
    lab = registry.lab
    node = lab.cluster + "-control-plane"
    certs = f"/etc/containerd/certs.d/{registry.registry}"
    config = registry.work / "sbom-hosts.toml"
    config.write_text(f'[host."https://{registry.registry}"]\n'
                      f'capabilities = ["pull", "resolve"]\nca = "{certs}/ca.crt"\n')
    registry.docker("exec", node, "mkdir", "-p", certs)
    registry.docker("cp", str(config), f"{node}:{certs}/hosts.toml")
    registry.docker("cp", str(registry.registry_ca), f"{node}:{certs}/ca.crt")
    name = "saf-0604-001-covered"
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": {
        "automountServiceAccountToken": False, "restartPolicy": "Never",
        "containers": [{"name": "workload", "image": image, "imagePullPolicy": "Always"}],
    }})
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}", "--timeout=85s", timeout=95)
    status = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)["status"]
    runtime = status["containerStatuses"][0]["imageID"].endswith(digest)
    marker = lab.kubectl("logs", name).stdout.strip() == MARKER
    lab.check("positive", "Kind ran the exact inventoried manifest and exercised all fixture modules",
              runtime and marker, {"ran_exact_digest": runtime, "transitive_module_executed": marker})


def run(lab):
    with load_registry()(lab) as (registry, _, _):
        missing_root, missing_digest = stage(registry, "missing", leaf_metadata=False)
        full_root, full_digest = stage(registry, "complete", leaf_metadata=True)
        absent, missing = scan(registry, missing_root, missing_digest)
        complete, observed = scan(registry, full_root, full_digest)
        if missing_digest == full_digest:
            lab.block("The positive and comparison OCI manifests were not distinct")
        absent_packages = set(PACKAGES.items()) - set(missing.items())
        expected_gap = absent_packages == {("saf-fixture-leaf", "3.0")}
        lab.check("red", "The runnable comparison loses only its unregistered transitive package from the inventory",
                  expected_gap, {"known_dependency_executed": True, "uncataloged_transitive_package": sorted(absent_packages)})
        missing_is_held = release(registry, missing_root, absent, missing) is None
        no_publication = release_tag_absent(registry, missing_root)
        lab.check("green", "Release validation holds the image with incomplete inventory coverage",
                  missing_is_held and no_publication, {"withheld": missing_is_held, "release_tag_absent": no_publication})
        covered = observed == PACKAGES
        lab.check("green", "The generated CycloneDX inventory includes every declared Python fixture package",
                  covered, {"observed": sorted(observed.items()), "generator_version": "1.57.1"})
        if not covered:
            lab.block("The release requires all expected components at the pinned versions")
        (lab.evidence / "inventory-subjects.json").write_text(json.dumps(
            {"held": absent, "approved": complete}, indent=2, sort_keys=True) + "\n")
        push_ref = release(registry, full_root, complete, observed)
        run_approved(registry, push_ref, full_digest)
