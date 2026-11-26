"""Scan inert image bytes offline, then enforce promotion into an isolated registry."""
from hashlib import sha256
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
SCANNER = ("ghcr.io/google/osv-scanner:v2.7.1@sha256:"
           "a70ffffc2bfd33482953e5d6b64c6fcdb30239717a07b0f0d3ab2859ce3e4cde")
REGISTRY = ("docker.io/library/registry:3.0.0@sha256:"
            "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e")
REGISTRY_NAME = "fixture-scan-registry"
PROMOTER = "fixture-scan-promoter"
OBSERVER = "fixture-scan-observer"
CODE = "fixture-scan-program"
TRUST = "fixture-scan-trust"
REPO = "fixtures/prerelease"
TIME = "2026-11-23T11:45:00Z"
VERSIONS = {"affected": "1.0.0", "clear": "1.0.1"}
SCOPE = (
    "Pinned OSV-Scanner executes offline against deterministic inert image archives and a generated "
    "synthetic advisory. A Kubernetes promotion workload verifies exact candidate digests and records "
    "the decision. A separately mounted Ed25519 public-key policy authenticates the exact canonical "
    "scan report before the promoter accepts it. A separate reader checks the manifest and blobs in "
    "a pinned Distribution registry inside the lab. The signer and advisory are synthetic; this does "
    "not establish production scanner identity, advisory-feed authenticity, or CI custody."
)
TRUSTED_REPORT_SIGNER = "fixture-osv-scanner-v1"
UNAPPROVED_REPORT_SIGNER = "fixture-unapproved-scanner-v1"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_scanner(lab, inputs, archive):
    return lab.command("docker", "run", "--rm", "--network=none", "--cap-drop=ALL",
                       "--security-opt=no-new-privileges", "--env",
                       "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/fixture/db",
                       "--volume", f"{inputs}:/fixture:ro", SCANNER,
                       "scan", "image", "--offline", "--all-packages", "--format=json",
                       "--archive", "/fixture/" + archive, timeout=240, allow_failure=True)


def report_from_scan(lab, fixture, scan, candidate, artifact, version):
    expected_exit = 1 if version == VERSIONS["affected"] else 0
    if scan.returncode != expected_exit:
        lab.block(f"Unexpected pinned OSV scanner exit {scan.returncode} for fixed {version} fixture")
    result = json.loads(scan.stdout)
    expected_layers = json.loads(artifact["config.json"])["rootfs"]["diff_ids"]
    scanned_layers = [entry["diff_id"] for entry in result["image_metadata"]["layer_metadata"]]
    if scanned_layers != expected_layers:
        lab.block("The image scan reports different layer contents from the candidate manifest")
    packages = [entry for report in result["results"] for entry in report["packages"]
                if entry["package"]["name"] == fixture.PACKAGE]
    if len(packages) != 1 or packages[0]["package"]["version"] != version:
        lab.block("The pinned scanner did not identify the exact inert package")
    findings = [{"id": v["id"], "severity": v["database_specific"]["severity"]}
                for v in packages[0].get("vulnerabilities", [])]
    expected = [{"id": fixture.ADVISORY, "severity": "HIGH"}] if expected_exit else []
    if findings != expected:
        lab.block("The pinned scanner results differ from the locked synthetic advisory")
    return {"artifact": candidate, "repository": REPO, "time": TIME, "findings": findings,
            "state": "completed", "scanner_exit": scan.returncode,
            "package": fixture.PACKAGE, "package_version": version,
            "scanner_output_sha256": fixture.digest(scan.stdout.encode()), "layers": scanned_layers}


def openssl_binary():
    candidate = os.environ.get("SAF_OPENSSL") or shutil.which("openssl")
    if not candidate:
        raise RuntimeError("OpenSSL is required for ephemeral fixture report signatures")
    result = subprocess.run([candidate, "version"], capture_output=True, text=True,
                            timeout=5, check=False)
    if result.returncode != 0 or not result.stdout.startswith("OpenSSL 3."):
        raise RuntimeError("OpenSSL 3 with Ed25519 support is required")
    return candidate


def signer_material(openssl, directory, name):
    private = directory / (name + ".key")
    public = directory / (name + ".pub")
    subprocess.run([openssl, "genpkey", "-algorithm", "ED25519", "-out", str(private)],
                   capture_output=True, check=True, timeout=10)
    os.chmod(private, 0o600)
    subprocess.run([openssl, "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                   capture_output=True, check=True, timeout=10)
    return private, public.read_text()


def signed_report(openssl, private_key, signer_id, report, directory):
    payload = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    with tempfile.TemporaryDirectory(prefix="report-sign-", dir=directory) as tmp_name:
        tmp = Path(tmp_name)
        source, signature = tmp / "payload.json", tmp / "signature.bin"
        source.write_bytes(payload)
        os.chmod(source, 0o600)
        subprocess.run([openssl, "pkeyutl", "-sign", "-inkey", str(private_key),
                        "-rawin", "-in", str(source), "-out", str(signature)],
                       capture_output=True, check=True, timeout=10)
        return {"report": report, "signer_id": signer_id,
                "signature_b64": base64.b64encode(signature.read_bytes()).decode("ascii")}


def signature_valid_for_public_key(openssl, public_key, envelope, directory):
    payload = json.dumps(envelope["report"], sort_keys=True, separators=(",", ":")).encode()
    signature = base64.b64decode(envelope["signature_b64"], validate=True)
    with tempfile.TemporaryDirectory(prefix="report-verify-", dir=directory) as tmp_name:
        tmp = Path(tmp_name)
        public_path, source, signature_path = tmp / "public.pem", tmp / "payload.json", tmp / "signature.bin"
        public_path.write_text(public_key)
        source.write_bytes(payload)
        signature_path.write_bytes(signature)
        for path in (public_path, source, signature_path):
            os.chmod(path, 0o600)
        result = subprocess.run([openssl, "pkeyutl", "-verify", "-pubin", "-inkey",
                                 str(public_path), "-rawin", "-in", str(source),
                                 "-sigfile", str(signature_path)], capture_output=True,
                                timeout=10, check=False)
        return result.returncode == 0


def deploy(lab, image, trusted_public_key=None):
    registry = container("registry", image=REGISTRY, ports=[{"containerPort": 5000}],
                         env=[{"name": "REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY",
                               "value": "/tmp/saf-registry"}])
    del registry["command"]
    registry["readinessProbe"] = {"httpGet": {"port": 5000, "path": "/v2/"}, "periodSeconds": 1}
    definition = pod(REGISTRY_NAME, [registry], automountServiceAccountToken=False)
    definition["metadata"]["labels"] = {"app": REGISTRY_NAME}
    lab.create(definition)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": REGISTRY_NAME},
                "spec": {"selector": {"app": REGISTRY_NAME}, "ports": [{"port": 5000}]}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CODE},
                "immutable": True, "data": {
                    **{name: (HERE / name).read_text()
                       for name in ("image_fixture.py", "promotion_fixture.py", "report_crypto.py")},
                }})
    if trusted_public_key is not None:
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": TRUST},
                    "immutable": True, "data": {
                        "trusted-report.pub": trusted_public_key,
                        "report-policy.json": json.dumps({
                            "trusted_signer_id": TRUSTED_REPORT_SIGNER,
                            "trusted_public_key": "/trust/trusted-report.pub",
                            "algorithm": "Ed25519",
                            "scope": "synthetic OSV report fixture only",
                        }, sort_keys=True),
                    }})
    for name in (PROMOTER, OBSERVER):
        client = container("client", image=image, imagePullPolicy="Never", command=["sleep", "3600"],
                           volumeMounts=[{"name": "program", "mountPath": "/fixture", "readOnly": True}])
        volumes = [{"name": "program", "configMap": {"name": CODE}}]
        if name == PROMOTER and trusted_public_key is not None:
            client["volumeMounts"].append({"name": "trust", "mountPath": "/trust", "readOnly": True})
            volumes.append({"name": "trust", "configMap": {"name": TRUST}})
        lab.create(pod(name, [client], automountServiceAccountToken=False, volumes=volumes))
        ready(lab, name)
    ready(lab, REGISTRY_NAME)
    lab.kubectl("exec", OBSERVER, "--", "python", "/fixture/promotion_fixture.py", "ready", timeout=27)
    if trusted_public_key is not None:
        lab.kubectl("exec", PROMOTER, "--", "python", "-c",
                    "import sys; sys.path.insert(0, '/fixture'); from report_crypto import openssl; openssl()",
                    timeout=12)


def run(lab):
    fixture = load(HERE / "image_fixture.py", "saf_image_fixture")
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_scan_fixture_runtime")
    inputs = lab.kubeconfig.parent / "synthetic-scan"
    inputs.mkdir()
    fixture.database(inputs / "db")
    subjects = {}
    archives = {}
    reports = {}
    for name, version in VERSIONS.items():
        artifact = fixture.image(version)
        subjects[name] = fixture.digest(artifact["manifest.json"])
        archive = fixture.docker_archive(artifact)
        path = inputs / (name + ".tar")
        path.write_bytes(archive)
        archives[name] = fixture.digest(archive)
        reports[name] = report_from_scan(lab, fixture, run_scanner(lab, inputs, path.name),
                                         subjects[name], artifact, version)
    scanner_error = run_scanner(lab, inputs, "absent-image.tar")
    if scanner_error.returncode in (0, 1):
        lab.block("The missing archive did not elicit an infrastructure scan error")
    database_hash = sha256(next((inputs / "db").rglob("all.zip")).read_bytes()).hexdigest()
    signer_dir = lab.kubeconfig.parent / "synthetic-report-signers"
    signer_dir.mkdir(mode=0o700)
    openssl = openssl_binary()
    trusted_private, trusted_public = signer_material(openssl, signer_dir, "trusted-scanner")
    unapproved_private, unapproved_public = signer_material(openssl, signer_dir, "unapproved-scanner")
    deploy(lab, runtime.load_runtime(lab), trusted_public)
    signed_reports = {name: signed_report(openssl, trusted_private, TRUSTED_REPORT_SIGNER,
                                          report, signer_dir)
                      for name, report in reports.items()}

    def observe(tag):
        response = lab.kubectl("exec", OBSERVER, "--", "python", "/fixture/promotion_fixture.py",
                               "inspect", tag, timeout=25)
        return json.loads(response.stdout)

    def proposal(tag, variant, report, exception=None, baseline=False):
        payload = json.dumps({"tag": tag, "version": VERSIONS[variant],
                              "mode": "baseline" if baseline else "governed",
                              "report": report, "exception": exception})
        result = subprocess.run(["kubectl", "--kubeconfig", str(lab.kubeconfig),
                                 "--context", f"kind-{lab.cluster}", "--namespace", "saf-test",
                                 "exec", "-i", PROMOTER, "--", "python", "/fixture/promotion_fixture.py", "promote"],
                                input=payload, capture_output=True, text=True, timeout=35, env=lab.env)
        if result.returncode != 0:
            lab.block("The owned promotion process did not return a decision")
        return {"gate": json.loads(result.stdout), "registry": observe(tag)}

    unchecked = proposal("unchecked", "affected", signed_reports["affected"], baseline=True)
    red = (unchecked["gate"]["decision"] == "unchecked-baseline"
           and unchecked["registry"] == {"status": 200, "digest": subjects["affected"], "blobs_available": True})
    lab.check("red", "Unchecked build pipeline publishes the flagged inert image", red, unchecked)
    exception = {"id": "fixture-exception-01", "approval": "fixture-security-reviewer",
                 "repository": REPO, "subject": subjects["affected"], "finding_ids": [fixture.ADVISORY],
                 "start": "2026-11-23T11:00:00Z", "end": "2026-11-23T13:00:00Z"}
    blocked = {}
    cases = {
        "high": ("affected", signed_reports["affected"], None, "blocked-severity"),
        "missing-report": ("clear", None, None, "report-absent"),
        "scan-error": ("clear", signed_report(openssl, trusted_private, TRUSTED_REPORT_SIGNER,
                                               {"state": "failed", "scanner_exit": scanner_error.returncode}, signer_dir), None, "scanner-error"),
        "wrong-subject": ("affected", signed_reports["clear"], None, "report-subject-mismatch"),
        "stale-report": ("clear", signed_report(openssl, trusted_private, TRUSTED_REPORT_SIGNER,
                                                 {**reports["clear"], "time": "2026-11-20T12:00:00Z"}, signer_dir), None, "report-stale"),
        "expired-exception": ("affected", signed_reports["affected"],
                              {**exception, "end": "2026-11-23T11:59:00Z"}, "blocked-severity"),
        "wrong-repo-exception": ("affected", signed_reports["affected"],
                                 {**exception, "repository": "fixtures/other"}, "blocked-severity"),
    }
    for tag, (variant, report, candidate_exception, wanted) in cases.items():
        result = proposal(tag, variant, report, candidate_exception)
        blocked[tag] = {**result, "expected": wanted}
    green = {name: row["gate"]["decision"] == row["expected"] and not row["gate"]["manifest_written"]
             and row["registry"] == {"status": 404, "digest": None, "blobs_available": False}
             for name, row in blocked.items()}
    lab.check("green", "Disallowed proposals have no registry manifest at the governed release tags",
              all(green.values()), green)
    clear = proposal("approved", "clear", signed_reports["clear"])
    excepted = proposal("approved-by-exception", "affected", signed_reports["affected"], exception)
    positive = (clear["gate"]["decision"] == "allowed-clear" and
                clear["registry"] == {"status": 200, "digest": subjects["clear"], "blobs_available": True}
                and excepted["gate"]["decision"] == "allowed-exception" and
                excepted["registry"] == {"status": 200, "digest": subjects["affected"], "blobs_available": True})
    lab.check("positive", "The clean artifact and explicitly excepted digest reach the owned registry",
              positive, {"clean": clear, "exception": excepted})
    unapproved_envelope = signed_report(openssl, unapproved_private, UNAPPROVED_REPORT_SIGNER,
                                        reports["clear"], signer_dir)
    unapproved_signature_valid = signature_valid_for_public_key(
        openssl, unapproved_public, unapproved_envelope, signer_dir)
    unapproved = proposal("unapproved-signer", "clear", unapproved_envelope)
    claimed_approved = proposal("claimed-approved-signer", "clear", {
        **unapproved_envelope, "signer_id": TRUSTED_REPORT_SIGNER,
    })
    invalid_under_approved_key = (claimed_approved["gate"]["decision"] == "report-signature-invalid"
                                  and not claimed_approved["gate"]["manifest_written"]
                                  and claimed_approved["registry"]["status"] == 404)
    denied_unapproved = (unapproved_signature_valid and invalid_under_approved_key
                         and unapproved["gate"]["decision"] == "report-untrusted-signer"
                         and not unapproved["gate"]["manifest_written"]
                         and unapproved["registry"] == {"status": 404, "digest": None,
                                                        "blobs_available": False})
    lab.check("green", "A valid exact scan report from an unapproved fixture signer cannot be promoted",
              denied_unapproved, {"unapproved_signer_rejected": denied_unapproved,
                                  "signature_valid_under_unapproved_key": unapproved_signature_valid,
                                  "claimed_approved_identity_with_wrong_signature_rejected": invalid_under_approved_key,
                                  "manifest_written": unapproved["gate"]["manifest_written"],
                                  "registry_status": unapproved["registry"]["status"],
                                  "fixture_signer_policy": "trusted public key pinned separately"})
    (lab.evidence / "image-scan-promotion-observations.json").write_text(json.dumps({
        "scanner": SCANNER, "synthetic_advisory_db_sha256": database_hash,
        "scanner_error_exit": scanner_error.returncode, "archive_digests": archives,
        "scanner_reports": reports, "baseline": unchecked, "blocked": blocked,
        "approved": {"clean": clear, "exception": excepted},
        "signer_policy": {"trusted_signer_id": TRUSTED_REPORT_SIGNER,
                          "unapproved_signer_id": UNAPPROVED_REPORT_SIGNER,
                          "trusted_public_key_sha256": sha256(trusted_public.encode()).hexdigest(),
                          "private_key_material_retained": False},
    }, indent=2, sort_keys=True) + "\n")
    trusted_private.unlink(missing_ok=True)
    unapproved_private.unlink(missing_ok=True)
