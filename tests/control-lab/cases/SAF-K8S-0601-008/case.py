"""Scan inert image bytes offline, then enforce promotion into an isolated registry."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

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
REPO = "fixtures/prerelease"
TIME = "2026-11-23T11:45:00Z"
VERSIONS = {"affected": "1.0.0", "clear": "1.0.1"}
SCOPE = (
    "Pinned OSV-Scanner executes offline against deterministic inert image archives and a generated "
    "synthetic advisory. A Kubernetes promotion workload verifies exact candidate digests and records "
    "the decision. A separate reader checks the manifest and blobs in a pinned Distribution registry "
    "inside the lab. The test covers a single known package, trusted lab input, and a fixed clock."
)


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


def deploy(lab, image):
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
                "immutable": True, "data": {name: (HERE / name).read_text()
                    for name in ("image_fixture.py", "promotion_fixture.py")}})
    for name in (PROMOTER, OBSERVER):
        client = container("client", image=image, imagePullPolicy="Never", command=["sleep", "3600"],
                           volumeMounts=[{"name": "program", "mountPath": "/fixture", "readOnly": True}])
        lab.create(pod(name, [client], automountServiceAccountToken=False,
                       volumes=[{"name": "program", "configMap": {"name": CODE}}]))
        ready(lab, name)
    ready(lab, REGISTRY_NAME)
    lab.kubectl("exec", OBSERVER, "--", "python", "/fixture/promotion_fixture.py", "ready", timeout=27)


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
    deploy(lab, runtime.load_runtime(lab))

    def observe(tag):
        response = lab.kubectl("exec", OBSERVER, "--", "python", "/fixture/promotion_fixture.py",
                               "inspect", tag, timeout=25)
        return json.loads(response.stdout)

    def proposal(tag, variant, report, exception=None, baseline=False):
        payload = json.dumps({"tag": tag, "version": VERSIONS[variant],
                              "mode": "baseline" if baseline else "governed",
                              "report": report, "exception": exception})
        result = lab.kubectl("exec", "-i", PROMOTER, "--", "python", "/fixture/promotion_fixture.py",
                             "promote", payload=payload, timeout=35)
        return {"gate": json.loads(result.stdout), "registry": observe(tag)}

    unchecked = proposal("unchecked", "affected", reports["affected"], baseline=True)
    red = (unchecked["gate"]["decision"] == "unchecked-baseline"
           and unchecked["registry"] == {"status": 200, "digest": subjects["affected"], "blobs_available": True})
    lab.check("red", "Unchecked build pipeline publishes the flagged inert image", red, unchecked)
    exception = {"id": "fixture-exception-01", "approval": "fixture-security-reviewer",
                 "repository": REPO, "subject": subjects["affected"], "finding_ids": [fixture.ADVISORY],
                 "start": "2026-11-23T11:00:00Z", "end": "2026-11-23T13:00:00Z"}
    blocked = {}
    cases = {
        "high": ("affected", reports["affected"], None, "blocked-severity"),
        "missing-report": ("clear", None, None, "report-absent"),
        "scan-error": ("clear", {"state": "failed", "scanner_exit": scanner_error.returncode}, None, "scanner-error"),
        "wrong-subject": ("affected", reports["clear"], None, "report-subject-mismatch"),
        "stale-report": ("clear", {**reports["clear"], "time": "2026-11-20T12:00:00Z"}, None, "report-stale"),
        "expired-exception": ("affected", reports["affected"],
                              {**exception, "end": "2026-11-23T11:59:00Z"}, "blocked-severity"),
        "wrong-repo-exception": ("affected", reports["affected"],
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
    clear = proposal("approved", "clear", reports["clear"])
    excepted = proposal("approved-by-exception", "affected", reports["affected"], exception)
    positive = (clear["gate"]["decision"] == "allowed-clear" and
                clear["registry"] == {"status": 200, "digest": subjects["clear"], "blobs_available": True}
                and excepted["gate"]["decision"] == "allowed-exception" and
                excepted["registry"] == {"status": 200, "digest": subjects["affected"], "blobs_available": True})
    lab.check("positive", "The clean artifact and explicitly excepted digest reach the owned registry",
              positive, {"clean": clear, "exception": excepted})
    (lab.evidence / "image-scan-promotion-observations.json").write_text(json.dumps({
        "scanner": SCANNER, "synthetic_advisory_db_sha256": database_hash,
        "scanner_error_exit": scanner_error.returncode, "archive_digests": archives,
        "scanner_reports": reports, "baseline": unchecked, "blocked": blocked,
        "approved": {"clean": clear, "exception": excepted},
    }, indent=2, sort_keys=True) + "\n")
