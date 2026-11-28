"""Run the pinned historical quote checks as a separate restricted Kind Job."""

import hashlib
import json
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent / "tdx-reference"
JOB = "tdx-historical-quote"
ROOT_NOTICE = re.compile(
    r"WARN : [0-9/]+ [0-9:.]+ verify\.go:[0-9]+: "
    r"Using embedded Intel certificate for TDX attestation root of trust"
)
ARCHITECTURES = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}
EXPECTED_ID = {
    "schema": "saf-intel-tdx-historical-reference-v1",
    "verifier": "google/go-tdx-guest@v0.3.1",
    "quote_sha256": "6dde5548bec99147fef832643301f113df99931547be26df8ac376c4eaa5b5a7",
    "historical_evaluation_time_utc": "2023-07-01T01:00:00Z",
    "expiry_probe_time_utc": "2053-07-01T01:00:00Z",
    "quote_bytes_unchanged": True,
    "live_platform_or_freshness_observed": False,
}


ARCHIVE_URL = "https://untrustsecurity.com/evidence/gcp-c3-tdx-7dfdc0d5.zip"
ARCHIVE_SHA256 = "7dfdc0d585b277a1f599efbafdaf42257f4f05838f2cc7b8c42890700db1d851"
INTEL_ROOT_URL = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"
INTEL_ROOT_PEM_SHA256 = "267a851c8d10982685b5f219d9ac2600ba71463569a6541827c2dc9fe9d6d699"
ARCHIVE_MEMBERS = (
    "quote.bin", "nonce.hex", "collateral/tcb-info.json", "collateral/tcb-info-chain.pem",
    "collateral/qe-identity.json", "collateral/qe-identity-chain.pem", "collateral/pck-sign-chain.pem",
    "collateral/pck-platform-crl.der", "collateral/root-ca-crl.der",
)
COLLATERAL_ID = {
    "quote_sha256": "7cdbd00a3921dd18631d33f7ba2f5317057e3abe8ac14335005908c371060ff9",
    "evaluation_time_utc": "2026-10-06T04:00:00Z",
    "expired_probe_time_utc": "2026-11-15T04:00:00Z",
    "intel_root_sha256": "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3",
    "local_pcs_artifacts_used": ["pck-platform-crl.der", "qe-identity.json", "root-ca-crl.der", "tcb-info.json"],
    "live_quote_or_current_collateral_observed": False,
}


def fetch(lab, destination, url, expected_sha256):
    lab.command("curl", "--proto", "=https", "--proto-redir", "=https", "--fail", "--silent", "--show-error",
                "--location", "--max-redirs", "2", "--retry", "1", "--max-time", "20", "--max-filesize", "100000",
                "--output", str(destination), url, timeout=45)
    if hashlib.sha256(destination.read_bytes()).hexdigest() != expected_sha256:
        lab.block("The downloaded Intel TDX fixture differs from its reviewed digest")


def stage_archive(lab, scratch):
    archive_path = scratch / "tdx-capture.zip"
    fetch(lab, archive_path, ARCHIVE_URL, ARCHIVE_SHA256)
    fetch(lab, scratch / "intel-root.pem", INTEL_ROOT_URL, INTEL_ROOT_PEM_SHA256)
    with ZipFile(archive_path) as archive:
        names = archive.namelist()
        for relative in ARCHIVE_MEMBERS:
            member = "gcp-c3-tdx/" + relative
            if names.count(member) != 1 or not 0 < archive.getinfo(member).file_size <= 32000:
                lab.block("The archived TDX capture does not have the expected bounded inputs")
            destination = scratch / "archive" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(archive.read(member))


def check_signed_collateral(lab, record):
    checks = (
        ("tdx-archived-collateral",
         "A production-rooted archived TDX quote matches Intel's signed TCB, QE identity and revocation data at capture time",
         ("strict_collateral_and_revocations_verified", "archived_report_data_and_mrtd_match")),
        ("tdx-collateral-fail-closed",
         "The same archived TDX quote is rejected when collateral is expired or the platform CRL is unavailable",
         ("expired_collateral_rejected", "missing_platform_crl_rejected")),
    )
    verdict_keys = {key for _, _, fields in checks for key in fields}
    if (not isinstance(record, dict) or set(record) != set(COLLATERAL_ID) | verdict_keys
            or record["live_quote_or_current_collateral_observed"] is not False
            or any(record[key] != value for key, value in COLLATERAL_ID.items())):
        lab.block("The Job returned an unrecognized signed collateral receipt")
    for phase, claim, fields in checks:
        observed = {key: record[key] is True for key in fields}
        lab.check(phase, claim, all(observed.values()), observed)
    artifact = {"source_archive_sha256": ARCHIVE_SHA256, **record}
    (lab.evidence / "tdx-signed-collateral.json").write_text(json.dumps(artifact, sort_keys=True, indent=2) + "\n")


def build(lab, image):
    host = lab.command("docker", "info", "--format", "{{.Architecture}}", timeout=15).stdout.strip()
    platform = ARCHITECTURES.get(host)
    if platform is None:
        lab.block("The TDX verifier fixture supports Linux amd64 or arm64")
    with TemporaryDirectory(prefix="saf-tdx-verifier-") as directory:
        scratch = Path(directory)
        for name in ("main.go", "signed_collateral.go", "go.mod", "go.sum"):
            (scratch / name).write_bytes((HERE / name).read_bytes())
        lab.command("env", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "CGO_ENABLED=0",
                    f"GOARCH={platform}", "go", "-C", str(scratch), "build", "-mod=readonly",
                    "-trimpath", "-o", "quote-check", ".", timeout=180)
        stage_archive(lab, scratch)
        (scratch / "Dockerfile").write_text(
            "FROM scratch\nCOPY --chmod=0555 quote-check /quote-check\n"
            "COPY intel-root.pem /intel-root.pem\nCOPY archive /archive\n"
            'ENTRYPOINT ["/quote-check","/archive","/intel-root.pem"]\n')
        lab.command("docker", "build", "--network=none", "--provenance=false", "--platform", f"linux/{platform}",
                    "-t", image, str(scratch), timeout=100)
    lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=100)


def run(lab):
    image = f"saf-k8s-local/tdx-historical-verifier:{lab.cluster}"
    labels = {"fixture.example/tdx-profile": JOB}
    try:
        build(lab, image)
        lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                    "metadata": {"name": JOB},
                    "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress", "Egress"],
                             "ingress": [], "egress": []}})
        lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": JOB},
                    "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 40,
                             "template": {"metadata": {"labels": labels}, "spec": {
                                 "restartPolicy": "Never", "automountServiceAccountToken": False,
                                 "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                     "seccompProfile": {"type": "RuntimeDefault"}},
                                 "containers": [{"name": "verify", "image": image, "imagePullPolicy": "Never",
                                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                                     "readOnlyRootFilesystem": True,
                                                                     "capabilities": {"drop": ["ALL"]}},
                                                 "resources": {"requests": {"cpu": "25m", "memory": "24Mi"},
                                                               "limits": {"cpu": "300m", "memory": "96Mi"}}}]}}}})
        ready = lab.kubectl("wait", "--for=condition=complete", f"job/{JOB}", "--timeout=60s",
                            timeout=65, allow_failure=True)
        if ready.returncode:
            lab.kubectl("logs", f"job/{JOB}", allow_failure=True)
            lab.block("The local TDX verifier Job did not complete its executable checks")
        output = lab.kubectl("logs", f"job/{JOB}").stdout
        lines = [line for line in output.splitlines() if not ROOT_NOTICE.fullmatch(line)]
        if len(lines) != 1 or len(output) > 8192:
            lab.block("The verifier logs did not contain one bounded normalized receipt")
        document = json.loads(lines[0])
        signed_collateral = document.pop("signed_collateral", None)
        checks = {
            "archived_signature_and_chain": ("historical_signature_and_pck_chain_verified",
                                             "expected_report_and_measurement_matched"),
            "expiry_and_binding": ("pck_expiry_denied", "wrong_expected_report_data_denied",
                                   "wrong_expected_measurement_denied"),
            "archived_tcb_policy": ("strict_archived_collateral_tcb_denied",),
        }
        identity_matches = all(document.get(key) == value for key, value in EXPECTED_ID.items())
        approved_keys = set(EXPECTED_ID) | {k for fields in checks.values() for k in fields}
        if not identity_matches or set(document) != approved_keys:
            lab.block("The Job returned an unrecognized or out-of-scope historical quote receipt")
        record = lab.evidence / "tdx-historical-reference.json"
        record.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")
        statements = (
            "The historical signed TDX quote verifies under Intel's embedded root and matches its expected bindings",
            "The TDX verifier denies an expired certificate and rejects incorrect expected bindings for the same quote",
            "The archived collateral profile rejects the signed quote because the TCB has no matching level",
        )
        for (phase, fields), claim in zip(checks.items(), statements):
            observed = {name: document[name] is True for name in fields}
            lab.check(phase, claim, all(observed.values()), observed)
        check_signed_collateral(lab, signed_collateral)
    finally:
        lab.command("docker", "image", "rm", image, timeout=30, allow_failure=True)
