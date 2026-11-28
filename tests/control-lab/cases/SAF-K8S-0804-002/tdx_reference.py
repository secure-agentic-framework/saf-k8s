"""Run the pinned historical quote checks as a separate restricted Kind Job."""

import json
import re
from pathlib import Path
from tempfile import TemporaryDirectory

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


def build(lab, image):
    host = lab.command("docker", "info", "--format", "{{.Architecture}}", timeout=15).stdout.strip()
    platform = ARCHITECTURES.get(host)
    if platform is None:
        lab.block("The TDX verifier fixture supports Linux amd64 or arm64")
    with TemporaryDirectory(prefix="saf-tdx-verifier-") as directory:
        scratch = Path(directory)
        for name in ("main.go", "go.mod", "go.sum"):
            (scratch / name).write_bytes((HERE / name).read_bytes())
        lab.command("env", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "CGO_ENABLED=0",
                    f"GOARCH={platform}", "go", "-C", str(scratch), "build", "-mod=readonly",
                    "-trimpath", "-o", "quote-check", ".", timeout=180)
        (scratch / "Dockerfile").write_text(
            "FROM scratch\nCOPY --chmod=0555 quote-check /quote-check\nENTRYPOINT [\"/quote-check\"]\n")
        lab.command("docker", "build", "--provenance=false", "--platform", f"linux/{platform}",
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
    finally:
        lab.command("docker", "image", "rm", image, timeout=30, allow_failure=True)
