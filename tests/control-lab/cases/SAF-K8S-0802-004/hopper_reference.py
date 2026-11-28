"""Replay authentic archived Hopper evidence and both signed NVIDIA references."""

import base64
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent / "hopper-reference"
JOB = "hopper-archived-firmware"
PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SDK = "https://raw.githubusercontent.com/NVIDIA/attestation-sdk/da4949b4cd8e9ab95a27fced2eb08163877786a3/nv-attestation-sdk-cpp/unit-tests/testdata"
ROOTS = "https://raw.githubusercontent.com/NVIDIA/nvtrust/78e7aa5fd4a3c7453ef09f2e7c1a24f3be7fc40d/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/certs"
RIM = "https://rim.attestation.nvidia.com/v1/rim"
FILES = {
    "hopper-report.txt": (SDK + "/hopperAttestationReport.txt",
                          "6637193a75d34923cbbf5597741818c60e54db01476560f5815e96932179b1f5"),
    "hopper-chain.pem": (SDK + "/hopperCertChain.txt",
                         "6aaea7be4a70070c6abdd45cc07184988e7d13c7f2682cb49d049c6f9d232cae"),
    "nvidia-device-root.pem": (ROOTS + "/verifier_device_root.pem",
                               "6e6e91e84068cb7de2c715ca73d6df168a16b23d96a895b42e553b297a471bfc"),
    "nvidia-rim-root.pem": (ROOTS + "/verifier_RIM_root.pem",
                           "afe8d01ab79b451fc6401a00bd8d3cba283e67339bd902e14bb41171eacb99d1"),
}
REFERENCES = {
    "driver": ("NV_GPU_DRIVER_GH100_580.159.03", "8837324e2491e8e7898ffe1f7f8d3d5f6e364d7e563dea0bc0ba2c2547bb0acb"),
    "vbios": ("NV_GPU_VBIOS_1010_0205_862_9600740020", "d9bfa0ae2efb2ce981b59bfb87c0a9012eb319560a63f42ee13f17a91a27541a"),
}
ARCHITECTURES = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}
IDENTITY = {
    "schema": "saf-nvidia-hopper-archived-spdm-v1", "reference_evaluation_at_utc": "2026-11-23T00:00:00Z",
    "device_root_sha256": "102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48",
    "transcript_sha256": "daf8ea2aa9adeb64d3e95fdb1adc1e7d35f27224562fb176cc04895f864b6f8c",
    "measurement_record_sha256": "ccd646a0ba2f2fbdb91efaf5d666147b11f0012cc3021ef0d21dca00be8ede78",
    "measurement_count": 64, "driver_version": "580.159.03", "certificate_revocation_evaluated": False,
    "live_device_or_freshness_observed": False,
}
REJECTION_KEYS = ("changed_measurement_signature_denied", "embedded_root_without_trust_denied",
                  "pre_validity_chain_denied", "altered_driver_rim_denied", "altered_vbios_rim_denied",
                  "altered_measurement_values_fail_reference_comparison")

DOCKERFILE = f"""FROM {PYTHON} AS deps
COPY wheels /wheels
RUN python -m pip install --no-index --no-deps --disable-pip-version-check --no-cache-dir --target /vendor /wheels/*.whl
FROM {PYTHON}
ENV PYTHONPATH=/vendor PYTHONDONTWRITEBYTECODE=1
COPY --from=deps /vendor /vendor
WORKDIR /fixture
COPY spdm-check compare.py nvidia-rim-root.pem driver-rim.xml vbios-rim.xml /fixture/
ENTRYPOINT ["python","-B","/fixture/compare.py"]
"""


def fetch(lab, target, url, maximum):
    lab.command("curl", "--proto", "=https", "--proto-redir", "=https", "--fail", "--silent", "--show-error",
                "--location", "--retry", "1", "--max-time", "25", "--max-filesize", str(maximum),
                "--output", str(target), url, timeout=55)
    return target.read_bytes()


def bound(lab, raw, expected):
    if sha256(raw).hexdigest() != expected:
        lab.block("A pinned NVIDIA archive or verifier dependency differs from the reviewed bytes")


def build(lab, image):
    machine = lab.command("docker", "info", "--format", "{{.Architecture}}", timeout=15).stdout.strip()
    platform = ARCHITECTURES.get(machine)
    if platform is None:
        lab.block("The Hopper reference is supported on Kind arm64 and amd64")
    with TemporaryDirectory(prefix="saf-hopper-archive-") as directory:
        work = Path(directory)
        for name, (url, pin) in FILES.items():
            bound(lab, fetch(lab, work / name, url, 32768), pin)
        for part, (identifier, pin) in REFERENCES.items():
            carrier = fetch(lab, work / f"{part}.json", f"{RIM}/{identifier}", 131072)
            record = json.loads(carrier)
            if record.get("id") != identifier or record.get("rim_format") != "TCG":
                lab.block("NVIDIA RIM service did not return the selected TCG reference")
            xml = base64.b64decode(record["rim"], validate=True)
            bound(lab, xml, pin)
            (work / f"{part}-rim.xml").write_bytes(xml)
        wheels = work / "wheels"
        wheels.mkdir()
        for plan in json.loads((HERE / "wheels.json").read_text()).values():
            item = plan[platform]
            bound(lab, fetch(lab, wheels / item["filename"], item["url"], 12000000), item["sha256"])
        for name in ("main.go", "compare.py"):
            (work / name).write_bytes((HERE / name).read_bytes())
        lab.command("env", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOOS=linux",
                    "CGO_ENABLED=0", f"GOARCH={platform}", "go", "build", "-trimpath", "-o",
                    str(work / "spdm-check"), str(work / "main.go"), timeout=120)
        (work / "Dockerfile").write_text(DOCKERFILE)
        lab.command("docker", "build", "--provenance=false", "--network=none", "--platform", f"linux/{platform}",
                    "-t", image, str(work), timeout=125)
    lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=90)


def checked_receipt(lab, document):
    fields = {**{key: True for key in REJECTION_KEYS}, **IDENTITY,
              "archived_device_chain_and_signature_verified": True, "signed_report_fields_match_pinned_reference": True,
              "signed_reference_manifests_verified": True, "driver_rim_active_measurements_matched": 22,
              "vbios_rim_active_measurements_matched": 12}
    if not isinstance(document, dict) or document.keys() != fields.keys():
        lab.block("The Hopper verifier returned an unexpected receipt shape")
    (lab.evidence / "hopper-archived-firmware.json").write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")
    groups = (
        ("archived-device-measurements", "The archived NVIDIA device chain and SPDM signature bind the expected transcript and measurements",
         (*IDENTITY, "archived_device_chain_and_signature_verified", "signed_report_fields_match_pinned_reference")),
        ("signed-reference-comparison", "The signed driver and VBIOS references match 34 active Hopper measurement entries",
         ("signed_reference_manifests_verified", "driver_rim_active_measurements_matched", "vbios_rim_active_measurements_matched")),
        ("archived-reference-rejection", "The archived checks reject changed measurements, altered signed manifests and untrusted or early certificate chains",
         REJECTION_KEYS),
    )
    for phase, statement, keys in groups:
        observed = {key: document[key] for key in keys}
        lab.check(phase, statement, all(document[key] == fields[key] and type(document[key]) is type(fields[key])
                                        for key in keys), observed)


def run(lab):
    image = f"saf-k8s-local/hopper-archive:{lab.cluster}"
    labels = {"fixture.example/hopper-reference": JOB}
    try:
        build(lab, image)
        lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": JOB},
                    "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress", "Egress"],
                             "ingress": [], "egress": []}})
        lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": JOB},
                    "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 40,
                             "template": {"metadata": {"labels": labels}, "spec": {
                                 "restartPolicy": "Never", "automountServiceAccountToken": False,
                                 "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                     "seccompProfile": {"type": "RuntimeDefault"}},
                                 "volumes": [{"name": "scratch", "emptyDir": {"sizeLimit": "4Mi"}}],
                                 "containers": [{"name": "verify", "image": image, "imagePullPolicy": "Never",
                                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                                     "readOnlyRootFilesystem": True,
                                                                     "capabilities": {"drop": ["ALL"]}},
                                                 "volumeMounts": [{"name": "scratch", "mountPath": "/tmp"}],
                                                 "resources": {"requests": {"cpu": "15m", "memory": "30Mi"},
                                                               "limits": {"cpu": "250m", "memory": "120Mi"}}}]}}}})
        result = lab.kubectl("wait", "--for=condition=complete", f"job/{JOB}", "--timeout=55s",
                              timeout=60, allow_failure=True)
        output = lab.kubectl("logs", f"job/{JOB}", allow_failure=bool(result.returncode)).stdout
        if result.returncode or len(output) > 8192 or len(output.splitlines()) != 1:
            lab.block("The archived Hopper verifier did not complete with one normalized receipt")
        document = json.loads(output)
        checked_receipt(lab, document)
        return document
    finally:
        lab.command("docker", "image", "rm", image, timeout=30, allow_failure=True)
