"""Authenticate a public archived Azure CPU/GPU capture and enforce an inert use gate."""

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time
from zipfile import ZipFile

HERE = Path(__file__).with_name("hcl-reference")
ARCHIVE_URL = "https://untrustsecurity.com/evidence/azure-ncc-h100-v5-457a6507.zip"
ARCHIVE_SHA256 = "457a6507bbe030fa1035af7e6ff0004e3920e8f413b3a0e11ebb1d6e3e398bf5"
AMD_KDS = "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"
AMD_KDS_SHA256 = "e6ecc853fa56d3170a624d40851f98a1036f974b50204ea69e6aec91d777aca3"
NVIDIA_ROOT = (
    "https://raw.githubusercontent.com/NVIDIA/nvtrust/78e7aa5fd4a3c7453ef09f2e7c1a24f3be7fc40d/"
    "guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/certs/verifier_device_root.pem"
)
NVIDIA_ROOT_SHA256 = "6e6e91e84068cb7de2c715ca73d6df168a16b23d96a895b42e553b297a471bfc"
MEMBERS = (
    "cpu/certs/ark.pem", "cpu/certs/ask.pem", "cpu/certs/genoa-vcek.crl", "cpu/certs/vcek.der",
    "cpu/hcl.bin", "cpu/snp-report.bin", "gpu/gpu-cert-chain.pem", "gpu/nonce.hex",
    "gpu/spdm-evidence.bin", "vtpm/user.bin",
)
JOB = "fixture-archived-compute"
VERIFIER_NAMESPACE = "saf-archive-proof"
PARAMS = "fixture-archived-compute-assessment"
TARGET = "fixture-sensitive-pre-use"
POLICY = "fixture-confidential-pre-use"
DENIAL = "Sensitive fixture use requires an approved CPU and GPU assessment"
PLATFORMS = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}
EXPECTED = {
    "schema": "saf-azure-hcl-spdm-v1", "evaluation_time_utc": "2026-10-06T04:27:47Z",
    "cpu": {"amd_snp_signature_and_signer_verified": True, "amd_archived_revocation_checked": True,
            "hcl_runtime_claims_bound": True, "secure_boot_enabled": False, "cpu_challenge_matches": False},
    "gpu": {"nvidia_spdm_signature_and_signer_verified": True, "gpu_capture_challenge_matches": True,
            "gpu_challenge_matches_hcl_digest": False},
    "live_assurance_observed": False,
}


def fetch(lab, destination, url, digest):
    lab.command("curl", "--proto", "=https", "--proto-redir", "=https", "--fail", "--silent",
                "--show-error", "--location", "--max-redirs", "2", "--retry", "1", "--max-time", "20",
                "--max-filesize", "100000", "--output", str(destination), url, timeout=50)
    if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
        lab.block("A downloaded Azure archive input differs from its reviewed digest")


def image_build(lab, image):
    host = lab.command("docker", "info", "--format", "{{.Architecture}}", timeout=20).stdout.strip()
    platform = PLATFORMS.get(host)
    if platform is None:
        lab.block("The Azure reference needs a Linux amd64 or arm64 Docker host")
    with TemporaryDirectory(prefix="saf-azure-hcl-") as name:
        work = Path(name)
        fetch(lab, work / "capture.zip", ARCHIVE_URL, ARCHIVE_SHA256)
        fetch(lab, work / "amd-kds.pem", AMD_KDS, AMD_KDS_SHA256)
        fetch(lab, work / "nvidia.pem", NVIDIA_ROOT, NVIDIA_ROOT_SHA256)
        with ZipFile(work / "capture.zip") as archive:
            names = archive.namelist()
            for relative in MEMBERS:
                member = "azure-ncc-h100-v5/" + relative
                if names.count(member) != 1 or not 0 < archive.getinfo(member).file_size <= 32000:
                    lab.block("The Azure archive does not have the expected bounded inputs")
                target = work / "capture" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(member))
        source = work / "src"
        source.mkdir()
        for name in ("main.go", "cpu.go", "gpu.go", "go.mod", "go.sum"):
            (source / name).write_bytes((HERE / name).read_bytes())
        lab.command("env", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux",
                    f"GOARCH={platform}", "CGO_ENABLED=0", "go", "-C", str(source),
                    "build", "-mod=readonly", "-trimpath", "-o", str(work / "verify"), ".", timeout=180)
        (work / "Dockerfile").write_text(
            "FROM scratch\nCOPY --chmod=0555 verify /verify\nCOPY capture /capture\n"
            "COPY amd-kds.pem nvidia.pem /trust/\nUSER 65534:65534\n"
            'ENTRYPOINT ["/verify","/capture","/trust/amd-kds.pem","/trust/nvidia.pem"]\n')
        lab.command("docker", "build", "--network=none", "--provenance=false", "--platform", f"linux/{platform}",
                    "--tag", image, str(work), timeout=100)


def archived_assessment(lab):
    image = f"saf-k8s-local/azure-hcl-reference:{lab.cluster}"
    try:
        image_build(lab, image)
        lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=90)
        lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": VERIFIER_NAMESPACE,
                    "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}})

        def in_verifier_namespace(*args, **kwargs):
            return lab.kubectl("-n", VERIFIER_NAMESPACE, *args, **kwargs)

        def create_fixture(resource):
            in_verifier_namespace("create", "-f", "-", payload=json.dumps(resource))

        labels = {"fixture.example/azure-archive": JOB}
        create_fixture({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": JOB},
                    "spec": {"podSelector": {"matchLabels": labels},
                             "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []}})
        create_fixture({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": JOB},
                    "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 40,
                             "template": {"metadata": {"labels": labels}, "spec": {
                                 "restartPolicy": "Never", "automountServiceAccountToken": False,
                                 "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                     "seccompProfile": {"type": "RuntimeDefault"}},
                                 "containers": [{"name": "verify", "image": image, "imagePullPolicy": "Never",
                                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                                     "readOnlyRootFilesystem": True,
                                                                     "capabilities": {"drop": ["ALL"]}},
                                                 "resources": {"requests": {"cpu": "20m", "memory": "24Mi"},
                                                               "limits": {"cpu": "300m", "memory": "72Mi"}}}],
                             }}}})
        wait = in_verifier_namespace("wait", "--for=condition=complete", f"job/{JOB}", "--timeout=45s",
                                     timeout=55, allow_failure=True)
        if wait.returncode:
            in_verifier_namespace("get", "pods", "-l", f"job-name={JOB}", allow_failure=True)
            in_verifier_namespace("get", "events", "--field-selector", f"involvedObject.name={JOB}",
                                  allow_failure=True)
            in_verifier_namespace("logs", f"job/{JOB}", "--pod-running-timeout=3s", allow_failure=True)
            lab.block("The Azure archive verifier Job did not complete its fixture checks")
        output = in_verifier_namespace("logs", f"job/{JOB}").stdout
        if len(output) > 8192 or len(output.splitlines()) != 1:
            lab.block("The Azure archive verifier did not emit one bounded receipt")
        return json.loads(output)
    finally:
        lab.command("docker", "image", "rm", image, timeout=30, allow_failure=True)


def exact(value, expected):
    if type(expected) is dict:
        return (type(value) is dict and set(value) == set(expected)
                and all(exact(value[key], item) for key, item in expected.items()))
    return type(value) is type(expected) and value == expected


def admission(lab, fields):
    api = "admissionregistration.k8s.io/v1"
    expression = "params != null && has(params.data) && " + " && ".join(
        f"'{name}' in params.data && params.data['{name}'] == 'true'" for name in fields)
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE"], "resources": ["pods"]}]},
                         "matchConditions": [{"name": "exact-sensitive-fixture",
                                              "expression": f"object.metadata.name == '{TARGET}'"}],
                         "validations": [{"expression": expression, "message": DENIAL}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                         "paramRef": {"name": PARAMS, "namespace": "saf-test", "parameterNotFoundAction": "Deny"},
                         "matchResources": {"namespaceSelector":
                                            {"matchLabels": {"fixture.example/sensitive-placement": "true"}}}}})


def run(lab, request):
    observed = archived_assessment(lab)
    if not exact(observed, EXPECTED):
        lab.block("Unexpected archived CPU or GPU verification result")
    cpu, gpu = observed["cpu"], observed["gpu"]
    sources = {
        "independent_cpu_identity_and_claims_verified": cpu["amd_snp_signature_and_signer_verified"]
        and cpu["hcl_runtime_claims_bound"] and cpu["amd_archived_revocation_checked"],
        "independent_gpu_identity_and_transcript_verified": gpu["nvidia_spdm_signature_and_signer_verified"]
        and gpu["gpu_capture_challenge_matches"],
    }
    lab.check("archived-cpu-gpu-authenticity", "The two archived reports independently authenticate their signed claims",
              all(sources.values()), sources)
    request["metadata"]["name"] = TARGET
    initial = lab.create(request, dry_run=True, allow_failure=True)
    if initial.returncode:
        lab.block("The same scoped request did not pass placement admission before the assurance gate")
    qualified = {
        **sources, "secure_boot_enabled": cpu["secure_boot_enabled"],
        "fresh_cpu_challenge_matches": cpu["cpu_challenge_matches"],
        "gpu_challenge_matches_required_hcl_binding": gpu["gpu_challenge_matches_hcl_digest"],
    }
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": PARAMS}, "immutable": True,
                "data": {name: str(value).lower() for name, value in qualified.items()}})
    admission(lab, qualified)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        probe = lab.create(request, dry_run=True, allow_failure=True)
        if probe.returncode and DENIAL in probe.stderr:
            break
        time.sleep(0.5)
    else:
        lab.block("The API did not enforce the exact assurance gate denial")
    denied = lab.create(request, allow_failure=True)
    readback = lab.kubectl("get", "pod", TARGET, "--ignore-not-found", "-o", "name")
    verdict = {"initial_placement_only_request_accepted": initial.returncode == 0,
               "actual_create_denied_by_assurance_policy": denied.returncode != 0 and DENIAL in denied.stderr,
               "sensitive_fixture_absent": readback.stdout.strip() == "",
               "approved_assessment_absent": not all(qualified.values())}
    lab.check("archived-evidence-pre-use-denial", "Independently authentic archive reports cannot authorize fixture use",
              all(verdict.values()), verdict)
    artifact = {"source_archive_sha256": ARCHIVE_SHA256, **observed,
                "admission_conditions": qualified, "pod_admission": verdict}
    (lab.evidence / "archived-confidential-assurance.json").write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
