"""Authenticate the AWS-published Nitro archives and exercise current release denial."""

import base64
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time
from zipfile import ZipFile

HERE = Path(__file__).with_name("nitro-archive")
AWS_ROOT_URL = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"
AWS_ROOT_ARCHIVE = "8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c"
AWS_ROOT = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
EXAMPLE = (
    "https://raw.githubusercontent.com/aws-samples/aws-iot-validate-enclave-attestation/"
    "14e13acb5d896a897e11c5b3e71caf01412611c8"
)
ZERO_SHA = "c9f773ce17c720028abc33639bb4ba3e61077164bbfa410510e4b545d7d1ebfe"
MEASURED_SHA = "ad3e38b5f9617755c1d15912d16d784c4fb18eb35032997e87e2edcf74f77978"
WRAPPER_SHA = "16fce61891debbc695768e098d395c44552bf0aa5071a36d1cb4309c9dad18e9"
JOB = "fixture-nitro-archive"
ARCHITECTURES = {"aarch64": "arm64", "arm64": "arm64", "amd64": "amd64", "x86_64": "amd64"}


def check_digest(lab, data, digest):
    if hashlib.sha256(data).hexdigest() != digest:
        lab.block("A published Nitro fixture artifact differs from its reviewed digest")


def fetch(lab, path, url, digest):
    lab.command("curl", "--proto", "=https", "--proto-redir", "=https", "--fail", "--silent", "--show-error",
                "--location", "--retry", "1", "--max-time", "20", "--max-filesize", "12000",
                "--output", str(path), url, timeout=45)
    data = path.read_bytes()
    check_digest(lab, data, digest)
    return data


def prepare(lab, image):
    arch = lab.command("docker", "info", "--format", "{{.Architecture}}", timeout=20).stdout.strip()
    platform = ARCHITECTURES.get(arch)
    if platform is None:
        lab.block("The Nitro replay fixture needs a Docker arm64 or amd64 host")
    with TemporaryDirectory(prefix="saf-nitro-archive-") as name:
        work = Path(name)
        root_zip = fetch(lab, work / "aws-root.zip", AWS_ROOT_URL, AWS_ROOT_ARCHIVE)
        with ZipFile(io.BytesIO(root_zip)) as archive:
            if archive.namelist() != ["root.pem"] or not 0 < archive.getinfo("root.pem").file_size <= 4096:
                lab.block("The public Nitro root ZIP has an unexpected layout")
            (work / "root.pem").write_bytes(archive.read("root.pem"))
        fetch(lab, work / "zero.cose", EXAMPLE + "/validate_doc/att_doc_sample.bin", ZERO_SHA)
        document = fetch(lab, work / "example.json", EXAMPLE + "/python/example-attestation-doc.json", WRAPPER_SHA)
        carrier = json.loads(document)
        if set(carrier) != {"attestation", "attestation_size", "status"} or carrier["status"] != "success":
            lab.block("The AWS Nitro document wrapper has an unexpected shape")
        measured = base64.b64decode(carrier["attestation"], validate=True)
        if len(measured) != carrier["attestation_size"]:
            lab.block("The AWS wrapper and Nitro document lengths differ")
        check_digest(lab, measured, MEASURED_SHA)
        (work / "measured.cose").write_bytes(measured)

        source = work / "src"
        source.mkdir()
        for entry in ("go.mod", "go.sum", "main.go"):
            (source / entry).write_bytes((HERE / entry).read_bytes())
        # Build explicitly from the proof-bound module without modifying its checksum inputs.
        lab.command("env", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux",
                    f"GOARCH={platform}", "CGO_ENABLED=0", "go", "-C", str(source), "build",
                    "-mod=readonly", "-trimpath", "-o", str(work / "fixture"), ".", timeout=120)
        (work / "Dockerfile").write_text(
            "FROM scratch\nCOPY fixture /fixture\nCOPY root.pem zero.cose measured.cose /inputs/\n"
            "USER 65534:65534\nENTRYPOINT [\"/fixture\",\"/inputs/root.pem\","
            "\"/inputs/zero.cose\",\"/inputs/measured.cose\"]\n", encoding="utf-8")
        lab.command("docker", "build", "--network=none", "--provenance=false", "--platform", f"linux/{platform}",
                    "--tag", image, str(work), timeout=90)


def evaluate_in_kind(lab):
    image = f"saf-k8s-local/nitro-archive:{lab.cluster}"
    prepare(lab, image)
    try:
        lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=90)
        labels = {"fixture.example/nitro-archive": JOB}
        lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": JOB},
                    "spec": {"podSelector": {"matchLabels": labels},
                             "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []}})
        lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": JOB},
                    "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 45,
                             "template": {"metadata": {"labels": labels}, "spec": {
                                 "restartPolicy": "Never", "automountServiceAccountToken": False,
                                 "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                     "seccompProfile": {"type": "RuntimeDefault"}},
                                 "containers": [{"name": "verify", "image": image, "imagePullPolicy": "Never",
                                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                                     "readOnlyRootFilesystem": True,
                                                                     "capabilities": {"drop": ["ALL"]}},
                                                 "resources": {"requests": {"cpu": "15m", "memory": "16Mi"},
                                                               "limits": {"cpu": "300m", "memory": "64Mi"}}}],
                             }}}})
        complete = lab.kubectl("wait", "--for=condition=complete", f"job/{JOB}", "--timeout=55s",
                                timeout=65, allow_failure=True)
        output = lab.kubectl("logs", f"job/{JOB}", allow_failure=bool(complete.returncode)).stdout
        if complete.returncode or len(output) > 8192 or len(output.splitlines()) != 1:
            lab.block("The Nitro archive fixture did not complete with one normalized result")
        return json.loads(output)
    finally:
        lab.command("docker", "image", "rm", image, timeout=25, allow_failure=True)


def sample_expectation(digest, timestamp, measured):
    return {"document_sha256": digest, "timestamp_ms": timestamp, "authentic_at_issuance": True,
            "approved_measurements_match": measured, "has_nonzero_pcr0_through_pcr2": measured,
            "nonce_present": False, "requested_nonce_matches": False, "recipient_key_present": False,
            "recipient_satisfies_policy": False, "live_certificate_valid": False, "fresh_timestamp": False,
            "release_allowed": False}


def evidence_exact(value, expected):
    if type(expected) is dict:
        return (type(value) is dict and set(value) == set(expected)
                and all(evidence_exact(value[key], field) for key, field in expected.items()))
    return type(value) is type(expected) and value == expected


def run(lab, grant, see_decision, principal, workload, target, role):
    observed = evaluate_in_kind(lab)
    expected = {
        "schema": "saf-nitro-archive-release-v1", "aws_root_sha256": AWS_ROOT,
        "sample_decisions": {
            "debug": sample_expectation(ZERO_SHA, 1680004560937, False),
            "measured": sample_expectation(MEASURED_SHA, 1686060167435, True),
        },
        "bad_signature_rejected": True, "payload_change_rejected_by_signature": True,
    }
    if not evidence_exact(observed, expected):
        lab.block("Unexpected archived Nitro verification or live release decisions")
    historic = {"both_documents_authentic_at_issuance": True,
                "zero_pcrs_distinguished_from_pinned_measurements": True,
                "changed_signature_and_changed_payload_rejected": True}
    lab.check("nitro-historical-attestation", "Two archived Nitro documents verify at issuance against the pinned AWS root",
              all(historic.values()), historic)

    def apply_decision(label, permitted):
        now = int(time.time())
        return grant(lab, {"subject": workload, "resource": target,
                           "appraisal": "fixture-approved" if permitted else "fixture-denied",
                           "valid_after": now - 1, "expires": now + 60, "review": label}, now)

    # Show that the same marker would be exposed if authentication were the only gate.
    try:
        authentic = observed["sample_decisions"]["measured"]["authentic_at_issuance"]
        granted = apply_decision("archive-authentication-only-comparator", authentic)
        effective = see_decision(lab, workload, target, True)
        marker = lab.kubectl("--as", principal(workload), "get", "configmap", target, "-o", "json")
        comparator = granted and effective and json.loads(marker.stdout)["data"]["marker"] == target + "-public"
    finally:
        lab.kubectl("delete", "rolebinding", role, "--ignore-not-found")
    see_decision(lab, workload, target, False)
    decisions = {name: apply_decision("nitro-current-" + name, verdict["release_allowed"])
                 for name, verdict in observed["sample_decisions"].items()}
    binding = lab.kubectl("get", "rolebinding", role, "--ignore-not-found", "-o", "name")
    marker = lab.kubectl("--as", principal(workload), "get", "configmap", target, allow_failure=True)
    denial = {
        "authentication_only_counterfactual_exposed_owned_marker": comparator,
        "both_sample_decisions_denied_current_grant": all(value is False for value in decisions.values()),
        "grant_absent": binding.stdout.strip() == "",
        "actual_marker_read_forbidden": marker.returncode != 0 and "(Forbidden)" in marker.stderr and target in marker.stderr,
        "expired_chain_and_missing_challenge_and_recipient_observed_for_both": True,
    }
    lab.check("nitro-current-release-denial", "Historic Nitro authenticity alone cannot authorize the current fixture read",
              all(denial.values()), denial)
    (lab.evidence / "nitro-archived-release.json").write_text(
        json.dumps({**observed, "marker_authorization": denial}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
