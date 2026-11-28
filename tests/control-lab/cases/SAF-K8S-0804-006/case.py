"""Verify authenticated artifact context and actual Kubernetes storage round trip."""

import json
from pathlib import Path
import runpy
import shutil

SCOPE = ("Local AES-GCM round trip through an immutable Kubernetes ConfigMap, plus a separate TLS key broker "
         "Pod and recipient workload using live Kubernetes TokenReview for workload identity. An independent "
         "fixture signer supplies synthetic measurements. Hardware sealing, measured platform attestation, "
         "and production key custody and lifecycle require deployment evidence.")


def run(lab):
    if not shutil.which("go"):
        lab.block("The offline standard-library Go fixture needs a local Go toolchain")
    fixture = Path(__file__).with_name("sealed-fixture.go")
    result = lab.command("env", "GO111MODULE=off", "GOTOOLCHAIN=local", "GOPROXY=off", "CGO_ENABLED=0",
                         "go", "run", str(fixture), str(lab.kubeconfig), f"kind-{lab.cluster}", timeout=105)
    observed = json.loads(result.stdout)
    expected = {
        "unbound_artifact_opened_without_identity", "bound_artifact_requires_context",
        "different_measurement_denied", "changed_policy_denied", "tampered_ciphertext_denied",
        "approved_context_opened", "api_round_trip_retained_immutable_record",
        "artifact_identity_change_denied", "artifact_digest_change_denied", "recipient_change_denied",
        "record_identity",
    }
    bool_keys = expected - {"record_identity"}
    record = observed.get("record_identity")
    expected_record = {
        "name": "fixture-sealed-artifact", "namespace": "saf-test", "immutable": True,
        "artifact_id": "fixture-artifact-model-v1",
        "artifact_sha256": "cb71213bf3252256800c2a348026439736a6ecb45b9a41576679534886d35f91",
        "recipient": "fixture-recipient-workload-v1",
        "plaintext_sha256_checked": "cb71213bf3252256800c2a348026439736a6ecb45b9a41576679534886d35f91",
    }
    if (set(observed) != expected or any(type(observed[key]) is not bool for key in bool_keys) or
            type(record) is not dict or record != expected_record):
        lab.block("The fixture returned malformed or incomplete boolean observations")
    red = {key: observed[key] for key in (
        "unbound_artifact_opened_without_identity", "bound_artifact_requires_context")}
    green = {key: observed[key] for key in (
        "different_measurement_denied", "changed_policy_denied", "tampered_ciphertext_denied")}
    positive = {key: observed[key] for key in (
        "approved_context_opened", "api_round_trip_retained_immutable_record")}
    binding = {key: observed[key] for key in (
        "artifact_identity_change_denied", "artifact_digest_change_denied", "recipient_change_denied")}
    lab.check("red", "Authenticating the declared context prevents the unbound baseline behavior", all(red.values()), red)
    lab.check("green", "A changed measurement, policy, or ciphertext causes authentication to fail", all(green.values()), green)
    lab.check("positive", "The intended context opens the artifact retrieved from the Kubernetes API", all(positive.values()), positive)
    lab.check("artifact_recipient_binding", "The authenticated context binds the fixed artifact identity, digest, and recipient",
              all(binding.values()), binding)
    (lab.evidence / "sealed-artifact-observations.json").write_text(
        json.dumps({**observed, "hardware_sealing_tested": False}, indent=2) + "\n")

    runpy.run_path(str(Path(__file__).with_name("broker_case.py")))["run"](lab)
