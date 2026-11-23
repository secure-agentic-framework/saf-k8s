"""Verify authenticated artifact context and actual Kubernetes storage round trip."""

import json
from pathlib import Path
import shutil

SCOPE = ("Local AES-GCM round trip through an immutable Kubernetes ConfigMap, using an inert public marker and "
         "modeled identity and policy. The randomized fixture key and nonce stay inside one local process.")


def run(lab):
    if not shutil.which("go"):
        lab.block("The offline standard-library Go fixture needs a local Go toolchain")
    fixture = Path(__file__).with_name("sealed-fixture.go")
    result = lab.command("env", "GO111MODULE=off", "GOTOOLCHAIN=local", "GOPROXY=off", "CGO_ENABLED=0",
                         "go", "run", str(fixture), str(lab.kubeconfig), f"kind-{lab.cluster}", timeout=105)
    observed = json.loads(result.stdout)
    red = {key: observed[key] for key in (
        "unbound_artifact_opened_without_identity", "bound_artifact_requires_context")}
    green = {key: observed[key] for key in (
        "different_measurement_denied", "changed_policy_denied", "tampered_ciphertext_denied")}
    positive = {key: observed[key] for key in (
        "approved_context_opened", "api_round_trip_retained_immutable_record")}
    lab.check("red", "Authenticating the declared context prevents the unbound baseline behavior", all(red.values()), red)
    lab.check("green", "A changed measurement, policy, or ciphertext causes authentication to fail", all(green.values()), green)
    lab.check("positive", "The intended context opens the artifact retrieved from the Kubernetes API", all(positive.values()), positive)
    (lab.evidence / "sealed-artifact-observations.json").write_text(
        json.dumps({**observed, "hardware_sealing_tested": False}, indent=2) + "\n")
