"""Verify synthetic signatures and exercise a relying-party policy in Kubernetes."""

import json
from pathlib import Path

SCOPE = "Actual OpenSSL signature checking and Kubernetes Jobs applying fixture binding, freshness, and reuse rules, plus a synthetic role-separated verifier-result and relying-party gate."
SCOPE += " A separate Kind Job verifies a signed historical Intel TDX quote and expected denials; live freshness remains outside this reference."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
JOB = "fixture-attestation-appraisal"
CONFIG = "fixture-attestation-appraisal"


def verified(lab, fixture, record):
    result = lab.command("openssl", "dgst", "-sha256", "-verify", str(fixture / "authority-public.pem"),
                         "-signature", str(fixture / "evidence-signature.der"), str(record), allow_failure=True)
    return result.returncode == 0 and "Verified OK" in result.stdout


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    root = Path(__file__).parent
    record = root / "evidence-record.json"
    claims = json.loads(record.read_text())
    changed_claims = dict(claims, subject="fixture-other-assertion")
    changed = lab.kubeconfig.parent / "changed-fixture-evidence.json"
    changed.write_text(json.dumps(changed_claims))
    signature_ok = verified(lab, root, record)
    changed_signature_ok = verified(lab, root, changed)
    expected = {"record": claims, "signature_verified": signature_ok, "expected_subject": "fixture-workload",
                "expected_reference": "fixture-approved-measurement", "expected_challenge": "fixture-challenge-x", "now": 14}
    examples = [
        dict(expected, name="wrong-subject", expected_subject="fixture-unapproved"),
        dict(expected, name="wrong-measurement", expected_reference="fixture-other-measurement"),
        dict(expected, name="expired", now=20),
        dict(expected, name="wrong-challenge", expected_challenge="fixture-challenge-y"),
        dict(expected, name="changed", record=changed_claims, signature_verified=changed_signature_ok),
        dict(expected, name="fresh"),
        dict(expected, name="repeated"),
    ]
    naive_accepts = [item["name"] for item in examples if item["signature_verified"]]
    lab.check("red", "Valid signature bytes alone also pass stale, mismatched and repeated requests",
              naive_accepts == ["wrong-subject", "wrong-measurement", "expired", "wrong-challenge", "fresh", "repeated"],
              {"signature_only_passes_expired_and_repeated": "expired" in naive_accepts and "repeated" in naive_accepts})
    data = {"requests.json": json.dumps(examples), "appraise-fixture.py": (root / "appraise-fixture.py").read_text()}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG}, "immutable": True, "data": data})
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": JOB},
                "spec": {"backoffLimit": 0, "template": {"spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "fixture", "configMap": {"name": CONFIG}}],
                    "containers": [{"name": "compare", "image": IMAGE, "command": ["python", "/fixture/appraise-fixture.py"],
                                    "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                                    "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                  "limits": {"cpu": "100m", "memory": "40Mi"}},
                                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                        "capabilities": {"drop": ["ALL"]}}}]}}}})
    lab.kubectl("wait", "--for=condition=complete", f"job/{JOB}", "--timeout=60s", timeout=70)
    observed = json.loads(lab.kubectl("logs", f"job/{JOB}").stdout)
    rejected = {name: outcome for name, outcome in observed.items() if name != "fresh"}
    lab.check("green", "The live Job rejects wrong bindings, stale evidence, an unapproved challenge, changed bytes and reuse",
              rejected == {"wrong-subject": "binding-mismatch", "wrong-measurement": "binding-mismatch",
                           "expired": "outside-validity", "wrong-challenge": "challenge-mismatch",
                           "changed": "invalid-signature", "repeated": "already-used"}, rejected)
    lab.check("positive", "The fresh authentic matching fixture is eligible exactly once",
              observed["fresh"] == "eligible-fixture" and observed["repeated"] == "already-used",
              {"fresh_matching_fixture_eligible": observed["fresh"] == "eligible-fixture", "repeated_denied": observed["repeated"] == "already-used"})
    (lab.evidence / "attestation-appraisal-observations.json").write_text(json.dumps({
        "inert_signature_verified": signature_ok, "changed_signature_verified": changed_signature_ok,
        "relying_party_fixture_results": observed, "hardware_attestation_tested": False}, indent=2) + "\n")
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("saf_0804_002_cross_verifier", root / "cross_verifier.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run(lab, root)

    result_spec = spec_from_file_location("saf_0804_002_verifier_result_boundary", root / "verifier_result_boundary.py")
    result_module = module_from_spec(result_spec)
    result_spec.loader.exec_module(result_module)
    result_module.run(lab, root)

    tdx_spec = spec_from_file_location("saf_0804_002_historical_tdx", root / "tdx_reference.py")
    tdx_module = module_from_spec(tdx_spec)
    tdx_spec.loader.exec_module(tdx_module)
    tdx_module.run(lab)
