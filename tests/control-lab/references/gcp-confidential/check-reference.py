"""Check the expected decisions in a sanitized Confidential Space run receipt."""

import argparse
import json
from pathlib import Path

IDS = ("0804-001", "0804-002", "0804-004", "0804-005", "0804-006")


def verify(control, evidence):
    if evidence["schema"] != "saf-gcp-confidential-reference-v1":
        raise ValueError("Unknown reference receipt")
    probes = evidence["probes"]
    approved = probes["approved"]
    assert approved["access_decision"] == "allowed"
    assert approved["token_summary_trusted"] and approved["token_nonce_match"] and approved["fixture_matched"]
    assert approved["token_hwmodel"] == "GCP_AMD_SEV"
    assert evidence["cloud_cleanup"]["kms_versions_destroyed"]
    if control == "0804-001":
        assert probes["wrong_image"]["access_decision"] == "denied_as_expected"
        assert approved["inference_examples"] == 20_000_000
        assert evidence["profile"]["machine_type"] == "n2d-standard-2"
    elif control == "0804-002":
        wrong_challenge = probes["wrong_challenge"]
        altered = probes["altered_signature"]
        assert wrong_challenge["denial_stage"] == "sts_attribute_condition"
        assert altered["denial_stage"] == "sts_invalid_signature"
        assert evidence["negative_comparators"]["same_signed_token_bracketing_verified"]
    elif control == "0804-004":
        comparison = evidence["cpu_comparison"]
        assert comparison["matched_workload_image"] and comparison["matched_model_output"]
        assert len(comparison["ordinary_vm_cpu_ms"]) >= 3 and len(comparison["confidential_vm_cpu_ms"]) >= 3
        assert comparison["scope_decision"]
    elif control == "0804-005":
        retry = probes["after_revocation"]
        assert evidence["profile"]["resource"] == "Cloud KMS Decrypt"
        assert retry["token_summary_trusted"] and retry["denial_stage"] == "resource_forbidden"
        assert retry["denial_http_status"] == 403
        assert evidence["negative_comparators"]["pre_propagation_decrypt_succeeded"]
    elif control == "0804-006":
        assert probes["wrong_image"]["denial_stage"] == "sts_attribute_condition"
        updated = probes["authorized_update"]
        assert updated["access_decision"] == "allowed" and updated["fixture_matched"]
        assert evidence["image_digests"]["approved"] != evidence["image_digests"]["updated"]
        assert evidence["artifact_integrity"]["tampered_ciphertext_denied"]
        assert not evidence["artifact_integrity"]["returned_plaintext"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("control_id", choices=["SAF-K8S-" + value for value in IDS])
    parser.add_argument("receipt", nargs="?", type=Path, default=Path(__file__).with_name("cpu-reference.json"))
    args = parser.parse_args()
    verify(args.control_id.removeprefix("SAF-K8S-"), json.loads(args.receipt.read_bytes()))
    print("Verified", args.control_id, "reference assertions")


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("Run the evidence checker with assertions enabled")
    main()
