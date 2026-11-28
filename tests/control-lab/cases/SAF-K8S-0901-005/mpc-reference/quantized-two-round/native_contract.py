"""Exact case-owned one-vector reservation and native receipt fields."""

from synthetic_fixture import input_bits

RESERVATION_NAME = "mpc-two-round-vector-reservation"
RESERVATION_DATA = {
    "profile": "finite-quantized-mpc-reference-v1",
    "logical_rounds": "2",
    "coordinates": "2",
    "bits_per_participant": "8",
    "maximum_vector_transcripts": "1",
    "maximum_participant_transcript_likelihood_ratio": "6561",
    "epsilon": "8*ln(3)",
    "delta": "0",
}


def reservation_manifest():
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": RESERVATION_NAME, "namespace": "saf-test"},
        "immutable": True,
        "data": dict(RESERVATION_DATA),
    }


def reservation_matches(resource):
    metadata = resource.get("metadata", {})
    return (
        resource.get("kind") == "ConfigMap"
        and metadata.get("name") == RESERVATION_NAME
        and metadata.get("namespace") == "saf-test"
        and resource.get("immutable") is True
        and resource.get("data") == RESERVATION_DATA
    )


def duplicate_rejected(result):
    return result.returncode != 0 and "AlreadyExists" in result.stderr


def input_file_text(party):
    bits = input_bits(party)
    if len(bits) != 8 or any(bit not in (0, 1) for bit in bits):
        raise ValueError("Each participant input file must contain exactly eight binary tokens")
    return "".join(f"{bit}\n" for bit in bits)


def stable_receipt(oracle):
    """Project stable claims only; never include the random released vector."""
    required = {
        "calibration_rows_per_party": 1024,
        "directed_scalar_adjacency_outcome_checks": 2304,
        "maximum_scalar_likelihood_ratio": 9,
        "distinct_honest_interval_checks_per_scalar": 72,
        "fixed_input_examples": 18,
        "fixed_rounds": 2,
        "fixed_coordinates": 2,
        "bits_per_participant": 8,
        "vector_transcripts_observed": 1,
        "maximum_participant_transcript_likelihood_ratio": 6561,
        "participant_level_epsilon": "8*ln(3)",
        "delta": 0,
        "scope": "finite quantized update vector; no record-level or production dataset claim",
    }
    if any(oracle.get(key) != value for key, value in required.items()):
        raise ValueError("Finite-MPC proof summary differs from the reserved case budget")
    return {**oracle, "release_reservation": "immutable-case-owned-record",
            "production_enforcement_claimed": False,
            "random_vector_in_normalized_receipt": False}
