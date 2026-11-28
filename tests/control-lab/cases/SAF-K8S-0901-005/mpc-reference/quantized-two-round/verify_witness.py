"""Exact finite oracle and strict native transcript verifier for the quantized proof."""

from collections import Counter
from fractions import Fraction
from itertools import combinations, product
import re

from synthetic_fixture import PARTY_VALUES, input_bits, quantized_negative_gradient, examples_for_q

CALIBRATION = re.compile(r"saf-quantized-calibration ([0-3]{3}) ([01]{4}) ([01]{2})")
PRIVATE = re.compile(r"saf-quantized-vector ([01]{8})")
NUMBER = r"\d+(?:\.\d+)?"
MAX_LOG_BYTES = 256 * 1024
MAX_LOG_LINES = 1100
RUNTIME_PATTERNS = re.compile(
    rf"Time = {NUMBER} seconds|"
    rf"Data sent = {NUMBER} MB in ~\d+ rounds \(party [012] only; use '-v' for more details\)|"
    rf"Global data sent = {NUMBER} MB \(all parties\)"
)
RUNTIME_MARKERS = {
    "Using statistical security parameter 40",
    "The following benchmarks are including preprocessing (offline phase).",
    "Significant amount of unused triples of replicated secret distorting the benchmark. "
    "This protocol has a large minimum batch size, which makes this unavoidable for small programs.",
    "Significant amount of unused bits of replicated secret distorting the benchmark. "
    "For more accurate benchmarks, consider reducing the batch size with --batch-size.",
}


def median3(values):
    if len(values) != 3 or any(value not in range(4) for value in values):
        raise ValueError("Expected three unsigned two-bit values")
    return sorted(values)[1]


def noisy_value(value, coins):
    if value not in range(4) or len(coins) != 4 or any(bit not in (0, 1) for bit in coins):
        raise ValueError("Invalid finite mechanism input")
    low = (value & 1) ^ (coins[0] & coins[1])
    high = ((value >> 1) & 1) ^ (coins[2] & coins[3])
    return low | (high << 1)


def expected_calibration():
    result = {}
    for values in product(range(4), repeat=3):
        aggregate = median3(values)
        for coins in product((0, 1), repeat=4):
            result[(values, coins)] = noisy_value(aggregate, coins)
    return result


def parse_calibration_line(line):
    match = CALIBRATION.fullmatch(line)
    if not match:
        return None
    values = tuple(map(int, match[1]))
    coins = tuple(map(int, match[2]))
    return (values, coins), int(match[3], 2)


def scalar_distribution(values):
    aggregate = median3(values)
    return Counter(noisy_value(aggregate, coins) for coins in product((0, 1), repeat=4))


def exact_scalar_oracle():
    expected = expected_calibration()
    adjacency_outcome_checks = 0
    maximum = Fraction(0, 1)
    for before in product(range(4), repeat=3):
        before_mass = scalar_distribution(before)
        if set(before_mass) != set(range(4)):
            raise AssertionError("Every released code must have positive probability")
        for position in range(3):
            for replacement in range(4):
                if replacement == before[position]:
                    continue
                after = list(before)
                after[position] = replacement
                after_mass = scalar_distribution(tuple(after))
                for output in range(4):
                    ratio = Fraction(before_mass[output], after_mass[output])
                    if ratio > maximum:
                        maximum = ratio
                    adjacency_outcome_checks += 1
    if adjacency_outcome_checks != 2304 or maximum != 9:
        raise AssertionError("Finite scalar mechanism differs from the reviewed bound")

    interval_checks = 0
    for corrupt in range(3):
        for honest_pair in combinations(range(4), 2):
            low, high = honest_pair
            for corrupt_value in range(4):
                values = [corrupt_value] * 3
                honest_positions = [index for index in range(3) if index != corrupt]
                values[honest_positions[0]], values[honest_positions[1]] = honest_pair
                if not low <= median3(values) <= high:
                    raise AssertionError("Median escaped the distinct honest interval")
                interval_checks += 1
    if interval_checks != 72:
        raise AssertionError("Unexpected distinct-honest interval case count")
    return expected, adjacency_outcome_checks, maximum, interval_checks


def verify_synthetic_fixture():
    expected_vectors = (
        (0, 0, 0, 0),
        (1, 2, 1, 2),
        (3, 3, 3, 3),
    )
    for party, (values, expected) in enumerate(zip(PARTY_VALUES, expected_vectors)):
        if values != expected:
            raise AssertionError("Fixed synthetic update values changed")
        reconstructed = []
        for round_number in range(2):
            q0, q1 = values[round_number * 2:round_number * 2 + 2]
            rows = examples_for_q(q0, q1)
            if quantized_negative_gradient(rows) != (q0, q1):
                raise AssertionError(f"Logistic-step quantization mismatch for party {party}, round {round_number}")
            reconstructed.extend((q0, q1))
        bit_string = input_bits(party)
        observed_values = tuple(bit_string[index] | (bit_string[index + 1] << 1)
                                for index in range(0, len(bit_string), 2))
        if observed_values != tuple(reconstructed) or len(bit_string) != 8:
            raise AssertionError("Eight participant input bits do not encode the fixed two-round gradient vector")
    for cell in range(4):
        values = [PARTY_VALUES[party][cell] for party in range(3)]
        if len(set(values)) != 3:
            raise AssertionError("The fixed honest values must be distinct for every corruption choice")
        for corrupt in range(3):
            honest = [values[index] for index in range(3) if index != corrupt]
            aggregate = median3(values)
            if not min(honest) <= aggregate <= max(honest):
                raise AssertionError("Fixed-case median escaped its honest interval")
    return 18  # 3 participants × 2 rounds × 3 shared two-feature examples.


def global_transcript_bound_witness():
    # One participant changes all four cells from q=0 to q=3. The two other
    # participants hold q=0 and q=3 in every cell, so each median changes 0→3.
    before = scalar_distribution((0, 0, 3))
    after = scalar_distribution((3, 0, 3))
    ratio = Fraction(before[0] ** 4, after[0] ** 4)
    if ratio != 6561:
        raise AssertionError("Exact full-vector participant adjacency witness changed")
    return ratio


def parse_logs(logs):
    if len(logs) != 3:
        raise ValueError("Expected exactly three enrolled participant logs")
    for log in logs:
        if len(log.encode("utf-8")) > MAX_LOG_BYTES or len(log.splitlines()) > MAX_LOG_LINES:
            raise ValueError("Participant log exceeded the reviewed byte or line bound")
    expected, adjacency_checks, maximum, interval_checks = exact_scalar_oracle()
    results = []
    for log in logs:
        calibration = {}
        vector_outputs = []
        private_seen = False
        for raw in log.splitlines():
            line = raw.rstrip()
            parsed = parse_calibration_line(line)
            if parsed:
                key, output = parsed
                if private_seen or key in calibration:
                    raise ValueError("Duplicate or late public calibration row")
                calibration[key] = output
            elif match := PRIVATE.fullmatch(line):
                private_seen = True
                vector_outputs.append(match[1])
            elif not RUNTIME_PATTERNS.fullmatch(line) and line not in RUNTIME_MARKERS:
                raise ValueError("Unexpected MPC output outside reviewed diagnostics")
        if calibration != expected:
            raise ValueError("Public two-bit calibration differs from independent exact oracle")
        if len(vector_outputs) != 1:
            raise ValueError("Each enrolled party must observe exactly one eight-bit vector transcript")
        results.append(vector_outputs[0])
    if len(set(results)) != 1:
        raise ValueError("The three enrolled parties disagree about the single vector release")
    transcript_maximum = global_transcript_bound_witness()
    if adjacency_checks != 2304 or maximum != 9 or interval_checks != 72:
        raise ValueError("The finite scalar privacy/robustness oracle changed")
    return {
        "calibration_rows_per_party": len(expected),
        "directed_scalar_adjacency_outcome_checks": adjacency_checks,
        "maximum_scalar_likelihood_ratio": int(maximum),
        "distinct_honest_interval_checks_per_scalar": interval_checks,
        "fixed_input_examples": verify_synthetic_fixture(),
        "fixed_rounds": 2,
        "fixed_coordinates": 2,
        "bits_per_participant": 8,
        "vector_transcripts_observed": 1,
        "maximum_participant_transcript_likelihood_ratio": int(transcript_maximum),
        "participant_level_epsilon": "8*ln(3)",
        "delta": 0,
        "scope": "finite quantized update vector; no record-level or production dataset claim",
    }


def self_test():
    expected, checks, maximum, interval = exact_scalar_oracle()
    examples = verify_synthetic_fixture()
    assert len(expected) == 1024
    assert checks == 2304 and maximum == 9 and interval == 72 and examples == 18
    # Equal vectors under one replacement attain the full participant transcript bound.
    per_cell = maximum
    assert per_cell ** 4 == 6561
    assert global_transcript_bound_witness() == 6561
    return {"calibration_rows": len(expected), "adjacency_outcome_checks": checks,
            "scalar_max_ratio": int(maximum), "honest_interval_checks": interval,
            "synthetic_examples": examples, "transcript_max_ratio": 6561}


if __name__ == "__main__":
    import json
    print(json.dumps(self_test(), sort_keys=True))
