"""Verify the public calibration and bound the single binary release."""

from collections import Counter
from fractions import Fraction
from itertools import product
import re

BITS = (0, 1)
CALIBRATION = re.compile(r"saf-public-calibration ([01]{5}) ([01])")
PRIVATE = re.compile(r"saf-private-update ([01])")
RUNTIME_MARKERS = {
    "Using statistical security parameter 40",
    "The following benchmarks are including preprocessing (offline phase).",
    "Significant amount of unused triples of replicated secret distorting the benchmark. "
    "This protocol has a large minimum batch size, which makes this unavoidable for small programs.",
    "Significant amount of unused bits of replicated secret distorting the benchmark. "
    "For more accurate benchmarks, consider reducing the batch size with --batch-size.",
}
NUMBER = r"\d+(?:\.\d+)?"
RUNTIME_PATTERNS = re.compile(
    rf"Time = {NUMBER} seconds|"
    rf"Data sent = {NUMBER} MB in ~\d+ rounds \(party [012] only; use '-v' for more details\)|"
    rf"Global data sent = {NUMBER} MB \(all parties\)"
)


def read_outputs(log):
    calibration = {}
    outputs = []
    for raw in log.splitlines():
        line = raw.rstrip()
        if match := CALIBRATION.fullmatch(line):
            update_and_coins = tuple(map(int, match[1]))
            if update_and_coins in calibration or outputs:
                raise ValueError("Unexpected repeated or late public calibration output")
            calibration[update_and_coins] = int(match[2])
        elif match := PRIVATE.fullmatch(line):
            outputs.append(match[1])
        elif not RUNTIME_PATTERNS.fullmatch(line) and line not in RUNTIME_MARKERS:
            raise ValueError("Unexpected MPC output outside the reviewed diagnostics")
    if len(outputs) != 1:
        raise ValueError("Each participant must observe exactly one noisy bit")
    return calibration, outputs[0]


def calibrated_output(updates, coins):
    median = sorted(updates)[1]
    return 1 - median if coins == (1, 1) else median


def likelihood_bound(calibration):
    inputs = tuple(product(BITS, repeat=3))
    mass = {x: Counter(calibration[x + coins] for coins in product(BITS, repeat=2)) for x in inputs}
    if any(set(count) != set(BITS) for count in mass.values()):
        raise ValueError("Both possible release values need positive probability")
    ratios = []
    for inputs_before in inputs:
        for position in range(3):
            adjacent = list(inputs_before)
            adjacent[position] ^= 1
            for output in BITS:
                ratios.append(Fraction(mass[inputs_before][output], mass[tuple(adjacent)][output]))
    return len(ratios), max(ratios)


def honest_agreement_checks(calibration):
    total = 0
    for dissenting in range(3):
        for agreed in BITS:
            updates = [agreed] * 3
            updates[dissenting] = 1 - agreed
            if calibration[tuple(updates) + (0, 0)] != agreed:
                raise ValueError("One differing input overrode the agreed updates")
            total += 1
    return total


def verify(logs):
    if len(logs) != 3:
        raise ValueError("Expected one log per enrolled participant")
    expected = {bits: calibrated_output(bits[:3], bits[3:]) for bits in product(BITS, repeat=5)}
    observed = [read_outputs(log) for log in logs]
    if any(calibration != expected for calibration, _ in observed):
        raise ValueError("The public truth table differs from the independent oracle")
    if len({output for _, output in observed}) != 1:
        raise ValueError("The peers disagree about the released bit")

    adjacency_count, bound = likelihood_bound(observed[0][0])
    if adjacency_count != 48 or bound != 3:
        raise ValueError("The exact likelihood-ratio bound differs from the reviewed binary mechanism")
    return {"agreed_noisy_outputs": 1, "calibration_rows_per_peer": len(expected),
            "directed_adjacency_outcome_checks": adjacency_count,
            "maximum_likelihood_ratio": int(bound), "epsilon_per_release": "ln(3)", "delta": 0,
            "honest_pair_agreement_checks": honest_agreement_checks(observed[0][0])}
