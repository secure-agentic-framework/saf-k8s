"""Public, fixed logistic-step fixture and its exact two-bit quantizer."""

# q values ordered (round0/coordinate0, round0/coordinate1,
# round1/coordinate0, round1/coordinate1).
PARTY_VALUES = (
    (0, 0, 0, 0),
    (1, 2, 1, 2),
    (3, 3, 3, 3),
)
ROUNDS = 2
COORDINATES = 2
EXAMPLES_PER_STEP = 3


def examples_for_q(q0, q1):
    """Return three (x0,x1,y) examples with y=1 and x in {-1,+1}^2."""
    if q0 not in range(4) or q1 not in range(4):
        raise ValueError("Quantized coordinate must be an unsigned two-bit value")
    rows = []
    for index in range(EXAMPLES_PER_STEP):
        x0 = 1 if index < q0 else -1
        x1 = 1 if index < q1 else -1
        rows.append((x0, x1, 1))
    return tuple(rows)


def quantized_negative_gradient(rows):
    """At w=(0,0), q=3*g+3/2 where g is the mean negative logistic gradient."""
    if len(rows) != EXAMPLES_PER_STEP:
        raise ValueError("Each synthetic local step has exactly three examples")
    sums = [0, 0]
    for x0, x1, label in rows:
        if (x0 not in (-1, 1) or x1 not in (-1, 1) or label not in (0, 1)):
            raise ValueError("Unexpected synthetic logistic example")
        # At zero weights, negative gradient is (y - 1/2) * x.
        sums[0] += x0 * (2 * label - 1)
        sums[1] += x1 * (2 * label - 1)
    # g_j = sum_j / 6, so 3*g_j + 3/2 = (sum_j+3)/2 exactly.
    result = tuple((value + EXAMPLES_PER_STEP) // 2 for value in sums)
    if any(value not in range(4) for value in result):
        raise ValueError("The fixed quantizer produced a value outside its two-bit domain")
    return result


def input_bits(party):
    """Input file tokens: low then high bit for each round-coordinate value."""
    values = PARTY_VALUES[party]
    return tuple(bit for value in values for bit in (value & 1, (value >> 1) & 1))


def gradient_rows():
    return {
        f"party-{party}-round-{round_number}": examples_for_q(
            PARTY_VALUES[party][round_number * COORDINATES],
            PARTY_VALUES[party][round_number * COORDINATES + 1],
        )
        for party in range(3)
        for round_number in range(ROUNDS)
    }
