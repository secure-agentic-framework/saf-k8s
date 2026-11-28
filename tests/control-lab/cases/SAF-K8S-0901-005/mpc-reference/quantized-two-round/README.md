# Finite two-round quantized MPC reference

The SAF-K8S-0901-005 case invokes this finite mechanism after the one-bit
MP-SPDZ v0.4.4 checks. The host-only oracle checks and native Pod observations
produce separate evidence.

## Fixed mechanism

Three participant inputs contain four unsigned two-bit values each, ordered as
round 0 coordinate 0, round 0 coordinate 1, round 1 coordinate 0, round 1
coordinate 1. Each input therefore contains exactly eight secret bits. Both
rounds are fixed and nonadaptive. For each scalar value, the circuit computes
an integer median using a two-bit comparator and sorting network, then applies
independent two-bit randomized response to that value's two bits. It reveals
the concatenated eight-bit result once, after all four medians are computed.
The second fixed round does not consume a model updated by the first; this is
a bounded transcript-composition proof, not a training-convergence run.

The fixed synthetic participant values are `(0,0,0,0)`, `(1,2,1,2)`, and
`(3,3,3,3)`. Every participant-round has three public synthetic logistic
examples with two features in `{-1,+1}` and label 1. At zero model weights,
the mean negative gradient is `g_j = sum_i(x_ij)/6`; the fixed quantizer is
`q_j = 3*g_j + 3/2 = (sum_i(x_ij)+3)/2`, producing the selected integer in
`{0,1,2,3}` exactly. The verifier recomputes these values from the fixed
examples; the case should submit only the resulting eight secret bits per
participant.
In circuit input order (low bit then high bit for each scalar), the fixed
participant tokens are `00000000`, `10011001`, and `11111111`.

## Finite oracle and budget

The public calibration has 64 triples of two-bit inputs and 16 combinations
of four fixed noise coins (1,024 rows). The independent oracle checks 2,304
directed single-scalar adjacency/output ratios, whose maximum is 9, plus 72
distinct-honest-pair interval cases. With four independent scalar mechanisms,
the fixed transcript's participant-level adjacency changes one participant's
entire eight-bit update vector. The conservative pure-DP bound is
`9^4 = 6,561 = 3^8`, or `epsilon = 8*ln(3)`, `delta = 0`.

This is update-level privacy over the finite quantized vector. It is not
record-level privacy for the local examples or a real dataset. The robust
property is only that, for each coordinate and round, the integer median of
three values remains between the two distinct honest values when the third is
arbitrary. It does not show training convergence, broad Byzantine resilience,
production enrollment, or complete abort/output guarantees. The immutable
case-owned reservation binds the fixture to two logical rounds and one vector
transcript; it is not production release-budget enforcement.

## Host-only checks

```sh
python3 -m unittest -v test_oracle.py
python3 verify_witness.py
```

The verifier's native log path requires exactly 1,024 distinct public
calibration rows, one eight-bit private transcript per participant, and byte
for byte agreement of that transcript across all three logs. It rejects
unknown program output and never includes the random vector in the normalized
summary. A separate native run is needed before calling the circuit
demonstrated.

`entrypoint.sh` gives the static container-side run shape: it performs the
public calibration, then one private protocol command, and accepts exactly
eight input tokens for the participant. The native checker requires the
resulting single vector line from each party to be identical; calibration rows
may appear only before it.
