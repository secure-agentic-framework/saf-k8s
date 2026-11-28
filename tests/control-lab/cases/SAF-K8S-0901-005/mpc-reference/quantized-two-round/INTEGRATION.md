# Kind integration route

This route is additive to the `mpc-reference/case.py`: that case runs the
original one-bit suite first, unchanged, then invokes this route. It uses a
separate image, three `saf-fl-q-party-*` namespaces, a distinct namespace and
Pod label, its own immutable reservation, and a separate stable receipt. The
NetworkPolicy only selects Pods carrying the quantized route label, so it does
not authorize the legacy one-bit peers. The original check labels and evidence
file remain separate.

The route reuses the existing case's `resource`, namespaced create, pinned
Dockerfile, and MP-SPDZ v0.4.4 runtime model. Its enrollment code preserves
short-lived per-party certificates and sends private key/input material via
stdin into immutable fixture Secrets. The private workload receives only eight
binary tokens per participant. It does not access real records or run a
training workload.

## Source and artifact guards

`build_runtime.py` downloads the same MP-SPDZ v0.4.4 archive pinned by the
original route and checks its SHA-256. It compiles from a fresh temporary
extraction, first removes target bytecode/schedule/assembly outputs, verifies
the exact circuit source inventory and hashes, requests the quantized program's
assembly listing, then verifies the documented compiler artifact hashes. The
runtime executable and Debian Dockerfile are the existing pinned artifacts.
There is no persistent compiler cache path. `COMPILE_EVIDENCE.md` records the
previous compile-only evidence; it is not evidence of an MPC execution.

## Evidence boundary

The fixed public fixture comprises three participants, two rounds, three
examples per participant-round, and two coordinates per example. Thus the
fixture contains 18 synthetic examples (36 feature values). The host-side
oracle checks the quantizer and a complete finite mechanism table; only the
eight already quantized bits enter MPC. The result is update-vector-level
privacy for this finite mechanism, not record-level privacy, privacy for real
training data, training convergence, a production budget, or proof that a
malicious party deviated.

Each participant log is capped at 256 KiB and 1,100 lines before parsing. The
parser requires exactly the complete 1,024-row public calibration, one
eight-bit private output per participant, no extra application output, and
agreement across the three peers. The stored receipt excludes the random
output. The transcript is released to the participants and is present in Pod
stdout while the disposable cluster exists. The route retrieves bounded logs
directly into memory rather than placing their contents in `commands.log`; the
normalized receipt omits the random vector. This does not claim that the vector
is never persisted. Runtime execution in Kind remains a required next-stage
check; no Docker or cluster run is claimed here.
