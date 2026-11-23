# Local synthetic dataset integrity fixture

This is a defensive, local Kind lab. `case.py` exposes the SAF runner contract:
module-level `SCOPE` and `run(lab)`. The runner uses the real adjacent helper at
`HERE.parent / "SAF-K8S-0908-001" / "case.py"` and calls its `load_runtime(lab)`.
The helper supplies the lab's pinned local image. The workload namespace is
`saf-test`, which is owned by the outer runner; this case does not create it.

## What it demonstrates

- A baseline streams and accepts a fixed, benign deterministic alteration to
  one synthetic partition because it performs no trusted comparison.
- The governed path checks the exact partition inventory, declared byte length,
  and SHA-256 digest against the immutable `manifest.json`; it denies changed or
  missing content and accepts only `synthetic-approved-v1`.
- Each file is read in 257-byte chunks. At most two partition hash workers run
  concurrently. Output is one bounded summary with fixed labels, counts, and
  booleans; partition bytes and records are never logged.
- PVC and its consumer Pod are created before waiting. This supports storage
  classes using delayed `WaitForFirstConsumer` binding.

Run through the SAF harness by invoking `run(lab)` in the established local Kind
environment. This source packet does not invoke Docker or Kind. It also does not
create the runner-owned namespace.

## Evidence scope

The fixture is four 4 KiB synthetic partitions (16 KiB total), generated inside
the lab PVC. This is representative control wiring, not production-scale
benchmarking or production-storage evidence. It does not establish manifest
signing or publisher identity, storage durability, crash consistency, race
resistance against concurrent writers, access-path coverage, multi-node behavior,
or throughput/latency at training-data scale. Production evaluation must include
the trusted manifest distribution and approval chain, the actual storage and
ingestion path, workload concurrency, capacity/performance measurements, and
recovery behavior under the organization's threat model.

No hostile inputs, attack traffic, private data, or unowned targets are used.

The trusted fixture manifest also contains a Merkle root built from sorted
partition names, lengths and observed digests. Domain prefixes distinguish
leaves from parent nodes. An otherwise valid dataset with a mismatched root is
rejected. The retained observations include the derived root for the positive
case. This exercise uses an immutable manifest in a fresh cluster with separate
authority for installation. Production signing, partition storage and recovery
require evidence from the deployed system.
