# Compile-only evidence

The circuit sources compiled with a pinned MP-SPDZ v0.4.4 source snapshot. The
private program command is
`PYTHONPATH="$PWD/Programs/Source" python3 -B compile.py -B 1 -a quantized_median.asm quantized_median`;
the calibration command is
`PYTHONPATH="$PWD/Programs/Source" python3 -B compile.py -B 1 saf_quantized_median_calibration`.
The schedule hash includes the assembly argument and therefore must match this
exact command. The integration rebuilds from the official release archive
whose SHA-256 is pinned in `build_runtime.py`, requests the assembly listing,
and checks the compiled artifact hashes below. No MP-SPDZ runtime, Kind,
Docker, or cluster was executed for this compile-only evidence.

Compiler output for `quantized_median` reports exactly 8 private bit inputs for
each of parties 0, 1, and 2. Its generated assembly contains 16 `bitb`
instructions (two fresh secret random bits for each of eight output bits) and
one `reveal` instruction over the eight output bits. The source places that
reveal after both fixed rounds. The calibration program reports no private
inputs and compiles 1,024 public calibration rows.

Compiled artifact SHA-256 values:

| Artifact | SHA-256 |
|---|---|
| `quantized_median-0.bc` | `7638664c1edbbd41c1de2b97c06e58f3a460d0a620ab1c3a574467f0e1d93f7d` |
| `quantized_median.sch` | `ea1c784edddc5ce83120f2626da560192f2e36f8687ef38bbf5c8b0e0ba7ea3d` |
| `quantized_median.asm-quantized_median-0` | `7948abb45fda40f5d98d046c8af57bddb618db0225bb9a8d5c1d83c92edf5dd6` |
| `saf_quantized_median_calibration-0.bc` | `a38563750b17fa0f9a6bf0944e6a4677bb8e2911c8685439516c3bba1b3b74f9` |
| `saf_quantized_median_calibration.sch` | `8e78f589546b57b95b3def3875cbc04e9d83414c628748c36edf22f1c30e23a7` |
