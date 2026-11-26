# SAF-K8S-0905-032 — Gate model format allowlists before loading

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-032 --docker-context desktop-linux` from the framework checkout.

A restricted Job runs seven checks. An inert legacy input reaches only a counted stub under permissive policy and is blocked before loading under the allowlist. A narrow fixture parser accepts known SafeTensors-framed values and reads zero values from the mislabeled inert input. A separate path uses the standard Python JSON loader. The exact approved digest and format reach the parser and return the expected weights. A wrong format label and other benign bytes with an unapproved digest each produce zero logical loader calls.

## Verify an adopted model loader

1. Inventory serving, training, fine-tuning, conversion and other model-loading entry points, including supported versions, dispatch configuration, file or object-store sources and any fallback. Identify where decision policy is enforced and who can alter it.
2. Approve each actual format, loader version and safety configuration. Compare the digest or other immutable identity of the admitted bytes to the bytes observed at the loader. Verify source and signed policy metadata through an independently controlled trust path.
3. Run approved harmless data through every in-scope entry point. Also run controlled cases with a disallowed format label, an unapproved digest and mismatched format and content. Record the denial and verify that the unsafe or alternate loader was never invoked, using instrumentation or trustworthy events. Review quarantine, exceptions and any independently authorized execution behavior.
4. Record effective production library settings and version-specific constraints for adopted model formats. Preserve fixture names, approved digests and detector outcomes without sharing model data.

- [SafeTensors format](https://github.com/huggingface/safetensors#format)
- [Python JSON decoder](https://docs.python.org/3.13/library/json.html)

## Upstream SafeTensors parser

Eight checks cover the original fixed-byte, allowlist and JSON observations and one grouped upstream parser comparison.

The new Job uses the exact digest-pinned Python 3.13.2 Alpine image from the published case. Before creating the Job, the case selects the wheel for the observed Kind node architecture and fetches the official `safetensors` 0.8.0 PyPI wheel. It verifies PyPI's SHA-256 value before storing the wheel as a case-owned ConfigMap; the tokenless Job checks the same digest and its own machine architecture before importing the package. The Pod has no network access requirement, uses read-only code/package mounts, and extracts the pinned wheel only into a size-limited memory-backed `emptyDir`. No package manager or transitive dependency installation is used.

The positive path admits one fixed F32[2] vector only when both the exact `safetensors` label and its independently pinned artifact digest match, then calls upstream `safetensors.deserialize` and compares the returned name, dtype, shape, and values. Three denied paths use the same shared pre-load format/digest gate: a wrong format label, a valid but unapproved inert vector digest, and the fixed legacy marker mislabeled as SafeTensors. Each asserts a zero parser-call delta. The case retains only stable JSON fields, digests, architecture, and fixed public numeric values.

### Package pins

The upstream PyPI release page lists `safetensors` 0.8.0 wheel hashes and platform tags:
<https://pypi.org/project/safetensors/0.8.0/>

- Linux musl ARM64: `safetensors-0.8.0-cp310-abi3-musllinux_1_2_aarch64.whl`, SHA-256 `87eec7ffed2b809f05a398a8becb7d013f19f7837cd15d9748580d6cf30dbaf4`.
- Linux musl x86-64: `safetensors-0.8.0-cp310-abi3-musllinux_1_2_x86_64.whl`, SHA-256 `8e080062fcde23be189565e1c3305d16751a218ecf9412c8601e64204eb6f846`.

PyPI marks these individual wheels as lacking provenance attestations. The fixture therefore establishes version and byte identity by the pinned published SHA-256, not independent publisher provenance. The implementation imports the real release's `deserialize` export as shown in its [v0.8.0 package source](https://raw.githubusercontent.com/huggingface/safetensors/v0.8.0/bindings/python/py_src/safetensors/__init__.py).

### Parser scope

This is an approved-format/runtime reference over one tiny inert tensor and three fixed denials. It does not test production models, arbitrary SafeTensors files, PyTorch, GPU use, hostile payloads, production dispatch configuration, or security of the format for every consumer. It does not replace the separate 0905-033 preflight/structure fixture.
