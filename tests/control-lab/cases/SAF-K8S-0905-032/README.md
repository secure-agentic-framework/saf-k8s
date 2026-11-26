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
