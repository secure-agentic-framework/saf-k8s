# SAF-K8S-0905-033 — Validate model structure and metadata before loading

From the framework checkout run `python3 tests/control-lab/lab.py test SAF-K8S-0905-033 --docker-context desktop-linux`.

A restricted Job uses the official digest-pinned SafeTensors 0.8.0 native loader on owned numeric tensors. The four checks compare a permissive baseline with a versioned preflight. The preflight refuses an unapproved dtype, wrong payload size and an unrecognized harmless descriptor field before the native loader is called. The independent test controller reconstructs the expected digest of that last input. The loader returns the exact approved F32 values.

## Verify an adopted preflight

1. Inventory training, fine-tuning, inference, reload and promotion paths. Record the format, actual parser and framework version, loader entry point, authorized tensor/schema/metadata profile, size and resource bounds, and policy revision at each path.
2. Verify validation and loading see the same immutable digest or content-addressed object. Exercise approved numeric inputs and controlled benign mismatches in representation, size and metadata. Record the exact artifact and policy identity, sanitized reason and instrumented evidence that rejected input did not reach the loader.
3. Record how other model formats and paths are covered. Version changes and newly approved formats require reviewing and retesting the applicable fields and loader behavior.

- [SafeTensors format](https://github.com/huggingface/safetensors#format)
- [SafeTensors 0.8.0 release files](https://pypi.org/project/safetensors/0.8.0/)
