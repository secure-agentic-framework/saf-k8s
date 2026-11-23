# SAF-K8S-0905-032 — Enforce a model format allowlist before loading

    python3 lab.py test SAF-K8S-0905-032 --docker-context desktop-linux

One restricted Job compares an inert legacy representation with the format gate permissive and enforced. Both paths record the same input digest. The permissive path reaches a counted stub. The enforced gate denies that representation before any loader call. The same gate sends a small approved SafeTensors representation to a bounded loader and returns two expected values. The loader rejects the same legacy bytes when they are merely declared as SafeTensors.

The legacy fixture contains only inert bytes. The approved loader covers a deliberately small SafeTensors subset. Production parser and framework configurations, larger models, resource limits, full metadata validation, and all loading paths require separate evidence.

- [SafeTensors format](https://github.com/safetensors/safetensors#format)
- [PyTorch serialization guidance](https://docs.pytorch.org/docs/2.15/notes/serialization.html)
