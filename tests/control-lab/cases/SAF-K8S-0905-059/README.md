# SAF-K8S-0905-059 — Attach and retain external model lineage

    python3 tests/control-lab/lab.py test SAF-K8S-0905-059 --docker-context desktop-linux

The baseline stores the inert fixture in OCI without a lineage record. Governed intake validates the external origin, exact model hash, JSON structure scan, approval and internalization date. It publishes the approved tag after reading back the lineage attachment at the exact OCI manifest digest. The model and attached record are read back again after replacing the registry Pod. The fixture uses the OCI referrers tag fallback and a disposable registry PVC.

The fixture scanner checks this JSON structure. Verify deployed malware and behavioral scanning, production approval, access to registry writes, timestamp authority and long-term retention separately.

- [OCI Distribution Specification v1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
- [OCI Image Manifest v1.1.1](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md)
