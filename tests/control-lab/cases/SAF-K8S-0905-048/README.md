# SAF-K8S-0905-048

Run `python3 lab.py test SAF-K8S-0905-048`. Kubernetes admission compares
the fixture image and annotation to an immutable review record. The case
rejects a mutable tag and a replacement digest. It then reads the manifest
and payload from the admitted original digest after the tag points elsewhere.
The Pod requests use server dry-run, and the OCI client reads the actual case
registry. Production deployment and promotion coverage need separate evidence.
