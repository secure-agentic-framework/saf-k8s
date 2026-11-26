# Generate a digest-bound container SBOM

Run the control by ID on Kind.

```sh
python3 lab.py test SAF-K8S-0604-001 --docker-context desktop-linux
```

The fixture assembles two Python images with the same three-module runtime
dependency chain. Both run successfully. One image omits the package metadata
for the transitive leaf, so its scanner output omits that component even
though the workload executes it. The required inventory check holds that image.
Pinned Syft generates a CycloneDX inventory before the other image is released
to the disposable TLS registry. The scan receipt binds its inventory to the
exact OCI manifest and the Kind Pod runs that same digest.

The case needs Docker, Kind, kubectl, and access to the pinned fixture images.
Its evidence covers the fixture Python packages. Native library discovery,
deployed release coverage, vendor SBOMs and non-package model or data artifacts
require their own evidence.

## Adopter verification

Record the final OCI manifest digest, each in-scope platform digest, generator and catalogers, and exact SBOM format and digest. Compare component output with an independent package or build inventory and approved coverage requirements. Include native, vendored, statically linked and accelerator libraries where they apply. Record omissions, accepted exclusions and alternative evidence for required components. Compare an allowed release with one held for missing coverage or a digest mismatch.

Publish or attach the approved SBOM to the exact release and verify independent retrieval, integrity and retention through the governed path. Evaluate vendor-supplied inventories against the same subject and coverage. Maintain separate inventories and provenance for non-package models, weights and data. The reference uses two inert Python images and demonstrates a release hold for a missing transitive inventory item.

[NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
