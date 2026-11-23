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
