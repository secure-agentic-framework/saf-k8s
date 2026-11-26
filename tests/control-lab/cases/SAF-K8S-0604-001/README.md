# Verify coverage in the generated SBOM for an exact OCI image

    python3 tests/control-lab/lab.py test SAF-K8S-0604-001 --docker-context desktop-linux

Pinned Syft inventories two assembled fixture images and writes CycloneDX.
Both images execute the same ordinary Python dependency chain. The inventory
for one is missing the metadata of a required transitive package, so the
release check withholds its approved tag. The complete image is released
at the exact scanned manifest digest and then runs on Kind.

Before release the case checks that the native Debian libc6 record agrees
across the scanner records and CycloneDX. The approved workload independently
reads its package version and calls the active glibc library. The comparison
links that observation to the image digest and the generated SBOM.

For a deployment, verify every released manifest and platform against
independent package and build evidence, including required native, vendored,
GPU and wheel-bundled components. Document scanner version, cataloger scope,
exceptions, retention, and separate inventories for non-package model
artifacts, weights and data.
