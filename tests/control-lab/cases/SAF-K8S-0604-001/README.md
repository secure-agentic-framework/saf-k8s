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


## Additive pinned wheel/native ELF witness (scratch candidate)

A seventh assertion adds an inert `psutil==7.2.2` manylinux wheel for the active Docker architecture. The wheel is downloaded from its exact PyPI-hosted URL with a Dockerfile `ADD --checksum=sha256:...` gate; pip installs it with `--no-index --no-deps`. The PyPI release file table lists the artifact SHA-256 and reports no Trusted Publishing provenance for these selected files, so the checksum pins the bytes but does not establish publisher provenance. See [psutil 7.2.2 PyPI files](https://pypi.org/project/psutil/7.2.2/), including the [arm64 artifact detail](https://files.pythonhosted.org/packages/63/65/37648c0c158dc222aba51c089eb3bdfa238e621674dc42d48706e639204f/psutil-7.2.2-cp36-abi3-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64.whl) and [amd64 artifact detail](https://files.pythonhosted.org/packages/b5/70/5d8df3b09e25bce090399cf48e452d25c935ab72dad19406c77f4e828045/psutil-7.2.2-cp36-abi3-manylinux2010_x86_64.manylinux_2_12_x86_64.manylinux_2_28_x86_64.whl).

The fixture imports psutil's private Linux extension, performs bounded process metadata calls, validates the installed extension bytes against its wheel `RECORD` SHA-256, and checks ELF architecture. Pinned Syft scans the exact OCI manifest and must report both the Python package in CycloneDX and the extension's ELF format plus SHA-256 in native Syft JSON. The wheel image is copied into the existing disposable local registry with digest preservation; an owned Kind Pod pulls that exact digest and repeats the same safe probe. Evidence joins the PyPI wheel checksum, wheel `RECORD` extension checksum, Syft file digest and runtime-loaded extension digest. This adds file-level binary evidence alongside the existing Python package and libc package inventory. It does not claim that CycloneDX itself contains per-file ELF records.

This fixture is limited to one native architecture per run and a public test wheel. It does not establish organizational artifact allowlisting, wheel provenance, production image adoption, GPU components, or all platform-specific artifacts. It retains every prior test and uses the existing disposable registry/cluster cleanup.


The supplemental receipt distinguishes the Docker engine's image reference ID from the selected platform image config digest. On a containerd-backed Docker store, the engine ID can identify the OCI index while the config has a separate digest. The fixture links the exact tag annotation and platform descriptor to the saved config/layers, then verifies the Skopeo OCI layout uses the same config digest and rootfs diff IDs before Syft scans it.


### Native Docker OCI layout reconstruction (scratch v3)

This revision no longer asks Skopeo to convert `docker-archive` into the scan layout. It resolves the exact Docker image ID through the saved native OCI index and local platform descriptor, then copies only the selected manifest, its config, and its compressed layer blobs by validated SHA-256 descriptor into a new OCI layout. The layout index points to the exact saved platform manifest and adds `org.opencontainers.image.ref.name=wheel`; all manifest/config/layer payload bytes and sizes remain verified against the archive, config diffIDs, and selected descriptor chain. Syft scans this reconstructed layout. The existing Skopeo registry publication still uses `--preserve-digests`, and the expected pushed digest remains the exact native selected-manifest digest. No Docker/Kind run was performed for this revision.


### Syft full-file SHA-256 settings and wheel RECORD association (scratch v4)

The v3 replay confirmed that pinned Syft 1.57.1 reported the installed psutil package and the extension's file path plus `executable.format` value `elf`, but with `owned-by-package` it omitted file digests and did not identify that binary as package-owned. This revision sets the documented `SYFT_FILE_METADATA_SELECTION=all` and `SYFT_FILE_METADATA_DIGESTS=sha256` environment values for both Syft JSON and CycloneDX scans. The file-format assertion is case-insensitive. It checks Syft's native file digest against both the runtime-loaded ELF's SHA-256 and the independent SHA-256 entry in the wheel's `RECORD`. It does not claim that Syft's own ownership graph ties the `.so` to psutil: the receipt records that Syft presents it as a file-level ELF, while wheel RECORD plus module path and runtime observation provide the association.

Syft's official configuration reference documents `file.metadata.selection` values `all`, `owned-by-package`, and `none`, and maps `SYFT_FILE_METADATA_SELECTION` and `SYFT_FILE_METADATA_DIGESTS` to those configuration fields: https://oss.anchore.com/docs/reference/syft/configuration/ . The official Syft JSON reference documents `files[].executable.format` and `files[].digests`: https://oss.anchore.com/docs/reference/syft/json/16/ . These names are supported by the pinned Syft 1.57.1 release's configuration schema; verify the generated receipt at replay.

## Exact SBOM attachment and readback

The additional check uses the exact wheel CycloneDX bytes already emitted by the pinned Syft scan. It stores them as an OCI artifact layer, creates an OCI artifact manifest with the exact scanned platform manifest as `subject`, and updates the Distribution referrers-tag fallback index. The fixture first checks the pinned registry returns 404 for native referrers. It reads the subject manifest, artifact manifest and SBOM blob back by digest and independently resolves the descriptor through the fallback index. The check requires byte-identical subject and SBOM readback, matching SHA-256 descriptors, the exact subject descriptor, and the exact artifact descriptor in the referrers index.

The result covers attachment and readback for one image in the disposable registry. Production retention, backup, replication and registry access policy require deployment evidence.
