# SAF-K8S-0601-015 minimal inference image composition witness

`python3 tests/control-lab/lab.py test SAF-K8S-0601-015 --docker-context desktop-linux`

The baseline admits a dry-run request carrying a synthetic inference package
inventory that includes build tools. An immutable reviewed inventory and
native admission policy then refuse that same request, a different inventory
with the approved hash, and an unapproved image with the approved inventory.
The approved pinned inert Pod runs and carries the exact reviewed report.

The original declared GPU and native packages remain fixture metadata. A fourth
grouped assertion now builds two local OCI targets from the pinned BusyBox base:
one contains a distinct inert build-stage marker, and the runtime-only target
does not. The case records each image's local config and root filesystem layer
digests, then runs both under owned Kubernetes Jobs. Their runtime marker hashes
must match; the first must contain the exact build marker and the approved
runtime-only image must not. For each Pod's actual Kind node, `crictl inspecti`
must resolve the requested local image tag, return a config ID equal to Docker's
image config ID, and return root filesystem diff IDs equal to Docker's layer
diff IDs. The Pod runtime `imageID` is recorded separately as the runtime's
digest-qualified reference; it is not compared to the SHA-256 of the exact exported config bytes as though
those digest types were interchangeable.

This comparison demonstrates only the two synthetic files in these fixture
images. It does not establish the composition of a production inference image,
the absence of other compilers or package managers, GPU hardware/CUDA/driver
compatibility, signed provenance, registry promotion, or deployed release-gate
adoption. Those remain adopter evidence.

For each released inference image, bind the deployed digest to an independently verified layer or SBOM inventory and to the authenticated build and release decision. Identify the required runtime dependencies, including accelerator libraries when applicable. Verify that compilers, package managers and debugging tools are absent, and validate actual driver and hardware compatibility on the deployed target.

For adoption, capture the released image's immutable digest and independently
generated layer/SBOM inventory, bind both to the authenticated build and
approval record, and verify the inventory against the deployed digest. Confirm
which build-only tools are absent and which runtime/accelerator dependencies
are present. On the target hardware, record GPU model, driver and CUDA versions,
and a bounded application compatibility result. Preserve the gate decision and
deployment image ID as linked evidence; do not treat this synthetic BusyBox
marker comparison as production qualification.
