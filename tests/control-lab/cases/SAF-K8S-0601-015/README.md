# SAF-K8S-0601-015 minimal inference image composition witness

`python3 tests/control-lab/lab.py test SAF-K8S-0601-015 --docker-context desktop-linux`

The baseline admits a dry-run request carrying a synthetic inference package
inventory that includes build tools. An immutable reviewed inventory and
native admission policy then refuse that same request, a different inventory
with the approved hash, and an unapproved image with the approved inventory.
The approved pinned inert Pod runs and carries the exact reviewed report.

The declared GPU and native packages are fixture metadata. Actual image
composition, hardware qualification and provenance verification remain
deployment evidence.

For each released inference image, bind the deployed digest to an independently verified layer or SBOM inventory and to the authenticated build and release decision. Identify the required runtime dependencies, including accelerator libraries when applicable. Verify that compilers, package managers and debugging tools are absent, and validate actual driver and hardware compatibility on the deployed target.
