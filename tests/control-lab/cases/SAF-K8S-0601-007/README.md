# SAF-K8S-0601-007 approved AI base-image admission

`python3 tests/control-lab/lab.py test SAF-K8S-0601-007 --docker-context desktop-linux`

One owned Kind API accepts the harmless unchecked request in server dry-run.
A local test-only authenticated approval record binds a synthetic accelerator
profile and curation evidence to the exact fixture image. A native admission
policy denies the unchecked request, different digest, incorrect profile and
missing or changed evidence. These negative requests never run. A Pod using
the exact approved pinned BusyBox image is admitted and reaches Ready.

The synthetic GPU and framework profile exercises evidence handling. Actual
CUDA, driver and AI framework compatibility and production trust and release
coverage require separate evidence.

## Adopter verification

1. Confirm the approved production base-image inventory and immutable digests for training, serving and inference.
2. Match each image's CUDA/cuDNN and ML framework versions to the actual node GPU, driver and device-plugin profile. retain a compatibility result for each supported hardware profile.
3. Verify the production curation record, image source and trusted attestation through the release/admission path.
4. Review nonstandard images for approved, scoped exceptions, expiry and compensating controls. confirm unused build components were removed.
