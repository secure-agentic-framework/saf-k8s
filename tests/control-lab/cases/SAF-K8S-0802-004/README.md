# SAF-K8S-0802-004 Firmware version and approved change reconciliation

A real read-only Kubernetes Job checks an immutable synthetic inventory against owned fixture change windows and emits a structured result. It distinguishes a permitted version change, version drift, an unchanged observation, and an unverified integrity input. An additive second Job verifies detached RSA/SHA-256 signatures over two exact inert observation records, then classifies one signature-valid observation inside and one outside a fixed synthetic window. A missing signature and a one-field marker change retaining the original signature both remain unverified despite the familiar `fixture-fw-v2` version. Only OpenSSL's explicit verification-failure response counts as a bad signature; missing tools, malformed inputs, file failures, and unexpected verifier results fail the Job. The private fixture signing key exists only in a local temporary directory and is not retained; the separate Job receives only the public key and detached signatures. The total is four checks, retaining the original three. The fixture does not inspect firmware, monitor DCGM telemetry, or verify hardware trust, a production signer, or a deployed trust root.

The [A100 inventory](../SAF-K8S-0802-008/a100-reference/firmware-inventory.json)
records the observed VBIOS and InfoROM versions and a valid InfoROM checksum
on one passthrough device.

The [A100 firmware evidence review](a100-firmware-scope.md) identifies the
device, observed health evidence, and prerequisites for firmware attestation.
