# SAF-K8S-0802-004 Firmware version and approved change reconciliation

A real read-only Kubernetes Job checks an immutable synthetic inventory against owned fixture change windows and emits a structured result. It distinguishes a permitted version change, version drift, an unchanged observation, and an unverified integrity input. An additive second Job verifies detached RSA/SHA-256 signatures over two exact inert observation records, then classifies one signature-valid observation inside and one outside a fixed synthetic window. A missing signature and a one-field marker change retaining the original signature both remain unverified despite the familiar `fixture-fw-v2` version. Only OpenSSL's explicit verification-failure response counts as a bad signature; missing tools, malformed inputs, file failures, and unexpected verifier results fail the Job. The private fixture signing key exists only in a local temporary directory and is not retained; the separate Job receives only the public key and detached signatures. These fixtures account for four checks. These checks use generated observations and a temporary signer.

## Archived NVIDIA Hopper evidence

The additional Kind Job verifies a published Hopper SPDM 1.1 transcript under
NVIDIA's device certificate root at a fixed reference time. The test verifies
the signature before accepting the report, checks the archived challenge and
measurement identity, and verifies the ECDSA signatures and signer chains for
NVIDIA's matching driver and VBIOS Reference Integrity Manifests.

All 22 active driver entries and 12 active VBIOS entries must match the
authenticated report at their documented measurement indices. Changed
transcript data, an embedded root without independent trust, a certificate
chain evaluated before its validity period, a changed RIM field, and a wrong
measurement in the reference comparison are rejected. The Job emits only
normalized results in `hopper-archived-firmware.json`.

Run from the framework checkout with Docker, Kind, kubectl, Python, Go,
and curl.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0802-004 --docker-context desktop-linux
```

The host fetches hash-pinned primary artifacts and wheel files during setup.
The verification Job needs no GPU or vendor service connection. Its scope
is the fixed archived input. Live device identity, fresh challenges,
certificate revocation, and deployment monitoring remain separate evidence
requirements.

- [NVIDIA SDK release containing the sample](https://github.com/NVIDIA/attestation-sdk/releases/tag/2026.11.23)
- [NVIDIA local verifier workflow and RIM format](https://docs.nvidia.com/attestation/attestation-client-tools-sdk/latest/local-verifier/introduction.html)

## Archive monitoring and alert delivery

The case passes the normalized, verified Job receipt to a case-owned exporter.
The pinned archived transcript and measurement digest stay identical through
all comparisons. A separate fixture approval selects the expected measurement,
and the runner changes only that approval to exercise the mismatch. Prometheus
observes a healthy, authenticated scrape and Alertmanager delivers a firing
notification to the archive review receiver. The live operations receiver
receives only its synthetic route comparator, which confirms that receiver
is reachable independently. The archived receipt is always ineligible for
the live firmware rule.

Restoring the approved digest resolves the mismatch notification. An invalid
approval record then makes the exporter return an unavailable scrape and
triggers a distinct archive availability notification. Restoring the valid
record resolves it and restores collection. The runner retains both route
lifecycles in `hopper-archive-alerts.json` with the exact archived transcript
and measurement digests. The approval records and both receivers are local
fixtures. Fresh physical evidence, live responder routing and production
review decisions remain separate requirements.
