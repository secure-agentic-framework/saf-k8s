# SAF-K8S-0606-025 source review

The control at catalog revision 133a8698a45e2b335b51728bf4c62f7bda98d15f
requires enforcing organizational artifact freshness before promotion or
deployment. Git commit identity and build completion age are separate
properties. The fixture verifies commit timestamps from actual Git objects
and binds the build timestamp and exact artifact digest to the authenticated
fixture receipt. The chosen threshold and chronology policy are specific to
the test. SLSA v1.2 defines source dependency digests and build metadata
fields that deployments can use to support a freshness policy.
[SLSA build provenance](https://slsa.dev/spec/v1.2/build-provenance)

A second Job evaluates the policy and creates inert markers for the fresh and
boundary artifacts. Rebuilding from stale source, stale build output, future
values and mismatched bytes are rejected. The retained result compares exact
timestamps, reasons and API marker state.

Production source authorization, timestamp integrity, signer and builder
trust, approved thresholds and deployment coverage remain separate.
