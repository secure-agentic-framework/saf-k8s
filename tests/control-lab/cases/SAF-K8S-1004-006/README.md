# SAF-K8S-1004-006 adopter verification

## Control and mapping scope

The portable case validates one mechanism: correlating technical records with synthetic nontechnical context under exact cluster, namespace, workload and five-minute event-time matching, then adjusting advisory review order when one valid business context record qualifies. It rejects wrong-scope, outside-window, expired, and ambiguous context. Output remains advisory; the code explicitly reports no attribution and no employment decision.

This is a partial contribution to NIST SP 800-53 Rev. 5 AU-6(9), not proof of the full outcome. The normative control requires correlating information from nontechnical sources with audit record information to enhance organization-wide situational awareness. NIST notes that nontechnical sources may be sensitive, access should be limited to need-to-know personnel, and legal advice should be obtained before correlating records about suspected individuals. The fixture does not ingest actual audit or organizational records and proves neither those governance controls nor organization-wide awareness.

## Existing paired portable evidence

Published lab receipt: `saf-k8s-control-lab/evidence/SAF-K8S-1004-006/20261122T171051Z-adbf22c5/result.json`.
Published framework receipt: `saf-k8s-framework/tests/control-lab/evidence/SAF-K8S-1004-006/20261122T171051Z-a04c2944/result.json`.

Both recorded 3 passing assertions under catalog revision `133a8698a45e2b335b51728bf4c62f7bda98d15f`, control-row digest `9231ef42b8978d9f2c43f75df5a37f2af85d8cc86d788ee8f8f119c51dc3e8f2`, and Kubernetes v1.36.1. The lab and framework cluster IDs differ; both receipts record cleanup `deleted`. The checks are: baseline severity ordering; exact workload/time context changes analyst review ordering while critical stays first; and mismatched, late, expired or ambiguous context does not improperly raise urgency. Recheck these exact revisions before carrying the result into a newer catalog or case.

## Test dependencies and reproduction

The runner creates one ConfigMap and two tokenless, restricted Kubernetes Jobs in a disposable Kind v1.36.1 cluster. Jobs execute checked-in Python standard-library scripts from the read-only ConfigMap fixture volume using the pinned image `python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90`. There is no live SIEM/SOAR, external API, or third-party data source. Preserve only the runner's normal result receipt and synthetic triage evidence.

In an authorized disposable local lab, from `saf-k8s-control-lab`:

```sh
python3 lab.py test SAF-K8S-1004-006 --docker-context desktop-linux
```

For the framework copy, from `saf-k8s-framework`:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1004-006 --docker-context desktop-linux
```

Do not point this synthetic exercise at production or third-party endpoints. Verify the three named checks all match, Kubernetes version, catalog revision, control digest, distinct disposable cluster IDs, and cleanup status. A pass only verifies the fixture logic and runner isolation.

## Deployer evidence still required

1. **Name the source and purpose.** Inventory the actual audit-record repository and each nontechnical source type, its owner, purpose, legal basis/approval, sensitivity, retention and allowed users. Use real source identifiers only in the organization's protected evidence store.
2. **Authorize and minimize access.** Obtain privacy/legal review before any person-linked correlation, consistent with the NIST discussion. Define a need-to-know role and least-privilege source access; prove denied users cannot retrieve sensitive context. Document minimization, retention, deletion, and access logging.
3. **Validate deployed joins.** For approved sources, document the record keys, authoritative timestamps, time zones, scope boundaries and allowable windows. Use a controlled test record to verify correct correlation and that wrong identity/scope, stale, expired, ambiguous and late records cannot raise review urgency.
4. **Show actual audit analysis.** Produce a redacted sample of correlated audit-record IDs and nontechnical-source IDs, showing provenance and the human review decision. Confirm the output enters the intended organization-wide situational-awareness workflow, reaches the appropriate audiences, and is not treated as an attribution or personnel decision by this case.
5. **Review operation and revisions.** Record analyst acceptance/override and follow-up, source or rule version, access/retention review, and periodic owner review. When source schemas or correlation policy change, rerun the portable lab/framework candidates and revalidate current control-row fingerprints; old receipts cover only their recorded revisions.

## Authoritative source

NIST SP 800-53 Rev. 5, AU-6(9), states: “Correlate information from nontechnical sources with audit record information to enhance organization-wide situational awareness.” Its discussion identifies the sensitive nature of some nontechnical records, need-to-know access limits, and legal advice before correlation involving suspected individuals. Source: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf (AU-6(9), p. 72); publication/release page: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final.
