# SAF-K8S-0905-028 — Scan Python dependencies and gate promotion

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-028 --docker-context desktop-linux` from the framework checkout.

The first three checks use a restricted Job with two fictitious metadata-only Python wheels. An offline installation resolves the declared transitive dependency. The fixture permits promotion before enforcement, withholds it for an affected installed version, and allows it after a corrective version is installed. Three more checks parse a range-only subset of the official CVE Program record for CVE-2023-45803, compare five synthetic inventory rows to that metadata, and retain affected-version matches for review. The official record locator, raw SHA-256 and Git blob identity are in `fixtures/source-provenance.json`. The real affected package is neither installed nor executed. The fixed numeric comparator covers the recorded source syntax.

## Verify an adopted dependency workflow

1. Enumerate approved training and inference artifacts by digest, including the base image, installed direct and transitive Python packages, embedded framework distributions, and any runtime-loaded dependencies. Compare the actual inventory with the scanner input and document omissions.
2. Verify the deployed scanner uses approved, current advisory sources, matches distribution and installed version according to the relevant ecosystem, and retains source, ingest and scan timestamps. Test a controlled recorded match and a corrected version without installing affected packages in the test environment.
3. Review a finding against actual exposure, asset scope, likelihood, owner and response deadlines. Record either a verified corrective change or approved compensating action with expiry and evidence, then trace release enforcement and rescan to closure. Verify coverage and exceptions for each governed framework and deployment path.

- [Python Core metadata](https://packaging.python.org/en/latest/specifications/core-metadata/)
- [CVE Program official records](https://github.com/CVEProject/cvelistV5)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)

## Advisory source validation

The seventh check changes the repository field in an in-memory copy of the
provenance metadata. The same evaluator that accepts the pinned fixture
refuses the altered source before reading ranges or producing findings.
The fixture keeps the original record locator, raw hash and Git blob
identifier. The paired comparison checks the normalized snapshot hash and
expected identifiers locally. The adopter procedure covers the authoritative
feed, freshness and current deployed inventory.
