# SAF-K8S-0104-019 Kubernetes CVE risk prioritization

```sh
python3 lab.py test SAF-K8S-0104-019 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0104-019.md)
requires severity, exploitability, exposure, and cluster-specific impact to
inform a documented vulnerability-triage workflow. The fixture uses only
invented advisory identifiers, inert records and synthetic inventory.

This case runs two Kubernetes Jobs over identical records. Ordering by CVSS
base score alone places a higher-severity unexposed record first. The example
contextual policy ranks an exposed KEV-listed fixture first and keeps the
applicable version interval in the finding. Both Jobs exclude the component
whose version is at the interval's exclusive upper bound.

The sample accepts only simple, nonnegated CPE OR nodes with an inclusive
start and exclusive end. A production implementation needs the deployed
inventory and provider patch context, the actual data sources and applicability
rules, and evidence of triage, accountabilities, and timing. The fixture scores
and rankings define the example policy.

- [Kubernetes official CVE feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/)
- [NVD API vulnerability and applicability fields](https://nvd.nist.gov/developers/vulnerabilities)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document)

## Version-scoped evidence and follow-up

Catalog revision `7e2e05c327f54bcc2c6aefd64c255880a81ce7c9` adds a second pair of Jobs.
It compares generic advisory summaries with a policy that checks exact build
identifiers. An exact provider record clears a synthetic backported build,
while two contradictory records and an unknown build stay open with an owner
and review deadline. An affected fixture preserves its inference impact and
response deadline. The policy's deadline and source records are invented.
