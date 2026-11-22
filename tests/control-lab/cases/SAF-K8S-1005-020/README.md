# SAF-K8S-1005-020 — Vulnerability response ownership and coordination governance

This case exercises a fictional, offline coordination workflow in a disposable
Kind Kubernetes v1.36.1 cluster. It uses a single short-lived Job to read only
`fixtures/coordination-records.tsv`. No real advisories, feeds, provider systems,
upstream maintainers, or external contacts are accessed. The Job has no Kubernetes
API token, no API client, no credentials, and no network client. A default-deny
NetworkPolicy is installed for the Job Pod as defense in depth.

Run under the lab's normal supervisor workflow:

```sh
python3 lab.py test SAF-K8S-1005-020 --docker-context desktop-linux
```

## Observations

The validator evaluates the same requests in bypass and enforced modes and writes
both decisions to the Job log. The case separately reads Job status, Pod status, token settings,
and logs through kubectl. The runner retains the raw command transcript and
structured checks in `evidence/SAF-K8S-1005-020/<run-id>/commands.log` and
`result.json`; all input values are fictional and contain no secrets.

- **Red** observes that incomplete records with closure requests are accepted
  in bypass mode.
- **Green** observes the same requests withheld for missing ownership, missing
  escalation routing, or an unacknowledged handoff.
- **Positive** observes that acknowledged but unapproved work stays open and
  complete approved work closes. The tokenless Job completes successfully.

The lab retains `coordination-observations.raw.json` with the Job outcome.
NIST SP 800-216 describes responsibility, tracking, and coordinating remediation
with involved parties for the U.S. federal scope. This case exercises a fictional
workflow with locally chosen closure criteria.
[NIST SP 800-216](https://csrc.nist.gov/pubs/sp/800/216/final)

The node runtime may pull the digest-pinned BusyBox image. The Job itself
performs no network operations.

Kubernetes documents Jobs as one-off tasks that run to completion in its
[Job documentation](https://kubernetes.io/docs/concepts/workloads/controllers/job/).
Kubernetes documents default-deny NetworkPolicy behavior and its dependency on
network-plugin support in the [NetworkPolicy guide](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

## Coverage and limits

This is a local mechanics demonstration of record classification and one-shot
Job execution only. The NetworkPolicy object is observed as configured, but this
case does not probe or claim that the Kind network plugin enforces egress policy.
The script itself performs no network operations. The fixture cannot prove real
named ownership, escalation availability, acknowledgment authenticity, elapsed
response times, remediation completion, approved closure authority, upstream
coordination, cloud-provider procedures, external contact behavior, or production
coverage. Those remain unresolved source/control claims requiring organizational
records and independent operational evidence.
