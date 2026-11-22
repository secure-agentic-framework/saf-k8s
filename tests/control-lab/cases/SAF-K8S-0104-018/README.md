# SAF-K8S-0104-018 Kubernetes security advisory and provider bulletin monitoring

```sh
python3 lab.py test SAF-K8S-0104-018 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0104-018.md)
requires active monitoring of Kubernetes, CVE and relevant provider and
dependency advisory sources. The upstream Kubernetes feed may lag a disclosure
and covers official Kubernetes advisories. Provider programs have their own
coverage and delivery details. Configure sources to match the deployed
inventory.

This case serves an inert Kubernetes JSON Feed 1.1 record and an RSS 2.0
provider record inside kind. The Kubernetes record uses the native CVE ID field
with a synthetic identifier. The CronJob controller schedules polling every
minute. While the upstream endpoint returns HTTP 503, a scheduled Job records
that source failure and still parses the available RSS feed. A later Job from
the same CronJob parses both sources after the fixture recovers. Job ownership
and scheduled timestamps must match the CronJob.

This example verifies the scheduled monitoring path against inert sources.
Production evidence is required for subscription freshness, coverage across
the cluster and dependency inventory, notification delivery and response.

- [Kubernetes official CVE feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/)
- [Kubernetes JSON feed field definitions as published](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json)
- [AWS Security Bulletins](https://aws.amazon.com/security/security-bulletins/)
- [GKE cluster notifications](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/cluster-notifications)
