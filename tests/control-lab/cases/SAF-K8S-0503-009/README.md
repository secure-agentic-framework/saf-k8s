# SAF-K8S-0503-009 — CoreDNS and upstream resolver hardening

```sh
python3 lab.py test SAF-K8S-0503-009 --docker-context desktop-linux
```

The Kubernetes v1.36.1 Kind cluster starts with kubeadm's CoreDNS add-on
disabled. The test confirms API readiness and absence of the stock CoreDNS
Deployment and DNS Service. It then installs a dedicated CoreDNS v1.14.2
instance with a digest-pinned image.

Before configuration, the same reserved test query reaches only the
unapproved local resolver. A genuine ServiceAccount cannot update the
Corefile until it receives an RBAC grant scoped to that named ConfigMap.
The granted identity applies the change and is still denied on an
unrelated ConfigMap. The runner rolls out the new configuration, waits for
the Service's routing to converge, and checks that the exact query now
reaches only the approved resolver.

The case also verifies the native Kubernetes Service lookup, one cache
hit through unchanged upstream query counts, and separate health and
readiness endpoints. The loop plugin is configured and startup remains
healthy. Both upstreams are disposable fixtures. Deployment evidence
covers NodeLocal DNSCache, resolver approval and redundancy, other cache
settings, and actual configuration-change governance.

- [Kubernetes v1.36 kubeadm DNS add-on configuration](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubeadm-config.v1beta4/)
- [Kubernetes v1.36 DNS customization](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/dns-custom-nameservers/)
- [CoreDNS v1.14.2 plugins](https://github.com/coredns/coredns/tree/v1.14.2/plugin)

## Authenticate an upstream

The runner host needs OpenSSL. The real CoreDNS forwarder sends the same reserved query through two listeners on the same Ready CoreDNS Pod. Both listeners use the same TLS endpoint and trusted synthetic certificate with independent expected server names. The matching name delivers the query and returns the fixture marker. The mismatched name must cause an observed TLS certificate alert with the presented server name, leave the query absent at the resolver, and return SERVFAIL.

## Verify an adopting deployment

This guide supplements the local reference case. The original fourteen checks run on Kubernetes v1.36.1 with a separate CoreDNS v1.14.2 instance and two case-owned UDP resolver stubs. It demonstrates scoped Corefile authorization, resolver-target selection for one reserved query, one cache hit, Kubernetes Service lookup, and CoreDNS health/readiness responses. The TLS supplement also verifies one endpoint's server identity. Deployed DNS topology, DNSSEC record-origin validation, cache policy, monitoring, failover, and change governance need their own evidence.

## Evidence to collect for each deployed cluster

1. **Map the query path.** Record the cluster DNS Service, CoreDNS replicas and version, any NodeLocal DNSCache instances, node and Pod resolver configuration, forwarding zones, and each upstream. Confirm the effective configuration and the path for an owner-approved harmless internal name and a controlled external name. Record expected answer and resolver path; do not use a public test name as proof of internal policy.

2. **Verify upstream trust.** For every configured upstream, record the approved identity and how responses are authenticated: DNSSEC validation with the intended trust anchors, or an explicitly trusted authenticated transport/validation service. Confirm the deployed resolver actually validates or authenticates responses. A forward target IP, a successful lookup, or a CoreDNS cache hit alone does not prove data-origin authenticity or integrity.

3. **Review cache policy with controlled records.** Capture effective positive and denial TTL bounds, minimum TTLs, SERVFAIL caching, stale-answer behavior, and zone exclusions. Using owner-controlled records with known TTL and answer changes, check first lookup, repeat lookup, expiry/change visibility, negative response, and any enabled stale path. Record the expected result and upstream-query or cache-hit counters. The reference fixture checks only that one repeated query avoids another upstream request.

4. **Separate process health from upstream health.** Record `/health` and `/ready` results separately, plus readiness of the Kubernetes DNS Service endpoints. CoreDNS `/health` is process health; `/ready` reports readiness of participating plugins. Neither proves that a particular upstream can answer or that its data is trusted. For each upstream, retain scrape timestamps and per-upstream request latency/response-code and health-check-failure series. For CoreDNS versions exposing them, the `forward` plugin documents `coredns_proxy_request_duration_seconds{proxy_name="forward",to,rcode}`, `coredns_proxy_healthcheck_failures_total{proxy_name="forward",to,rcode}`, and `coredns_forward_healthcheck_broken_total`; verify the deployed version and enabled Prometheus plugin before relying on these names. Show alert delivery, retention, and the responder/runbook for loss of all upstreams.

5. **Prove failover only when claimed.** In a maintenance window or an isolated owner-controlled environment, use a synthetic zone and an approved test upstream to make one configured resolver unavailable. Capture the selected alternate, query result/rcode and latency, upstream health signals, and recovery after restoring the primary. Document the configured all-upstreams-unhealthy behavior: CoreDNS `forward` can continue sending to a random upstream when all are marked unhealthy, so an unhealthy signal alone is not proof of successful failover. Do not disrupt shared or third-party resolvers.

6. **Retain change and redundancy evidence.** Identify who can change CoreDNS/NodeLocal configuration, the reviewed change record, reconciliation or rollout result, and rollback path. Record replica/node placement and any zone or site failure assumptions behind a redundancy claim. The fixture's scoped ConfigMap RBAC check is a reference pattern; it does not verify the deployed authorization or change process.

## Acceptance record

For each check, retain cluster and resolver scope, collection time, deployed versions, sanitized effective configuration, query names limited to approved synthetic or internal test records, expected and observed resolver/answer, relevant counters and alert receipt, and the operator who reviewed the result. Redact credentials and unrelated internal names. Mark checks that do not apply and state why. Keep deployed observations separate from the disposable fixture receipt.

## Source behavior

- [CoreDNS v1.14.2 `forward` plugin](https://github.com/coredns/coredns/tree/v1.14.2/plugin/forward) documents supported transports, in-band health checks, all-upstreams-unhealthy behavior, and per-upstream metrics.
- [CoreDNS `cache` plugin](https://coredns.io/plugins/cache/) documents success/denial TTL controls, SERVFAIL caching, stale serving, and cache metrics. DNSSEC DO passthrough does not by itself mean the caching resolver validated signatures.
- [CoreDNS `health` plugin](https://coredns.io/plugins/health/) reports process health. [CoreDNS `ready` plugin](https://coredns.io/plugins/ready/) reports readiness from plugins that signal it.
- [CoreDNS Prometheus plugin](https://coredns.io/plugins/metrics/) exports metrics provided by enabled plugins; a metric existing locally does not prove it is scraped, retained, alerted, or acted on.
