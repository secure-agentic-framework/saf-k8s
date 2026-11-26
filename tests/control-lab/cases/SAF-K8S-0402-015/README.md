# SAF-K8S-0402-015 — Legacy service account token Secret retirement

```sh
python3 lab.py test SAF-K8S-0402-015 --docker-context desktop-linux
```

In a fresh kind Kubernetes v1.36.1 cluster, server dry-run admits an empty
legacy-type Secret request before policy, then rejects the same request by
type after applying a namespace-scoped admission policy. The policy still
admits an Opaque fixture in a dry run. Neither request persists an object.
A type-based inventory succeeds without returning any test Secrets. The
fixture also verifies the built-in ConfigMap that records when tracking began.

Legacy token metrics report usage. Inventory by Secret type and associated
account references is a separate operation. The cleaner applies to qualifying
inactive auto-generated tokens. Explicit retirement and migration need their
own evidence for remaining Secrets, including manually provisioned ones.
The test uses inert request bodies and never creates or uses credentials.

The framework retains `verified/SAF-K8S-0402-015.json`. The primary Bead
links the original finding, revised record and open production obligations.

- [Kubernetes v1.36 service account token tracking, cleanup and migration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Kubernetes v1.36 metrics reference](https://v1-36.docs.kubernetes.io/docs/reference/instrumentation/metrics/)

## Verify an adopting deployment

1. **Inventory without collecting token data.** In every in-scope cluster and namespace, obtain a metadata-only projection of Secret namespace/name, type, creation time, owner/reference annotations and labels. Exclude `.data` and `.stringData` from commands, exports, evidence and logs. Join each `kubernetes.io/service-account-token` Secret to the ServiceAccount by name and UID; also record whether it is referenced from that ServiceAccount's `.secrets` list. Do not save full Secret YAML or JSON.
2. **Identify consumers and token class.** Review Pod, Job, controller and external-application references using object names and configuration metadata only. Distinguish eligible auto-generated legacy tokens from manually provisioned ones; do not infer that a Secret is unused from absence of a Pod volume reference alone. Assign an owner and migration decision to each item, including approved dependencies outside the cluster.
3. **Review activity evidence.** Confirm the v1.36 tracking ConfigMap and TokenCleaner configuration for the actual cluster version. Review available API-server legacy-token usage metrics and audit events with their time window, scrape/retention coverage and source. Usage metrics are supplemental activity evidence: an absent increment does not by itself prove a credential is unused or identify every out-of-cluster consumer.
4. **Migrate active consumers.** Where supported, move to TokenRequest or projected, bounded-lifetime ServiceAccount tokens. Verify each intended consumer still completes a harmless authorized operation through its ordinary path; retain success/identity metadata only and never retain bearer contents. Document any manual long-lived token exception, approver, owner, need, expiration/review date and compensating controls.
5. **Retire intentionally.** After consumer and owner review, remove stale/manual legacy token Secrets and verify their metadata-only absence. For auto-generated tokens, verify cleaner eligibility and the observed invalidation/removal workflow; Kubernetes' cleaner targets qualifying auto-generated inactive tokens, while manually created tokens require explicit retirement. Confirm dependent applications remain healthy and intended permissions remain unchanged.
6. **Prevent recurrence.** Verify the deployed admission policy rejects a new legacy token Secret by type and still permits an ordinary Opaque Secret. Check policy scope, exemptions, rollout state, audit/alert ownership and the rollback/exception process. The fixture's dry-run comparison is a pattern; retain the deployed API-server response and policy revision without credential material.

### Versioned references

- [NIST SP 800-53 Rev. 5.1 derived OSCAL](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf), AC-2(3).
- [Kubernetes v1.36 ServiceAccount administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/): tracking ConfigMap, eligible auto-generated legacy-token invalidation/cleanup, ServiceAccount references, and TokenRequest behavior.
- [Kubernetes v1.36 ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/) and [Pod token configuration](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/): long-lived Secret-backed credentials versus TokenRequest/projected credentials.
- [Kubernetes v1.36 metrics](https://v1-36.docs.kubernetes.io/docs/reference/instrumentation/metrics/): versioned legacy-token usage metric names.
