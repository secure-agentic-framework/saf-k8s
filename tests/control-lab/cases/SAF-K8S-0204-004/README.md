# SAF-K8S-0204-004 — Scoped evidence collection and signed handoff

```sh
python3 lab.py test SAF-K8S-0204-004 --docker-context desktop-linux
```

The disposable collector is denied without its Role and denied on a second
Pod after the Role is granted. From the permitted Pod it collects a public
marker file and a limited PID, process name and UID summary. The test
records a collection time window and verifies the same container and
restart count before and after. A separate fixture custodian reads the
bundle from an immutable ConfigMap and verifies its signed manifest and
specimen digests. A modified manifest fails signature verification, and
both the custodian's permissions and API immutability protect the stored
data in the tested paths.

The Role scopes the Pod and subresource. The fixture selects the commands
and paths. Impersonated test identities, the ephemeral manifest key, cluster
clock and ConfigMap are local test dependencies. Collection via exec creates
process activity, and the continuity check measures identity and restarts.

## Verify deployment applicability and evidence

1. Build an evidence-class and platform inventory. Identify supported
   filesystem/snapshot, process-state and network-flow paths, required
   approvals, identities, data sensitivity, default scope and alternatives
   when evidence is inaccessible. Check the real provider and runtime support.
2. Rehearse with owned test data. Record the collector's authenticated
   identity, authorization and timestamps from an approved clock. Record
   tool versions, source identity, collection scope and expected collection
   impact. Compare measured impact and check completeness by artifact class.
3. Verify signed manifests, independent receiver verification, role separation,
   storage access and audit records, approved retention and cleanup. Check
   rejected reads and changes and trace a real custody transfer. The fixture
   demonstrates one handoff path and no restart over its capture window.
4. Verify flow capture and retention independently end to end. Trace owned
   markers across the exporter, receiver, access paths, rotation and
   deletion policy. Measure loss and elapsed availability where applicable.
   SAF-K8S requires at least 72 hours of scoped production flow retention
   or an approved provider-specific alternative with recorded limits and
   ownership. Retain the annual exercise schedule and results.

[Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) ·
[Kubernetes v1.36 ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/) ·
[NIST SP 800-86 forensic techniques](https://csrc.nist.gov/pubs/sp/800/86/final)
