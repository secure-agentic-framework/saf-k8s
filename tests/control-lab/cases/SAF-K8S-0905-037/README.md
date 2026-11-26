# SAF-K8S-0905-037 — Invoke a governed manual halt and preserve evidence

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-037 --docker-context desktop-linux` from the framework checkout.

Five checks use two owned Deployments and restricted fixture identities. Native authorization denies the ordinary identity and limits the responder to the named target. After recording the target's synthetic workload evidence, the authorized responder invokes the halt and observes target Pod removal within the declared 45-second fixture budget. A separate investigator verifies the pre-halt evidence digest and the unrelated workload stays active. A native server-side dry-run change to the immutable evidence object is refused. An independent read confirms identical stored bytes and digest after the attempted change.

## Verify an adopted incident halt

1. Identify authoritative responders, alternate approvers and investigators. Verify permissions for each actual target and lifecycle operation, including training, inference and pipeline controllers.
2. Define approved response-time start and completion events, actual service targets, identity and runbook versions. Exercise controlled halt, retained independent functions, timeliness and approved recovery or restart.
3. Define the minimal pre-halt evidence, binding to workload and event, integrity verification, protected collection and transfer, custody and retention. Verify investigator access and readback after the actual halt, and verify authorized recovery of protected records.
4. Record effective coverage, relevant alert and owner, permissions and any exceptions for each controller path. Test authorized change or removal of evidence according to the adopted policy.

- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/)
