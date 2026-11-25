# SAF-K8S-0102-014 rolling etcd certificate renewal

In the framework repository, run the three-member Kind demonstration with:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0102-014 --docker-context desktop-linux
```

The lab runner uses its own temporary kubeconfig and deletes the disposable
cluster. This profile starts three control-plane nodes.

## Observed behavior

The case identifies exactly three etcd members, their static Pods and their
corresponding API servers. It verifies a shared etcd CA, all nine public leaf
certificates, their expiry and role usage, and the baseline Kubernetes API.

For each member in sequence, kubeadm renews the etcd server, etcd peer and
API-server-to-etcd client leaf files. The other members' files stay unchanged.
The target member's local API pauses first so its kubelet can restart etcd
without waiting on calls to a local API that depends on the stopped etcd.
While the member is paused, its listener refuses connections, the two
remaining endpoints retain quorum, and the surviving Kubernetes API accepts
a synthetic ConfigMap write and read. After the restarted member presents its
new server leaf, the target API returns. The case checks that the live server
and peer leaves match their files and that the target API references the renewed
client file, reads the exact record locally, and becomes ready. The final
comparison confirms unchanged membership, three healthy endpoints, a leader,
and the original data.

The case compares certificate fingerprints and validity metadata in memory and
retains bounded check results. The API-server client comparison observes its
configured renewed file and a successful storage read. It does not inspect the
actual client certificate on the wire. The three Kind nodes share one
underlying failure domain.

## Reproduce the scheduling companion

The independently replayed single-member scheduling implementation is
preserved at framework commit
[`669f0d7b6`](https://github.com/secure-agentic-framework/saf-k8s/tree/669f0d7b6/tests/control-lab/cases/SAF-K8S-0102-014).
Run the same command from a checkout at that commit. Two CronJob-owned Jobs
evaluated explicit synthetic decision times against actual public leaf dates.
The due result selected the three certificate roles used by the renewal
comparison. The scheduling and three-member rollout are distinct test
scenarios.

## Verify a self-managed implementation

1. Inventory every voting member, hosting node, API-server client path and
   effective PKI issuer. Check the exact server, peer and client role usage,
   renewal ownership, expiry lead time and the trusted time source.
2. Exercise the approved automation with out-of-window and due test records.
   Inspect the controller's actual decision timestamps, receipt age and
   expected role set. Confirm an omitted role is detected and that the
   due path dispatches to the approved renewal executor.
3. Rehearse the serial rollout in a representative staging topology. Before
   advancing, preserve per-member renewal metadata, quorum and leader
   observations, TLS identity checks on the relevant endpoints, target API
   readiness, and a successful read of a preexisting fixture record.
4. Capture the policy and evidence used to stop on a failed step, alert the
   responsible operator, and restore service without risking quorum. Verify
   provider-managed paths under the documented ownership boundary when used.

Sources [Kubernetes v1.36 kubeadm certificate management](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/)
and [etcd v3.6 transport security](https://etcd.io/docs/v3.6/op-guide/security/).
