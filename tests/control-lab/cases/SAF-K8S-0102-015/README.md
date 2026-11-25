# SAF-K8S-0102-015 etcd certificate recovery drill

From the framework root, run `python3 tests/control-lab/lab.py test SAF-K8S-0102-015 --docker-context desktop-linux`.

The case runs on one disposable kubeadm-managed Kind control plane. It
checks verified etcd health, stages a mismatched leaf pair in the node,
and observes the explicit etcd TLS error and lost health. It restores the
original matching pair, confirms etcd health and Kubernetes readiness,
and checks both an existing object and a new API write. The original
key stays on the disposable node throughout the rehearsal.

The case measures one local restoration. Production quorum, issuer
transitions, outage tolerance, monitoring and repeated procedure rehearsal
require deployed evidence.

- [Kubernetes v1.36 kubeadm certificate management](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/)
- [etcd transport security](https://etcd.io/docs/v3.6/op-guide/security/)

## Adopter verification

1. Record the etcd topology, issuer and certificate roles, planned maintenance
   and escalation authority, and the approved recovery time objective for etcd
   and the Kubernetes API. Tie the rehearsal to that objective and the
   versioned recovery procedure.
2. In an authorized rehearsal environment, verify the known-good key and
   certificate pairing, live issuer and trust, member health, API readiness,
   and an approved marker object before the change. Confirm how operators or
   automation obtain and apply the approved rollback files. Retain public
   certificate details and verdicts. Keep keys and credentials outside the
   evidence bundle.
3. Exercise an approved failure or partial-rotation scenario. Capture the
   intended error and the health signal that detects it. Record when detection
   and recovery started, the resulting decision, and the rollback command or
   alternative supported recovery action.
4. Verify the active restored certificate and trust, member health and quorum,
   Kubernetes API readiness, a preexisting marker read, and a permitted new
   write and read. Record elapsed disruption and compare it to the approved
   recovery objective. Open a follow-up for unmet time or availability bounds.
5. Record coverage of issuer, member topology, certificate roles, and failure
   modes. For separate issuers or managed endpoints, collect the applicable
   provider or issuer procedure and authorization for the rehearsal. Keep the
   dated evidence with the maintenance record and assign the next review owner.

The [companion successful-rotation case](../SAF-K8S-0102-014/README.md)
exercises certificate-role coverage. The rollback case demonstrates one
single-node local-issuer mismatch and recovery. Check the organization’s
issuers, member topology and recovery targets with their own evidence.
