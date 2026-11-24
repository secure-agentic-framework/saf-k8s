# SAF-K8S-0203-010 — Minimal node OS baseline

Build the fixture from the pinned upstream Kind node image, then pass the
returned local image ID to the runner. Run these commands from the control lab
directory.

```sh
image_id=$(DOCKER_CONTEXT=desktop-linux sh cases/SAF-K8S-0203-010/build-node.sh)
python3 lab.py test SAF-K8S-0203-010 --docker-context desktop-linux --local-node-image "$image_id"
```

The fixture starts a pinned stock worker and a derivative without APT. It
binds each worker to its expected image ID and compares their package and
account inventories. It checks that the derivative has no APT scheduling
units and that kubelet and containerd are active. A restricted Deployment
first reaches Ready on the stock worker. Its readiness probe checks cluster
DNS and the mounted ConfigMap marker. The case drains the stock worker and
observes a new Ready Pod from the same Deployment and ReplicaSet on the
approved worker.

## Verify deployment applicability and evidence

1. Identify the image, architecture, and role of each governed node pool.
   Tie `kubectl get nodes -o wide` and each Node's provider identity to the
   provider launch template or signed image build. Verify approval and the
   vendor's support for that OS and Kubernetes version. Draw the boundary
   between customer-managed and provider-managed hosts.
2. Reconcile the actual booted package/SBOM, accounts and administrative paths,
   enabled and running units, listeners, host extensions, and management agents
   against the approved profile. Where supported, collect read-only evidence
   with `dpkg-query` or the OS package tool, `getent passwd` and `getent group`,
   and `systemctl list-unit-files` and `systemctl list-units`. Use equivalent
   provider inventory on opaque nodes. Retain versions, evidence timestamps
   and owners, and how any exception is scoped, approved and reviewed.
3. Use the provider's supported replacement path in disposable staging. Bind
   the replacement to its approved image identity, then verify prohibited
   components remain absent, required services are healthy, and new Pods
   exercise relevant DNS, networking, storage, security, maintenance and
   accelerator functions for that pool. Record the supported rollout, workload
   transition, health and rollback evidence for the prior approved image.
4. Treat provider support, immutable image claims, component exceptions and
   compatibility as scoped observations. The APT exclusion demonstrates one
   policy on this fixture; each adopted node profile defines its own exclusions
   and required operations. Missing evidence for a managed pool leaves its
   deployment outcome unverified.

[Kind node images and configuration](https://kind.sigs.k8s.io/docs/user/configuration/) ·
[NIST SP 800-53 CM-7](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

[Kubernetes v1.36 node drain](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/)
