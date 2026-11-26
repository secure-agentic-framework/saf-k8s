# SAF-K8S-0904-003 — Notebook workspace isolation

Each workspace is an upstream digest-pinned Jupyter base-notebook Pod with a
distinct non-root UID and a tokenless ServiceAccount. NetworkPolicy closes
the cross-workspace paths while both ordinary dataset reads still succeed.
Native admission rejects the same unpinned image that passes its baseline.
Each admitted workspace then executes a fixed cell through a real local
Jupyter kernel.

The case covers Kubernetes workspace boundaries, an approved image reference,
and basic kernel execution. JupyterHub identity and spawner integration,
extension review, external data entitlements, and image provenance require
deployment evidence.

## Verify adopted user and workspace boundaries

1. Identify the actual notebook authority, allowed user and group claims, session policy, and supported spawner. Trace two approved synthetic test identities from the real authentication path to exact namespace, Pod, service account and storage permissions. Verify an unapproved test identity cannot spawn a workspace.
2. Inspect hardened images, image approval and Pod restrictions. Compare effective workspace and user identities to API and volume access, including role changes, session expiry, and approved extensions and publication workflows.
3. Exercise allowed own-workspace operations and refused cross-workspace data, storage and network paths using authorized test data. Include each relevant network path and the approved egress policy.
4. Correlate actual adoption audit and ownership evidence to the approved user, rendered workload and session. Include session stop, access removal, artifact handling and storage retention.

- [Zero to JupyterHub chart 4.4.5](https://github.com/jupyterhub/zero-to-jupyterhub-k8s/blob/4.4.5/jupyterhub/Chart.yaml)
- [KubeSpawner 7.1.0 configuration](https://jupyterhub-kubespawner.readthedocs.io/en/7.1.0/spawner.html)
