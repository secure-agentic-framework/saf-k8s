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
