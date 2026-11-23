# SAF-K8S-0702-010 Tenant API separation

The case compares one shared Kind API with two real vCluster APIs installed from the pinned official chart. Two namespace arguments still refer to one cluster-scoped host CRD. The separate virtual APIs each create the same CRD and a marker with its own value. Scoped authorization reviews confirm selected host decisions for inert tenant subjects.

Tenant API clients use only temporary fixture credentials over verified loopback TLS. The host kernel, network, storage, scheduler and sync permissions are shared or separately governed. Production identity and runtime isolation require additional evidence.
