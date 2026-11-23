# SAF-K8S-0601-010 deployment-aware artifact retention

The case uses a private temporary registry and storage on an owned
Kind cluster. It deploys an immutable BusyBox digest and tests a cleanup
rule against live Deployment state, retention periods by artifact type,
and a hold. A fixture chart and a held model stay available. The expired
model is deleted and its unreferenced content goes through the registry's
garbage collector with the registry stopped.

The case uses fixed release dates. It requires local Helm and uses pinned
registry, Skopeo and BusyBox images. Production cleanup needs
additional coverage of deployment references, replication, artifact
relationships and lifecycle operations.

[CNCF Distribution garbage collection](https://distribution.github.io/distribution/about/garbage-collection/)
