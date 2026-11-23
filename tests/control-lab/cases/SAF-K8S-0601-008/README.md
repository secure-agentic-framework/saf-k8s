# SAF-K8S-0601-008 build-time image scanning

Run `python3 lab.py test SAF-K8S-0601-008` from the control-lab directory.

The pinned scanner opens two deterministic inert image archives with networking
disabled. The local advisory database and package name are invented. A Kind
workload makes promotion decisions for exact OCI image digests and pushes only
permitted artifacts to the case-owned Distribution registry. A separate pod
reads back the manifests and their referenced blobs.

The fixture tests one package and a fixed clock. Deployment evidence should
cover scanner coverage, advisory freshness and authenticity, report signing,
privileged release paths, alternate architectures, and exception approval.
