# SAF-K8S-0102-013 — etcd compaction and periodic defragmentation

```sh
python3 lab.py test SAF-K8S-0102-013
```

The case runs two separate official etcd 3.6.8 containers with Docker network
mode `none`; each has an ephemeral data directory and is removed after its
check. The harness also creates its ordinary disposable kind cluster, but this
case does not query or change Kubernetes resources or its embedded etcd.

The manual maintenance process uses three public synthetic marker keys and one
128 KiB padding value that it deletes before compaction. It captures the etcd revision, reads the marker's
old value at its exact historical revision, explicitly compacts the current
revision, then checks that the old read returns the compacted-revision error
while exact latest reads of all three keys still succeed. It next runs one
online `etcdctl defrag` against that isolated single member. Endpoint status
records `dbSize` (allocated bytes) and `dbSizeInUse` (bytes in use) before and
after defrag, and requires allocated size to decrease while subsequent reads
keep returning the latest expected values.

The measured allocated and in-use database bytes before and after defrag are
written to `raw-evidence.json` for each run. Stable check observations retain
the measured predicates: valid nonzero size metrics, allocated bytes at least
in-use bytes, lower allocated bytes after defrag, and successful latest-value
reads. The periodic compaction check also stores its measured elapsed time in
that artifact; its 40-second upper bound and compacted-revision/latest-read
conditions remain enforced and visible as stable observations.

A second instance uses periodic auto-compaction with an 8-second retention
window. The exact old marker read must work before expiry, then return etcd's
compacted-revision error within 40 seconds while the latest exact-key read
continues to return its current marker. Timing is bounded; it is not a
production retention recommendation. This fixture does not create a lease or
verify lease expiry and key cleanup; those lease behaviors remain untested.

## Claim and scope notes

etcd history compaction makes older keyspace revisions inaccessible; it makes
space available for reuse inside the backend but does not by itself return
fragmented database space to the filesystem. Defrag is a per-member operation
and blocks reads and writes on that member while rebuilding its state. The
case establishes the API behavior and observes reclaimed backend bytes on a
disposable single-member process. Sequential operation and availability across a
multi-member cluster remain explicitly untested.

Kubernetes also issues compaction requests from kube-apiserver. The Kubernetes
v1.36 command reference documents `--etcd-compaction-interval` with a default
of five minutes and a zero value that disables apiserver compaction. This is a
separate compactor from etcd's configured periodic retention. Operators must
account for both mechanisms and their history windows; the executable case
does not test controller overlap or deployed settings. Kubernetes v1.36
apiserver source describes retaining recent history and issuing a compaction
periodically, while etcd's periodic auto-compactor independently operates from
its configured retention window. Coordinate them so one mechanism does not
compact history that another component still expects to read.

## Versioned primary sources

- [etcd v3.6 maintenance: history compaction, automatic retention, defrag, and database size metrics](https://etcd.io/docs/v3.6/op-guide/maintenance/)
- [etcd v3.6 configuration options: auto-compaction mode and retention](https://etcd.io/docs/v3.6/op-guide/configuration/)
- [Kubernetes v1.36 kube-apiserver command reference: `--etcd-compaction-interval`](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [Kubernetes v1.36.1 apiserver compactor source](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/storage/etcd3/compact.go)
- [etcd v3.6 release notes: online-only `etcdctl defrag`](https://etcd.io/blog/2025/announcing-etcd-3.6/)

The default kube-apiserver compaction interval is not itself a guarantee about
the deployed configuration or a universal retention duration. Confirm actual
apiserver flags and etcd auto-compaction settings for the cluster under review.
