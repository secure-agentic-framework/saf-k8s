# SAF-K8S-0202-007 — Container runtime user namespace isolation

This case is prepared for a live run through the repository's local kind runner.
It uses the runner's pinned `kindest/node:v1.36.1` image (containerd CRI) and
the pinned BusyBox image in `fixtures.py`. It compares the vanilla Pod mapping
with an explicitly opted-in `hostUsers: false` Pod by reading only
`/proc/self/uid_map` inside each workload. A successful isolated observation
requires container UID 0 to map to a nonzero host UID and a mapping range larger
than one ID. Both workloads also run an innocuous `id` and `printf` check.

The admission policy is an optional namespace-scoped guard. Its red server-side
dry run verifies an omitted `hostUsers` value is admitted before policy setup;
its green request verifies the same shape is denied afterward; a green-path
positive dry run explicitly sets `hostUsers: false`. The policy enforces explicit
opt-in in `saf-test`; it is not cluster-wide and does not retrofit existing Pods.

## Applicability and support boundaries

- Kubernetes API support for Pod user namespaces does not by itself guarantee
  that a node can run them. The Linux kernel, CRI runtime, and node configuration
  must support user namespaces. This case only targets the pinned local kind
  image and its containerd runtime; it makes no claim about other runtimes,
  distributions, managed clusters, or kernel configurations.
- The live run must be treated as unsupported if the user namespace Pod cannot
  schedule/start or if its UID map does not demonstrate the requested mapping.
  A manifest accepted by admission alone is not runtime evidence.
- This case checks only namespace mapping and benign workload functionality. It
  does not probe host files, capabilities, escape paths, vulnerabilities, or
  resistance to hostile workloads. UID mapping alone is not a complete isolation
  assessment.
- No live cluster or control review was run while preparing this case. The
  mapping, scheduler/runtime support, policy enforcement, and workload readiness
  remain unverified until a separately authorized lab run produces evidence.
