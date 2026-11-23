# SAF-K8S-0501-008 case draft

This case exercises an explicit workload-class communication matrix across four
case-owned Kubernetes namespaces. It creates only disposable resources in those
namespaces. The lab harness provisions and deletes the cluster; the case itself
does not create clusters or touch other namespaces except reading the runner's
kind version and `kube-system/kindnet` identity/readiness.

## Tested profile

- kind `v0.32.0`
- Kubernetes `v1.36.1`, the default node image pinned by that kind release
- kind's bundled `kindnetd` network plugin
- One BusyBox client and one fixed-marker HTTP responder per workload class
- Direct Pod IPv4 addresses, TCP port 8080; no Service, DNS, or external target

The policy matrix allows `training -> pipeline`, `pipeline -> training`,
`pipeline -> inference`, and `notebook -> training`. The other eight directed
cross-class paths must be denied. One same-class client-to-responder path per
namespace must remain useful. Both ingress and egress policy are configured at
each boundary; the same flow has to match an explicit selector rule on both
ends.

## Run

Place this directory at `cases/SAF-K8S-0501-008/` in the lab checkout. From the
lab root, the normal supervised replay is:

```sh
python3 reference/lab.py test SAF-K8S-0501-008
```

Use the lab's approval flow for supervisor review where required. Do not run
this against a user or production cluster. A successful replay should record
the catalog and control hashes, pinned node image, Kubernetes server version,
case scope, red baseline, green denied paths, positive allowed paths, and
cluster cleanup state in the harness result.

## Evidence interpretation

Before policy installation, all 12 exact client-to-responder cross-class
requests must return the destination's fixed marker. After policy installation,
each denial must produce three repeated transport timeouts while all eight
case-owned Pods remain Ready. A non-timeout failure is reported as ambiguous
and blocks the case; it is not counted as policy evidence. Allowed paths must
continue returning their exact responder markers. The repeated timeout is
attributable to the controlled policy scenario only in combination with the
same-path baseline, the unchanged case-owned endpoints, the observed namespace
labels, and the installed rules. NetworkPolicy has no standard per-drop signal,
so this is not a direct read of a specific policy decision.

No cluster replay was performed while drafting this case. The supervisor must
verify and replay it before treating any red, green, or positive observation
as an executed receipt.
