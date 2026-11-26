# SAF-K8S-0503-005 — DNS query logging and scoped detection

Run from the framework root.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0503-005 --docker-context desktop-linux
```

The owned CoreDNS fixture first answers a canary query with logging disabled. With structured logging enabled, a fresh Pod answers the canary and ordinary queries. A separate Job reads the exact log rows and reports only the canary.

The second observer reads real CoreDNS logs for eight inert questions in the fixture zone. It verifies the per-name batch count, label length, label entropy, and query type rules. The two-query comparison stays below the three-query fixture threshold. Separate labels exercise the length and entropy conditions, and a TXT query exercises the type condition. The receipt retains the full set of observed rule results. The batch uses one owned client and the authoritative fixture server.

For adoption, inventory actual DNS paths, including node-local and managed resolvers and permitted alternate resolvers. Verify scoped, privacy-reviewed logs through the approved destination. Link queries to their observed source where the network and collector preserve it. Tune time-window and source-aware rules against the environment's expected names and types, and verify the alert route, recipient, retention, and performance. The fixture exercises detection based on selected log fields. DNS enforcement and protected routes have separate acceptance checks.

[CoreDNS log plugin](https://coredns.io/plugins/log/) · [Kubernetes v1.36 DNS debugging](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/dns-debugging-resolution/)

## Read CoreDNS logs through the API

After the original detection checks, a separate Job runs as a named
ServiceAccount with a short-lived projected token. Its Role grants metadata
access to two named fixture Pods and log access to the single CoreDNS Pod.
The Job verifies the same CoreDNS UID before and after the API read. It
validates all ten fixture records and receives HTTP 403 from the other
owned Pod's log endpoint. The two provisioned names return NOERROR. The
eight intentionally absent names return NXDOMAIN. The evidence contains
only counts, status codes and the check outcomes.

For a deployed collector, verify effective credentials, source scope,
renewal, performance and failure detection. Preserve actual forwarding,
processing and receipt at the approved analysis destination. Protect query
data and verify alert delivery with approved benign control records.
