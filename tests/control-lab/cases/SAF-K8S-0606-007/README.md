# Verify scoped build process, file and connection observations

    python3 tests/control-lab/lab.py test SAF-K8S-0606-007 --docker-context desktop-linux

The lab checks the pinned Tetragon process and file events for an inert
runner in a disposable namespace. Two successful HTTP marker requests use
an owned ClusterIP Service. The first precedes the specific connection
policy; the second produces a matching tcp_connect record attributed to
the runner Pod, policy and destination port. The case retains the response
and event observations for that comparison.

For a deployment, inventory governed runners, build VMs and managed build
services. Verify monitor versions, node and kernel coverage, namespace and
workload attribution, policy state and approved event sources. Confirm
separate CI and API audit records, the actual collector and alert route,
latency and loss limits, redaction and evidence retention. This fixture
covers the local sensor and its event output for the selected cases.

The test runner also relays the exact observed marker event to an ephemeral authenticated receiver bound to loopback. Independent readback retains exactly one event digest. The receiver refuses the other marker's process event, a modified-path comparison and wrong credentials. This witness uses a fixture-local relay.

## Workload-owned export

The sixth check starts a bounded exporter Job in the owned namespace after
the loopback comparator. It authenticates to the Kubernetes API with its projected
ServiceAccount token and mounted API CA, then reads only the `export-stdout`
log subresource for the exact Ready Tetragon DaemonSet Pod. Its Role grants
`get` on `pods/log` with that exact Pod name in `resourceNames`; a request for
a second existing Ready Pod in the same agent namespace must receive 403. The exporter selects the actual
`process_kprobe` marker event for the exact policy and fixture Pod and
correlates it to `process_exec`. The runner does not pass event bytes to it.

The exporter sends the selected event over HTTPS to a ClusterIP-only receiver
whose certificate SAN matches the Service DNS name. The receiver requires a
client certificate from a temporary case CA and checks the expected exporter
URI SAN. Before sending, the exporter confirms that a TLS handshake without a
client certificate fails. The receiver uses a separate projected token to
create one immutable ConfigMap receipt. Its Role plus a
ValidatingAdmissionPolicy restricts that ServiceAccount to the exact receipt
name and labels. The runner independently reads that API object and checks
normalized predicates plus the selected event SHA-256 digest.

The case generates CA and leaf keys in its private temporary directory with
mode 0600. `kubectl create secret` receives file paths only. Keys and raw event
data are absent from new command payloads, output, and check observations. The
Job has a 60-second deadline and requests 10m/32Mi with 100m/96Mi limits. All
resources are confined to the disposable cluster and removed with it.

This adds a local proof that a case-owned workload exports one selected
Tetragon event over authenticated transport and that the receipt is read back
independently. It does not establish production alert routing, fleet
enrollment, event durability, detection latency or loss objectives, CI
provider audit, or coverage beyond this pinned Kind/Tetragon fixture. Verify
the adopted Tetragon export, other audit sources, alert routing, and operating
objectives on their actual paths.

The design follows the pinned [Tetragon v1.8.0 event JSON interface](https://github.com/cilium/tetragon/blob/v1.8.0/docs/content/en/docs/concepts/events.md)
and [chart values](https://raw.githubusercontent.com/cilium/tetragon/v1.8.0/install/kubernetes/tetragon/values.yaml),
plus [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
and [projected ServiceAccount volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/projected-volumes/).
