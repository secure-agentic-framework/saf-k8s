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
