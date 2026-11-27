# SAF-K8S-0502-007 Cilium source IP verification and policy evidence

`python3 tests/control-lab/lab.py test SAF-K8S-0502-007 --docker-context desktop-linux`

The fixture installs a pinned Cilium release in an owned Kind cluster and
records its effective agent configuration and the fixture namespace and
Pod annotation state. Three ordinary, exact-signature HTTP requests
exercise the reachable baseline, a Cilium NetworkPolicy refusal with a
matching Hubble verdict, and retained access to the allowed endpoint.

The receipts identify the live source and destination Pods, IPs, and Cilium
observations. Invalid-source packet drop behavior, managed CNI and
alternate-path coverage remain unverified.

The corrected catalog requires each adopter to identify its supported source
validation paths, relevant managed endpoints, approved exceptions and
uncovered network paths. This reference observes Cilium 1.20.5 configuration,
the exact fixture Pod annotations and ordinary IPv4 policy and telemetry.
Enforcement for deployed address families, chained or additional interfaces,
provider datapaths and host-network paths needs scoped evidence.

- [Cilium 1.20.5 chart configuration](https://github.com/cilium/cilium/blob/v1.20.5/install/kubernetes/cilium/values.yaml)
