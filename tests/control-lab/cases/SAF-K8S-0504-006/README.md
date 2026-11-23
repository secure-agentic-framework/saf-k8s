# SAF-K8S-0504-006 SPIRE workload issuance and renewal

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0504-006 --docker-context desktop-linux
```

This fixture installs SPIRE 1.16.0 in a dedicated Kind cluster. It signs the owned kubelet's serving request, attests the agent with a Kubernetes projected service account token, and uses explicit Kubernetes workload selectors. An in-cluster verifier checks the issued URI, validity, local trust bundle and TLS handshake. A separate watch verifies renewed validity for the same SPIFFE ID. An unregistered fixture is denied.

The fixture keeps its X.509 private material inside a workload memory volume and retains only verification outcomes. It verifies local issuance and renewal. Production server and agent availability, actual consumer reload behavior, and federation need separate evidence.

[SPIRE workload registrations](https://spiffe.io/docs/latest/deploying/registering/), [SPIRE Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/), and [SPIRE Agent CLI](https://spiffe.io/docs/latest/deploying/spire_agent/).
