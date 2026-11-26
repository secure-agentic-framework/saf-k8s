# Verify network egress and approved model-source selection

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0905-054 --docker-context desktop-linux
```

The case checks default-deny client egress to owned in-cluster and
outside-cluster endpoints, then permits DNS and a narrowly selected proxy.
An independent namespace remains able to reach the fixture endpoints.
The test uses the bundled kindnet CNI.

The model proxy maps one exact source identifier to an approved fixture
upstream. It retrieves the approved JSON marker and refuses a second
reachable source. Separate counters at each upstream show that the approved
request was sent and the refused source received none.

In a deployment, inventory all fetch paths and apply egress controls to
both workloads and the proxy. Verify resolution and redirects, the actual
approved destinations, IP families, and equivalent provider boundaries.
Use fixture endpoints and demonstrate that removing a source approval
blocks it for the governed workloads. Kubernetes NetworkPolicy selects
network peers and ports. Application source selection runs at the proxy.
