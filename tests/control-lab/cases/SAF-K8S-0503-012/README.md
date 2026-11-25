# SAF-K8S-0503-012 — Client source IP preservation for external services

```sh
python3 lab.py test SAF-K8S-0503-012 --docker-context desktop-linux
```

A non-root fixture client attaches to the local Docker bridge shared by
the fresh Kind nodes. The case reads that container's actual IPv4 from
Docker, verifies the owned nodes and their bridge, and sends ordinary
HTTP requests to the worker NodePort. The ready backend reports the peer
address of the accepted connection along with a fixed marker.

All three `Cluster` requests reach the endpoint with rewritten peer
addresses. After the policy changes to `Local`, all three requests to the
same NodePort and backend return the same marker with the actual client
IPv4. The archive records comparisons that hold across separate runs. The
lab also retains the measured socket addresses as a separate receipt.

This covers the pinned Kind kube-proxy path. Production verification
covers the actual external ingress path, provider and proxy behavior, and
reviewed Service configuration. The routing mode tradeoffs have their own
control, SAF-K8S-0503-011.

- [Kubernetes v1.36 source IP behavior](https://v1-36.docs.kubernetes.io/docs/tutorials/services/source-ip/)
- [Kubernetes v1.36 external traffic policy](https://v1-36.docs.kubernetes.io/docs/reference/networking/virtual-ips/#external-traffic-policy)

## Adopter verification

Inventory every in-scope client-to-Service path, including provider load balancer, proxies, NAT and address family. From an approved test client, send a benign marker request and capture the client address and peer observed at the intended backend/boundary. Compare the two and document where source translation is expected or prohibited. Repeat for each materially different provider/proxy path and retain the Service routing mode.
