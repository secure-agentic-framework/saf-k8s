# SAF-K8S-0505-003 — Internal service endpoint protection

Run from the framework root with the reviewed Kind, Helm and Cilium prerequisites.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0505-003 --docker-context desktop-linux
```

The isolated v1.36.1 cluster uses pinned Cilium. The case checks defaulted ClusterIP and selector-backed headless Service behavior. It verifies both fixture clients initially reach each Service and the Pod IP. After an ingress NetworkPolicy is applied, the authorized client still reaches the marker on each path. The unselected client times out on each.

A scoped ValidatingAdmissionPolicy independently checks Service types. A LoadBalancer CREATE dry run is admitted before the rule and receives the exact policy denial after it. The owned stored ClusterIP accepts an annotation update in server-side dry run without persisting it. The LoadBalancer UPDATE receives the exact denial and the stored Service remains ClusterIP at the original resource version. The pre-existing NodePort and ClusterIP comparators exercise the same scoped admission. Provider-backed load balancers are outside the disposable test.

For adoption, inventory internal Services and access routes, including headless endpoints, direct Pod access, in-cluster proxies and cloud-specific routes. Test the effective CNI enforcement with representative permitted and refused flows. Check policy enrollment and exceptions, exact Service type defaults and updates, and attempted bypass through alternate exposure routes in approved nonproduction.

[Kubernetes v1.36 Service types](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/) · [Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
