# SAF-K8S-0503-004 internal load balancer admission

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0503-004 --docker-context desktop-linux
```

This case runs real Service creates and updates on a fresh Kubernetes v1.36.1 Kind cluster. Before the policy, an unannotated LoadBalancer Service is accepted. The policy then checks the explicit AWS scheme and permits the internet-facing exception only through a separate fixture identity with an approved source range. It rejects missing schemes, the legacy key alone, unapproved exposure, and absent or unapproved ranges. An ordinary ClusterIP Service and a permitted update still work. Denials must name the policy and binding and include the expected admission message.

The two test identities have scoped Service permissions. The runner impersonates the fixture identities in the isolated cluster. The fixture address ranges and approval identity are examples. In a deployment, protect authorization to use the exception identity, confirm the provider's effective scheme and source filtering, and verify external reachability.

The gate covers Kubernetes admission. Cloud provisioning and the organization's exception approval are verified separately.

[Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/), [AWS Load Balancer Controller annotations](https://kubernetes-sigs.github.io/aws-load-balancer-controller/v3.2/guide/service/annotations/), and [EKS Auto Mode annotations](https://docs.aws.amazon.com/eks/latest/userguide/auto-configure-nlb.html).

## Adopter verification

Inventory each effective load-balancer controller, class and version, and confirm the internal scheme value for that implementation. Verify policy attachment and authorization for approved exceptions on both Service creation and updates. Use owned test Services for the internal path and an explicitly approved external case. Record admitted Service configuration and independently inspect the controller's reconciled scheme, listener and source restrictions. Verify allowed and excluded source reachability from owned test locations. Record the address family, effective rule and reachability outcomes, change approval and policy revision. Validate provider-specific restrictions and exceptions in the actual network path.

[Kubernetes Service API](https://kubernetes.io/docs/reference/kubernetes-api/core/service-v1/) · [Amazon EKS Auto Mode NLB annotations](https://docs.aws.amazon.com/eks/latest/userguide/auto-configure-nlb.html)
