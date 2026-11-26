# Verify cloud load-balancer source filtering

Run the portable native admission case from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0503-006 --docker-context desktop-linux
```

The disposable API compares permitted and refused AWS NLB Service group references against the fixture's governed list. It verifies a permitted update and unchanged stored state after refused input. The receipt covers admission of declarations. Effective cloud network filtering is an adopter verification step.

For each adopted provider and controller mode, inventory the real frontend listeners, source ranges, security groups or firewall rules, backends, address families and relevant node or host policy. Confirm which options the controller implements and where it applies them. Inspect the reconciled frontend and backend rules. On authorized owned test paths, compare sources inside and outside the approved range and record observed reachability and the effective rule at each relevant boundary. Include exceptions, alternate routes and changes made through the provider interface in the evidence.

[AWS Load Balancer Controller v3.2 Service annotations](https://kubernetes-sigs.github.io/aws-load-balancer-controller/v3.2/guide/service/annotations/) · [GKE Service load balancer parameters](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/service-load-balancer-parameters) · [AKS load balancer configuration](https://learn.microsoft.com/en-us/azure/aks/configure-load-balancer-standard)
