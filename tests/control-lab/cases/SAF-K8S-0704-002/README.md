# Verify Pod policy directions and API authorization on Kind

```sh
python3 lab.py test SAF-K8S-0704-002 --docker-context desktop-linux
```

The bundled Kind CNI enforces live policies against case-owned TCP markers.
The case observes destination ingress and source egress decisions separately,
then allows both directions for the selected path. An independent Kubernetes
API probe verifies a scoped Role while the workload policies are active.

This case tests local Pod connectivity and API authorization. Cloud subnet,
firewall and endpoint reachability need target-provider configuration and
controlled connectivity evidence.
