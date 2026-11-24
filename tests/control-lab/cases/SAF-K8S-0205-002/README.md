# SAF-K8S-0205-002 NodePort and HostPort admission and reachability

The test uses Baseline Pod Security for the ordinary namespace and separate Pod
and Service ValidatingAdmissionPolicies. Those policies are verified on actual
API requests, including Pod init containers, Service updates, and explicit and
default LoadBalancer node-port declarations. An owned client Pod on the other
node sends marker requests to the exact fixture IPv4 addresses and ports and
checks that the ClusterIP alternative remains reachable.

The test's isolated exception namespace uses the Privileged Pod Security
profile to allow a HostPort exception to reach its separate policy. The demo
policy gates precisely this port mechanism. It compares two identities that
have the same create RBAC and requires the approved identity, namespace, name,
TCP port and current approval label. It shows that withdrawing the approval
denies recreation and that already-admitted listeners remain reachable until
removed. The lab does not expose host ports outside the private Kind network.

```sh
python3 lab.py test SAF-K8S-0205-002 --docker-context desktop-linux
```

## Verify on an adopter's cluster

1. Inventory predicted node paths and who owns them. Distinguish Pod HostPort,
   Service NodePort, LoadBalancer target mode, and Gateway or Ingress paths.
   Record governed namespaces, Pod profiles, address families, node address
   selection, routes, provider firewall, service controller and CNI. Use
   `kubectl get services -A -o yaml`, `kubectl get pods -A -o yaml`,
   `kubectl get nodes -o wide`, and approved controller and firewall exports.
2. Check Pod and Service admission separately with server-side dry-run in an
   equivalent staging namespace, using unapproved and approved identities.
   Cover ordinary and init containers, CREATE and UPDATE, and explicitly
   selected and automatically allocated Service ports. Verify that existing
   LoadBalancers with allocation disabled have no retained node ports and
   that the selected controller can deliver traffic in its target mode.
3. Scope approved exceptions by owner, identity, namespace, object, ports,
   protocol and allowed sources. Keep applicable Pod hardening controls in
   the exception namespace. Record approval and expiry in the organization's
   change system. At expiry, withdraw the approval, check admission again,
   remove or replace existing exposures, and verify the path closes.
4. For each governed route, probe a benign marker only at the explicitly
   authorized owned source and destination. Check the approved path and the
   allowed internal alternative, the expected absence of unapproved paths,
   and cleanup. Repeat on each used IP family and applicable controller.
   Retain the bounded path matrix, exact admission decision, effective
   controller and network observations, ownership, timestamps, and result.
   Leave the deployment verdict open when required paths or approval details
   lack evidence.

This fixture tests IPv4 TCP, the pinned Kind CNI and Service proxy, and a
manually withdrawn exception. Controller-specific LoadBalancer reachability,
other network paths, and scheduled approval expiry require adopter evidence.

- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes v1.36 Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 Services](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/)
