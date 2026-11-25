# SAF-K8S-0103-014 — Scheduler operational serving and Pod placement

```sh
python3 lab.py test SAF-K8S-0103-014 --docker-context desktop-linux
```

On the pinned kubeadm kind node, check the scheduler's actual secure listener
and a fixed HTTPS health status on loopback. The check discards the response
body. The scheduler's HTTPS server exposes operational routes. Pod placement
and binding are Kubernetes API operations.

The ordinary case-owned workload submitter can create Pods. A live
authorization review shows that the stock scheduler can create the named
Pod binding and the ordinary submitter cannot. A dry-run Pod specifying a
node demonstrates that denying the binding subresource alone leaves a separate
request path. A namespace-scoped admission policy rejects direct node assignment
on Pod CREATE, and a permitted Pod without an explicit node is placed by the
stock scheduler. The case makes no direct binding request and uses no
unauthenticated metrics or profiling route.

Deployment review still covers approved monitoring paths and identities,
custom schedulers, other placement rules, IPv6 or other network profiles,
and managed provider responsibilities. The disposable cluster is deleted.

- [Kubernetes v1.36.1 scheduler operational handlers](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kube-scheduler/app/server.go)
- [Kubernetes v1.36 assigning Pods to nodes](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)

## Adopter verification

1. Inventory each default or custom scheduler, deployment profile, and
   provider ownership boundary. Record the actual secure listener, its
   certificate trust, and each authorized monitoring identity and route.
2. Verify allowed and denied access from approved control-plane and
   monitoring origins. Check the intended health, metrics, or diagnostic
   paths separately. The [secure metrics case](../SAF-K8S-0103-017/README.md)
   demonstrates verified loopback TLS and scoped monitor authorization.
3. Resolve the effective subjects authorized for Pod binding, including
   direct, inherited, and administrative grants. Compare permitted and
   denied tuples with authorized access reviews.
4. Rehearse applicable placement constraints using server-side dry-run
   and a permitted synthetic workload. Include direct node assignment,
   selected scheduler profiles and applicable exemptions. Preserve the
   policy revision and provider evidence for managed routes.
