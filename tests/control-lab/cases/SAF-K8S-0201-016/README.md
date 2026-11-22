# SAF-K8S-0201-016 Node audit forwarding and centralized reviewability

```sh
python3 lab.py test SAF-K8S-0201-016 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0201-016.md)
requires retention and centralized forwarding of kubelet-file-access telemetry.
The scoped [file audit case](../SAF-K8S-0201-015/README.md) covers Linux rule
behavior. This case takes a single inert ConfigMap record as input.

The private receiver returns a 503 while the forwarder retries and retains the
pending event. The sink has no record at this stage. After the receiver accepts
the retry, the sender removes its pending copy. A query retrieves the event.
Restarting the receiver creates a new Pod with the same bound volume, and the
same query returns the persisted event. The nonroot fixture Pods use no token
or host mounts. The forwarder uses an `emptyDir`, so the durability check
applies to the receiver's PVC.

Production evidence must cover the deployed audit agent and protected transport,
node-local spool durability, tail loss and rotation behavior, required retention,
operational search and alerting, and recurring verification across the node fleet.

- [Linux Audit upstream forwarding plugin](https://github.com/linux-audit/audit-userspace/blob/v4.2.1/audisp/plugins/remote/audisp-remote.c)
- [Kubernetes v1.36 PersistentVolumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)
