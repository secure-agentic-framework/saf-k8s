# SAF-K8S-0703-013 — Locality selection and topology spread

```sh
python3 lab.py test SAF-K8S-0703-013 --docker-context desktop-linux
```

Two kind workers carry synthetic failure-domain labels. One also carries a
synthetic locality label. The test shows a Pod running without the locality
constraint, another selecting the labeled worker, and a Pod asking for a
nonexistent label value staying pending for the expected reason.

Four matching Pods spread 2/2 with `maxSkew: 1`. A fifth can run on the
first domain at skew one. A sixth with the same placement runs while its
spread constraint is absent. Kubernetes leaves it pending for the expected
topology spread reason when that constraint is present.

Kubelet Topology Manager coordinates NUMA hints for node-local admission.
This case covers Kubernetes scheduling with synthetic labels. Verify actual
NUMA hints, accelerator fabric, vendor scheduler behavior, and recovery from
a domain outage on the target deployment.

[Kubernetes Topology Manager](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/topology-manager/) ·
[Kubernetes topology spread](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/) ·
[Kubernetes device plugins](https://v1-36.docs.kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/)
