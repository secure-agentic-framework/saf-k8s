# SAF-K8S-0205-009 Service proxy API privileges

The case uses real Kubernetes authorization for the active kube-proxy service account. It compares an unnecessary fixture grant with its removal, confirms required reads, and reaches an owned ClusterIP through the same active proxy. The extra grant covers only a harmless ConfigMap in the lab.

Node capability reduction, approved backend state settings, and managed-service or replacement privileges require deployment-specific evidence.

```sh
python3 lab.py test SAF-K8S-0205-009 --docker-context desktop-linux
```
