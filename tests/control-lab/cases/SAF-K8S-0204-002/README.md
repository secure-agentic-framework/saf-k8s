# SAF-K8S-0204-002 Kubernetes-aware detection rules

Kind emits real audit metadata for two public ConfigMap reads. Falco with its pinned userspace audit plugin evaluates the records, distinguishes the marked read from ordinary activity, and emits an alert with the original namespace, actor and audit ID. This fixture verifies one Kubernetes API-audit rule and its JSON output. Kernel event coverage, production forwarding, supported node inventories and prevention need separate evidence.

```sh
python3 lab.py test SAF-K8S-0204-002 --docker-context desktop-linux
```
