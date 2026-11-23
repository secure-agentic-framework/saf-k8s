# SAF-K8S-0905-037 — Invoke a manual halt and retain evidence

    python3 tests/control-lab/lab.py test SAF-K8S-0905-037 --docker-context desktop-linux

The fixture starts two inert Deployments. An ordinary identity receives an API denial for the same scale request the authorized responder later invokes. Before the halt, the responder records the target's actual template, state and synthetic logs in an immutable ConfigMap. A distinct investigator reads and verifies the record after the target Pod is removed. The unrelated Deployment remains active.

The runner measures the interval from case invocation through evidence capture to observed halt against a declared 45-second fixture budget. Production timeliness, responder governance, forensic scope and long-term storage require deployed evidence.

- [Kubernetes 1.36 Deployment](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/)
- [Kubernetes 1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes 1.36 ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/)
