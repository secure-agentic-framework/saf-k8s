# SAF-K8S-1001-017 — Native API audit decision attribution

```sh
python3 lab.py test SAF-K8S-1001-017 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. The case starts a fresh Kubernetes v1.36.1 Kind cluster with a narrowly selected file audit policy. It uses curl and OpenSSL for the pinned Metrics Server installation and case-owned serving certificates.

- Scoped ConfigMap events show the difference between an RBAC 403 and an admission 403 after RBAC authorization. An allowed create returns 201 and persists. The matched omitted-namespace request has no selected audit event.
- Request-level SubjectAccessReview and Role events preserve the selected input without recording response bodies.
- The registered HTTPS webhook publishes distinct audit annotations for an exact denial and an allowed create. The denied resource stays absent. The approved object persists.
- Metrics Server v0.8.1 provides the named fixture PodMetrics resource using TLS-verified kubelet and aggregation endpoints. The exact GET returns 403 for the ungranted fixture identity and 200 for the authorized one. Both outcomes appear at Metadata level.

The fixture contains synthetic resources and identities. The generated serving keys remain in the disposable run. Production audit inventory, delivery, retention, other operations and managed-platform coverage require separate evidence.

[Original control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-1001-017.md) · [Kubernetes audit levels](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [Metrics API](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/resource-metrics-pipeline/) · [Admission response API](https://v1-36.docs.kubernetes.io/docs/reference/config-api/apiserver-admission.v1/)

For a deployed cluster, record the relevant API groups, resources, verbs, admission annotations, assigned audit levels, managed-service limitations and protected destinations. Compare observed denial and approval records to independent API decisions. Select Request or RequestResponse only when the necessary fields cannot be recovered at Metadata. If the scope includes a high-risk AI system, identify which API decisions support traceability and how the organization determines risk or substantial modification.
