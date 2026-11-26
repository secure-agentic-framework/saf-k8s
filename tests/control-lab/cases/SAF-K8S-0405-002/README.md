# Verify selected Kubernetes identity-use observations

    python3 tests/control-lab/lab.py test SAF-K8S-0405-002 --docker-context desktop-linux

The case records metadata for a scoped RoleBinding change and compares
the local review queue before and after its review exercise. Reconciliation
removes the selected excess fixture grant and preserves the approved read.

A case-owned Pod uses its projected ServiceAccount to read the one
approved named ConfigMap and attempt a second named read outside its Role.
The API returns allow and deny responses. Metadata-only audit attributes
the two exact requests and status codes to the Pod identity. The test
routes only the denied result to its local review queue.

For a deployment, identify effective identity and issuer boundaries and
the selected source events. Correlate authorized workload, provider and
runtime sources by approved identity and action. Verify actual delivery,
latency, retention, protected review access and authorized response.
