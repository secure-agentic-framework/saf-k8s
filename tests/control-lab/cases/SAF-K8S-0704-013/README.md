# SAF-K8S-0704-013 Audit producer and destination receipt

The test creates a disposable Kind cluster with a metadata-only audit policy for one owned ConfigMap patch. It verifies that the real API event exists before configuring the fixture collector to deliver it. An independent read of the local sink then checks the exact audit ID and separate Kubernetes and synthetic-provider identities.

The provider input and the collector enrollment gesture are local fixtures. Managed service settings, transport, retention and production delivery require evidence from those environments.
