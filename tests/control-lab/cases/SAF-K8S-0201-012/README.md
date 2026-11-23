# SAF-K8S-0201-012 kubelet endpoint lockdown

Run `python3 tests/control-lab/lab.py test SAF-K8S-0201-012 --docker-context desktop-linux`
from the framework root.

This case reads the live configuration on the disposable Kind v1.36.1
node. It confirms anonymous authentication is disabled, the secure
listener is present, and TCP 10255 has no listener. It compares a
TLS-verified credential-less health request with the trusted Kubernetes
API proxy path. The probe uses the fixture's own serving chain and does
not open or enable the legacy endpoint.

Deployed node pools, managed provider attestations, and network-boundary
evidence remain separate verification work.

- [Kubelet authentication and authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
- [Kubelet v1beta1 configuration](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)
