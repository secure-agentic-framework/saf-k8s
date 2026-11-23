# SAF-K8S-0303-003 SELinux categories

Run `python3 lab.py test SAF-K8S-0303-003` from the lab directory using the catalog
revision recorded with the verified result. The case persists two inert,
scheduling-gated Pods with different requested MCS levels and reads them back
from Kubernetes. Pod Security Restricted admits an omitted level and rejects
a custom role. A separate restricted Kind Job supplies the observed levels to
a disconnected ARM64 guest with the pinned Debian SELinux reference policy.

Two guest processes receive the observed categories during setup and preserve
their exact process contexts across the transition to enforcing. They can read
their matching synthetic canaries and cannot read each other's despite matching
DAC permissions. Changing only one object category changes both decisions.
Actual kubelet/container runtime labeling, production policy, and CSI volume
behavior need direct SELinux-enabled deployment evidence.

- [Kubernetes security contexts](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Red Hat MCS documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/assembly_using-multi-category-security-mcs-for-data-confidentiality_using-selinux)
