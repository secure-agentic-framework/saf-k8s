# SAF-K8S-0205-008 Service proxy mode selection

The Kind profile selects nftables kube-proxy. The case checks the component configuration and runtime log, reads the dedicated kernel table for its exact owned ClusterIP tuple, and proves that the Service selects and replaces a harmless backend. A conflicting fixture decision and an empty Service fail their comparisons.

This covers a Linux IPv4 ClusterIP fixture. Production approval, other platform modes, provider constraints and benchmark conclusions require separate evidence.

```sh
python3 lab.py test SAF-K8S-0205-008 --docker-context desktop-linux
```
