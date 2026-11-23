# Verify external-service policy boundaries on Kind

```sh
python3 lab.py test SAF-K8S-0704-005 --docker-context desktop-linux
```

Two case-owned endpoints serve inert markers. Kubernetes admission recognizes
only the allowed service declaration for each fixture namespace. NetworkPolicy
independently limits actual connections to the approved endpoint and blocks
both endpoints from the restricted namespace.

The case uses invented policy decisions and in-cluster addresses. External
provider approvals, data handling, credential governance, and deployed egress
and monitoring require their own evidence.
