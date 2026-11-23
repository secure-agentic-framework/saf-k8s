# SAF-K8S-0704-016 Effective entitlement reconciliation

The expected approved group represents an inert external entitlement. The live Kubernetes API initially confirms a stale RoleBinding grants its previous group access to one owned ConfigMap while the approved group is denied. Reconciling the one owned binding changes both effective outcomes. A separate binding remains effective and its object stays outside the remediated grant.

This demonstrates cluster-side authorization reconciliation and authorized rechecks. The expected provider entitlement, review cadence and operational change inputs need evidence from the deployed environment.
