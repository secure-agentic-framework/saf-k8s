# SAF-K8S-0704-017 local demonstration

This case adds two narrow RBAC grants to one synthetic identity and proves that the live authorizer returns the union. Removing the unexpected grant leaves the approved marker accessible and restores the reviewed boundary. Authorization reviews for other operations never perform those operations. The case uses no provider permissions or cloud credentials.
