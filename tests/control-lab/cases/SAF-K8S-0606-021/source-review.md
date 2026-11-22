# SAF-K8S-0606-021 source review

The control at catalog revision 133a8698a45e2b335b51728bf4c62f7bda98d15f
requires CI to sign the deployment manifest before promotion. This case signs
and verifies the exact Kubernetes manifest bytes with OpenSSL 3.3.2, checks
the distinct signer public keys independently, and promotes the exact
verified bytes as a harmless ConfigMap.
[OpenSSL dgst](https://docs.openssl.org/3.3/man1/openssl-dgst/)

Kubernetes runs the signature check as an init container in each promotion
Job. Three negative arms verify the expected signature failure and absence of
the ConfigMap. In the positive arm, the application container retrieves its
own authenticated username and sends the verified artifact through the normal
API. The API credential is mounted solely in that container.
[Init containers](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/init-containers/)

Production signer registration and protection, trust-policy approval,
repository custody, deployment coverage and exemptions remain separately
verifiable.
