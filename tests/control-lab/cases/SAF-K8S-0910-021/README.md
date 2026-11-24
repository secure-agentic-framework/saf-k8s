# SAF-K8S-0910-021 cross-cluster endpoint and workload identity

Run `python3 lab.py test SAF-K8S-0910-021` from the control-lab directory.
Each arm starts two separately owned Kind clusters and uses a dynamic NodePort
on the verified test bridge. The approved and alternate callers each mount
only their own disposable certificate. Another caller has no certificate.

The baseline accepts the alternate certificate from the trusted fixture CA.
The governed service checks the actual caller URI as well. The client checks
the exact destination DNS name. The gateway logs the approved identity from
its verified peer certificate. This test uses case-issued certificates and
does not validate SPIRE, workload attestation or production trust federation.
