# Verify CI/CD lifecycle checkpoints on Kind

```sh
python3 lab.py test SAF-K8S-0606-017 --docker-context desktop-linux
```

Develop checks the restricted manifest at the API. Distribute stages the
same digest in an immutable ConfigMap and rejects a changed document. Deploy
uses native admission to reject an unpinned image, then admits the exact staged
workload. The separate Runtime check verifies the Pod identity, readiness and
its public marker after startup.

These are local examples of phase coverage. Verify the actual CI pipeline,
artifact distribution, deployment policy and runtime controls independently.
