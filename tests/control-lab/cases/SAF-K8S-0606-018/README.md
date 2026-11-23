# Verify a Kubernetes CI handoff with separate evidence

```sh
python3 lab.py test SAF-K8S-0606-018 --docker-context desktop-linux
```

Two Jobs use their own projected Kubernetes identities. RBAC permits the
builder to write only the artifact and the observer to read it and write the
signed evidence. Only the observer receives the temporary fixture signing key.
The receiver verifies the observer's enrolled public key, identity and exact
marker digest before publishing a ConfigMap as a fixture release receipt.

The demonstration uses a public marker and a disposable signing key. The
actual CI issuers, evidence infrastructure, credential custody, stage coverage
and release deployment must be verified in their operating environment.
