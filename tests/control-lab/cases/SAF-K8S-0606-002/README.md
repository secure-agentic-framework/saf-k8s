# Verify an isolated ephemeral CI runner

```sh
python3 lab.py test SAF-K8S-0606-002 --docker-context desktop-linux
```

Two disposable Jobs build a tar archive from a public fixture marker. The case
checks Kubernetes Restricted admission, scoped projected API access, observed
egress to owned feeds, automatic Job and Pod cleanup, and fresh scratch storage
across identities. The test records rights and results without recording the
projected token.

Production host cleanup, build-tool execution, external secret services,
signing separation and managed runner semantics need separate evidence.
