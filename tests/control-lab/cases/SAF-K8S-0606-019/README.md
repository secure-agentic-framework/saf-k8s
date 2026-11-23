# Verify Helm chart package provenance

```sh
python3 lab.py test SAF-K8S-0606-019 --docker-context desktop-linux
```

This case needs `helm`, `gpg`, and `gpgconf`. It creates isolated, expiring
fixture keys and charts that install only an inert ConfigMap. Native Helm
verification accepts the exact package signed by the approved key. Missing provenance, different package bytes, and a distinct valid
fixture signer are rejected before release creation. The comparison installs the harmless
changed package without verification.

This demonstrates native Helm `.prov` checks on an owned local archive.
Registry trust, OCI verification, organizational keys and GitOps
reconciliation require independent evidence for the deployed tool and path.
