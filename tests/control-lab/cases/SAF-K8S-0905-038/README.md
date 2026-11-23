# SAF-K8S-0905-038 — Scope pull and publication permissions

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-038 --docker-context desktop-linux` from the framework checkout. The runner host needs `htpasswd`.

A baseline and a scoped Zot registry receive matching requests from the same fixture identities. A running inference client pulls a digest-checked manifest from the approved repository. With repository scoping enabled it cannot read the training repository or publish to the serving repository. A separate publisher can create training tags and receives denials for update and deletion. The steward can update and delete the training manifest, with digest and deletion readback.

The inference Pod uses an explicit Kubernetes ServiceAccount with token automount disabled and a distinct registry credential mounted from its own Secret. The fixture covers Zot native repository authorization. Verify OIDC or IAM federation, human account governance, all environment boundaries, credential rotation and production registry integrations separately.

- [Zot 2.1.23 authentication and authorization](https://zotregistry.dev/v2.1.23/articles/authn-authz/)
- [OCI Distribution Specification v1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
