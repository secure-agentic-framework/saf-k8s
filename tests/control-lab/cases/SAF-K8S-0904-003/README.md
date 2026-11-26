# Verify notebook workspace isolation and authenticated Hub spawning

    python3 tests/control-lab/lab.py test SAF-K8S-0904-003 --docker-context desktop-linux

Two case workspaces use distinct Kubernetes identities and non-root UIDs.
The fixture compares same-workspace and cross-workspace reachability before
and after network policy, verifies the approved image admission decision,
and runs a fixed cell in each local Jupyter kernel.

A pinned Zero to JupyterHub 4.4.5 release runs inside the same disposable
cluster. Its internal proxy handles a single allowed synthetic username
with a temporary fixture credential. The wrong password returns the native
login refusal and creates no notebook. A successful login reaches the
notebook route and the API reports one ready KubeSpawner Pod using the
expected username, image and dedicated ServiceAccount.

For adopter verification, check each actual authenticator and spawn profile,
user-to-workload mapping, individual access and shared-account policy,
workspace storage, egress, delegated authorizers, extensions, audit
coverage, and session termination. The fixture uses an internal HTTP
route and a case-only authentication policy. Production identities,
storage and trust requirements follow the adopted profile.

The vendored chart checksum and image pins are in vendor/pins.json.
The chart license is included with the archive.

- [Zero to JupyterHub 4.4.5](https://github.com/jupyterhub/zero-to-jupyterhub-k8s/releases/tag/4.4.5)
- [JupyterHub 5.5.5 authentication](https://jupyterhub.readthedocs.io/en/5.5.5/reference/authenticators.html)

## Distinct Hub user workspaces

Two case-owned usernames sign in through separate browser-style cookie jars.
Each accesses its own harmless marker through the Jupyter Contents API. The
harness binds each response to a distinct spawned Pod and compares both
reciprocal cross-user read decisions. The local authenticator uses one
temporary shared fixture password. For deployment, verify actual identity
provider enrollment and credential assurance separately from workspace access.
