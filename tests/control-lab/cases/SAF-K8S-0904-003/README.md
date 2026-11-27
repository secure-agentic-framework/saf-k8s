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

## Egress on Hub-spawned workspaces

The supplemental check selects the two actual KubeSpawner Pods by their
`hub.jupyter.org/username` labels and retains each Pod UID before and after
policy application. It probes the same two case-owned benign endpoint Pods
from each spawned notebook: both cross-user paths are reachable before the
supplemental policies, then only each user's own endpoint remains reachable
after policy convergence. The check also confirms both authenticated
`/user/<name>/` routes remain ready through the case-owned Hub proxy.

For this pinned chart fixture, the chart's single-user NetworkPolicy is
enabled with broad private and non-private address allowances disabled. Its
generated policy retains the chart's Hub/proxy and kube-system DNS paths; two
additional namespace-local policies allow each synthetic user only to its
matching fixed dataset endpoint. API readback verifies the actual spawned Pod
selection and exact policy peers. The observations apply to the tested
disposable Kind network implementation and these two local endpoints. They do
not establish production egress destinations, external or metadata-service
behavior, backend dataset authorization, or enforcement by a different CNI.


The before-policy comparison uses a temporary allowance for exactly the two
case-owned dataset endpoints and the same two spawned notebook Pods. The runner
removes that allowance before applying and checking the individually scoped
policies. The chart continues to supply the bounded Hub and DNS paths.

## Authenticated terminal-interface configuration

The pinned chart's `singleuser.extraFiles` input mounts one read-only, case-owned
Jupyter Server config file into each spawned user Pod. The supplemental check
reads the actual Pod volume/Secret mapping and performs a fixed read-only file
inspection that emits only a boolean for the expected trait line, the file SHA-256, and
the installed Jupyter Server package version. Through each user's existing
authenticated cookie session it sends GET requests to `/api/status` and
`/api/terminals`, retaining only status codes. The authenticated Contents
marker read remains part of the original workspace check. It never creates a
terminal or calls a terminal shell/WebSocket endpoint.

This verifies the fixture's mounted setting and read-only HTTP behavior for the
pinned singleuser image. It does not claim that hiding a terminal interface
prevents code execution through notebooks, or establish production extension
configuration. The case has no on/off runtime comparator: the controlled
contrast would require a second separately installed Hub release or chart
upgrade changing only `terminals_enabled`, followed by the same two-user
authenticated GETs. It is intentionally not added because that would duplicate
Hub provisioning and disrupt the single pinned egress scenario.
