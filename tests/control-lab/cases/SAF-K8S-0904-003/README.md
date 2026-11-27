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

## Inert Jupyter Server extension policy comparison

The same two authenticated Hub-spawned workspaces expose a fixed comparison
through their ordinary user routes. Alice is the case-only baseline: the
mounted `ServerApp.jpserver_extensions` config enables both case-owned inert
modules. Bob uses the policy configuration that enables only
`saf_approved_extension`; the same harmless `saf_unapproved_extension` module
is present but explicitly disabled. Authenticated GETs require the approved
marker route on both users, the second marker route on baseline Alice, and a
404 for that route on restricted Bob. The check binds the result to the same
Ready Pod UIDs, the mounted config and module SHA-256 values, and
Jupyter Server 2.21.1. The modules return only fixed fixture JSON and do not
read workspace data or perform other actions.

This demonstrates the pinned server's configured extension enable/disable
behavior for two inert fixture modules. It does not prove a reviewer approved
an extension, package provenance or signature verification, prevent users
from installing code outside the tested image/configuration, establish
production extension settings, or provide durable data-access auditing.

## Authenticated contents audit

The pinned asynchronous ContentsManager logs operations for the owned marker
path on each user server. Saving a marker produces an internal metadata get
followed by a save event. Two explicit authenticated reads then return the
expected fixed marker, yielding two further get events. The test requires
this order and independently reads the filtered event fields from each
matching Ready user Pod. Evidence binds the events to each Pod UID and Hub
identity and retains only the action, fixed path and schema and time fields.

The existing workspace test separately verifies cross-user denials. The
ContentsManager reports successful operations. Verify request actor
attribution, denial instrumentation, durability, integrity and retention in
the adopted logging pipeline.

[Jupyter Server 2.21.1 ContentsManager](https://github.com/jupyter-server/jupyter_server/blob/v2.21.1/jupyter_server/services/contents/filemanager.py) · [Jupyter Events handlers](https://jupyter-events.readthedocs.io/en/latest/user_guide/configure.html)

## Listener-side egress arrival evidence

The two fixed dataset listeners retain a bounded in-memory aggregate of
successful GET / arrivals: canonical source Pod IP, request count, HTTP 200
count and bytes written for the fixed marker response. The listeners do not
read request bodies, capture headers, retain paths with queries, or emit
request logs. Counts are capped at 256 requests and 16 distinct peers per
listener. On overflow, the listener keeps serving the same fixed response but
marks its evidence incomplete; the added check fails closed.

After the existing egress policy matrix, the case samples each listener
through a /__audit route that only answers loopback callers from a
kubectl exec inside that listener Pod. It brackets one additional own-route
request and the two blocked cross-user requests with snapshots. Kubernetes
readbacks bind both source and destination UIDs and Pod IPs before and after
the probes. The check expects one own-user arrival with the exact fixed
response byte count at each destination and no added arrival from the
cross-user source.

This proves the observed peer IP matched the exact source Pod IP for these
controlled Kind requests. It depends on this cluster network path preserving
the source Pod IP; a translated address fails the exact comparison. It does
not establish external route attribution, production logging or durable audit.
