# SAF-K8S-0904-016 — MLflow experiment access and modification audit

## What this fixture checks

This case runs an official MLflow 3.5.1 tracking server against its SQLite
backend-store and sends real Tracking REST API requests through an authenticated,
strictly allowlisted audit bridge. The server binds to `127.0.0.1` inside the
same Pod as the bridge. The Kubernetes Service selects only the bridge container's
port, so the client fixture has no Service path to the tracking API itself.

The bridge maps three fixture-only Basic-auth identities to fixed operations:

| Actor | Operation | MLflow request |
| --- | --- | --- |
| `lab-admin` | administrative | Create the fixed experiment |
| `lab-reader` | read | Get the fixed experiment |
| `lab-writer` | write | Create a run and log a parameter |
| `lab-writer` | delete | Delete that run |

The five-operation sequence runs first with persistence off and then with it on.
The red assertion requires every fixed MLflow call to succeed while no audit row
is persisted. The green assertion requires the same normalized dispatch and
success results plus five persisted rows with the expected actor, operation,
resource ID, and result. A separate positive read proves permitted access still
works and adds a sixth persisted row. Rows are append-only JSONL on a case-owned
`emptyDir`; the fixture checks the mounted file after the requests. The bridge
does not log authorization headers, credentials, request bodies, or secret
values. Dynamic experiment and run IDs are retained in
`mlflow-audit.raw.json`; result assertions compare stable shapes across fresh
clusters.

The bridge is intentionally not a general proxy. It accepts a small fixed
request schema, maps actors to exact operation names, constructs exact MLflow
REST calls itself, and rejects other paths or operations. Its audit sink only
appends event rows. These static credentials are lab-only fixtures, not a
production identity design.

## Source-backed scope

MLflow 3.5.1's official Tracking Server interface and server handlers expose
the actual experiment and run endpoints used here. The versioned MLflow
security documentation describes Basic HTTP authentication as an optional
server app and recommends a reverse proxy or VPN for production authentication
and TLS. The versioned security middleware covers host validation, CORS,
clickjacking, and related network protections. In the reviewed documentation
and tracking handlers, I found no MLflow-native event facility that records
authenticated actors, resource IDs, outcomes, and successful read, write,
delete, and administrative operations comprehensively. This is a bounded source
review, not proof that every third-party plugin lacks audit features.

For deployments using MLflow without such a native facility, the control must
require a trusted authenticated gateway or equivalent audited component, with
direct access to the tracking API closed. This fixture shows that integration
pattern against fixed local requests. It does not validate production SSO,
gateway bypass resistance across the complete network, authorization policy,
artifact access, durable remote export, retention, integrity monitoring, or
administrative changes to audit configuration.

## Run and evidence

The lab runner uses a fresh Kind v1.36.1 cluster and creates `saf-test` before
calling the case. Every fixture object names `namespace: saf-test` explicitly.
The backend, bridge, and client use the authenticated official image reference:

```text
ghcr.io/mlflow/mlflow:v3.5.1@sha256:7a8c21cd553b84227391ad7daa39c029dab64328da7607c372370cfa07ef43d9
```

Run through the lab harness after staging this artifact under
`tests/control-lab/cases/SAF-K8S-0904-016/`:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0904-016 --docker-context desktop-linux
```

The supervisor requested independent validation and two fresh clusters. Neither
was run while preparing this artifact. A successful harness run should record
the `red`, `green`, and `positive` checks, the pinned Kind node image, the
MLflow image reference, and cluster cleanup in its ordinary result evidence.
