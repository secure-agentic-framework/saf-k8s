# SAF-K8S-0606-034 — Emergency access audit and justification

Run from the SAF-K8S framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-034 --docker-context desktop-linux
```

The case uses a separate case-owned Kind v1.36.1 API server with the native audit log
backend and a policy limited to one pre-issued ServiceAccount and two inert
ConfigMaps. No Pod or application workload is created. Both actions are normal
HTTPS API PATCH requests made by the fixture ServiceAccount.

The case gives that ServiceAccount a namespace Role with only `patch` on the
two named ConfigMaps. The short-lived TokenRequest token is issued before either
action. The test captures the API response `Audit-Id`, then independently reads
the case-owned native audit log and requires the event's `auditID` to equal the
response ID. Request-level audit captures the synthetic merge-patch body so the
test can compare the exact operation as well as the actor, verb, namespace,
resource, and name.

The independently owned `incident-approval.json` fixture has a stable approval
ID and action ID. A separate fixture procedure creates an execution receipt
pairing that approval with the observed audit ID. The no-justification request
has no approval or receipt; its join must be false. The approved request must
join the exact event and pass. The same approval fails when linked to the
other audit ID or the other recorded request. Kube-apiserver writes the native
event. The case provides its own external approval, justification, and
execution receipt as procedure fixtures.

## Deterministic replay values

The request names, actor, request body, approval ID, action ID, response status,
event level, event stage, and expected join results are fixed in `fixtures.json`,
`incident-approval.json`, and `audit-policy.yaml`. Kubernetes generates a fresh audit ID for each request;
the case records that value and checks equality between the response header,
native event, and execution receipt rather than hard-coding a generated ID.

| Probe | Expected native event | Expected external join |
| --- | --- | --- |
| `saf-breakglass-no-justification` | `patch`, `Request`, `ResponseComplete`, HTTP 200, fixture ServiceAccount, exact request body | False; no approval or execution receipt |
| `saf-breakglass-approved-action` | `patch`, `Request`, `ResponseComplete`, HTTP 200, same fixture ServiceAccount, exact approved request body | True; `APPROVAL-0606-034-002` joined to `ACTION-0606-034-002` and the exact event audit ID |

Deployed audit configuration, centralized retention, independent reviewer
action, approval-system integrity, GitOps-path classification, and fleet
coverage require separate evidence.

## Verify an adopting implementation

Enumerate emergency identities, API verbs/resources,
audit-policy coverage, console/managed exporter routes, and review owners.
In a controlled exercise, correlate an authorized justified request and a
deliberately unapproved/no-justification request to exact audit IDs and
approvals; verify the independent reviewer can inspect the protected record.
Test exporter loss, delivery recovery, retention/immutability, access controls,
and post-use review across all emergency roles.
