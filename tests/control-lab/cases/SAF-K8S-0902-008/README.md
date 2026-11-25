# SAF-K8S-0902-008 inference endpoint authentication and authorization

Run from the framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0902-008 --docker-context desktop-linux
```

A disposable Kubernetes gateway serves two inert model endpoints. The same
fixed routes receive an open baseline and a governed comparison using a
case-generated synthetic signing key. The test rejects absent and expired
credentials, unapproved issuer and audience, unapproved algorithm declaration,
an unregistered subject, a changed signature, and a non-integer expiry claim.
The gateway denies access to another model for an otherwise authorized
principal. The approved principals can each reach their own model.

Gateway and backend logs independently agree on which requests were dispatched.
The retained results contain synthetic event IDs and redacted decisions. Each
model returns only the fixed fixture marker. The case uses one private local
HTTP topology and a synthetic trust policy.

## Verify an adopting implementation

1. Inventory every inference listener, gateway and direct backend route.
   Record which control enforces identity, authorized models and operations.
2. Record each approved token issuer, audience, algorithm, trust root and
   key source, token field schema and expiry rules, and how credentials are
   renewed or revoked. Verify trusted TLS and protected alternate paths.
3. Exercise each documented negative token class and a true authorized model
   request. Confirm the backend receives only permitted requests and the
   identity and client grant match the intended model and action.
4. Retain scoped decision records, effective config, ownership and review
   cadence. Keep real credential material outside evidence records.
