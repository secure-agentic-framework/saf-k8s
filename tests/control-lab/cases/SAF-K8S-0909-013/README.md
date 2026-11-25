# SAF-K8S-0909-013

Run `python3 tests/control-lab/lab.py test SAF-K8S-0909-013` from the repository root. Two local HTTPS repositories accept distinct fixture credentials. With admission disabled the fixed unregistered source reaches both consumers. The enabled registry rejects the same source before a fetch or any persisted change. The authorized approved source delivers its expected bytes to both stores. Verify production repository and publisher identities, path scope, source credential lifecycle, routing and alternate ingestion paths independently.

## Verify an adopting implementation

Inventory all source repositories, credentials, protocols and ingestion
routes. Verify the actual admission/registry decision blocks unapproved
sources before fetching or persistence, while approved publisher identity
and exact bytes succeed across each destination. The case uses two local
HTTPS repositories with fixed credentials and inert bytes, not real
repository identity or secret rotation.
