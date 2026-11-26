# Verify scoped model registry alerting and receiver authentication

    python3 tests/control-lab/lab.py test SAF-K8S-0905-041 --docker-context desktop-linux

The monitor applies fixed rules to normalized fixture events, compares
the resulting alerts with near misses, and preserves the same alert set
on replay. Kubernetes authorization separates the selected analyst
disposition from ordinary workload access.

An authenticated Zot publish contributes one actual native audit record.
The monitor routes its alert to a case-owned HTTPS receiver using enrolled
fixture credentials and certificate trust. A request with wrong credentials
is rejected without changing receiver state. An independent read observes
delivery of the authorized alert once after replay.

For an adopter, enroll the actual registry and receiver identities and
verify the authorized publication, matching event and sensitive-operation
rules. Record access to the review queue, recipient and acknowledgement,
response ownership, error and retry behavior, and retention across the
deployed provider and registry paths.

## Projected analyst acknowledgement reference

The eighth check follows the actual Zot-derived alert
already read back from the authenticated receiver. It creates a separate
case-owned review ConfigMap keyed to that alert ID, then uses two Kubernetes
ServiceAccounts with projected API tokens: an observer with `get` only and an
analyst with `get`/`patch` only on that named ConfigMap. The observer's patch
is denied and the record remains unchanged; the analyst records a fixture
disposition; a fresh observer Pod independently reads the exact alert and
disposition back through the API. Token bytes are used only as bearer
credentials to the API server and are not emitted or retained.

The fixture demonstrates scoped API authorization and persisted review.
Verify human review, retention, coverage and incident handling on the deployed
route. For deployment evidence, trace one real
registry event ID through source capture, alert delivery, the assigned
reviewer's authenticated acknowledgement, a separately authorized readback,
and the retention policy. Preserve the event-to-review ID join and timestamps;
record reviewer and outcome under the organization's access and retention
controls.
