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
