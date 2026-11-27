# SAF-K8S-0909-005

Run `python3 tests/control-lab/lab.py test SAF-K8S-0909-005` from the repository root. The same fixed benign note travels through two application paths. The baseline serializes the note into an authority-bearing message; the governed path checks its source, version, shape and digest and sends the approved record separately from fixed application messages. A separate consumer observes the roles and returns the expected benign response. Changed content, unknown source and extra metadata are rejected without reaching the consumer.

This case exercises application request assembly with a deterministic fixture. Verify the deployed model behavior, actual output and tool authorization, and monitoring independently.

The separate action check uses native Kubernetes RBAC and each Pod's projected
ServiceAccount credential. The ordinary subject can read the exact pending
record and receives HTTP 403 for the same fixed update. The scoped action
subject updates that record and receives HTTP 403 for the alternate record.
An independent API read confirms the approved UID and state and the unchanged
alternate UID and state. The role scopes access by ConfigMap name. The test
uses a fixed update to ConfigMap data. The observation file contains named
fixture objects, test results and identities. Credentials stay within the
requesting processes.
