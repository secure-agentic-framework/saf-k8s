# Verify changes to authorization-relevant Kubernetes identity metadata

    python3 tests/control-lab/lab.py test SAF-K8S-0402-004 --docker-context desktop-linux

The case records an ungoverned metadata write, then checks the approved
registry, scoped registrar RBAC and native admission policy. It observes
approved and refused changes for one ServiceAccount annotation and one
namespace label, verifies readback and the unaffected namespace, and checks
the scoped audit records for the fixture updates.

For a deployment, inventory the exact attributes and the consumers that
trust them. Record enrolled registrars, admission scope, registry
authorizations and observed writes. Verify the actual provider trust
binding or policy selector and the resulting authorization separately.
For projected-token audience issuance and verification, see
SAF-K8S-0402-020.
