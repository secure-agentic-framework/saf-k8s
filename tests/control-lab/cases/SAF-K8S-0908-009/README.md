# SAF-K8S-0908-009 Approved differential privacy parameters

Run by ID on fresh Kind. Native admission accepts only the reviewed
scope and parameters for one exact binary randomized-response mechanism.
The running pod reads the approved record, enumerates its finite
distributions and serves a bit from fresh secure randomness.

For neighboring one-bit inputs, bit replacement changes the
probability of either output from 1/4 to 3/4 or vice versa. That gives a pure
local differential privacy bound of epsilon = ln(3), delta = 0 for one
release in this case. Deployment evidence must establish the actual
mechanism, privacy unit, protected scope, implementation, and utility.
Verify cumulative spend separately under SAF-K8S-0908-010.

The case reuses the pinned runtime loader in SAF-K8S-0908-001.

- [NIST SP 800-226](https://csrc.nist.gov/pubs/sp/800/226/final)
- [Kubernetes Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

## Local input and collector boundary

A separate client Pod mounts an invented input bit and applies the same
approved mechanism before sending the noisy result to an isolated test
collector. An independent scope check compares actual Pod volume mounts.
The collector's native identity is forbidden from reading the input
ConfigMap. A fixed request with an extra field is rejected and leaves the
result record blank. The accepted request produces exactly one persisted
output field, observed separately.

The case uses one replacement bit, one release and the specified uniform draws
for its finite bound. The fixture control plane still has access to the input.
For adoption, verify the real privacy unit and neighboring relation, approved
utility measures for the actual use, mechanism and implementation provenance,
data path and recipient trust, retention, side channels and cumulative release
scope.
