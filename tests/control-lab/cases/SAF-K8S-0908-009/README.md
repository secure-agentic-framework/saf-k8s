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
