# SAF-K8S-0908-010

From the control-lab runner directory, run `python3 lab.py test SAF-K8S-0908-010`. Use an owned local Kind cluster with dynamic local volume provisioning. Separate baseline and governed Pods each use a persistent volume claim.

Both fixtures use the binary randomized-response mechanism from `SAF-K8S-0908-009`. The ledger charges one exact ln(3) unit with delta zero per fresh release for the replace-one-bit relation. An SQLite immediate transaction checks spend and commits both charge and result before responding. The baseline permits three releases against the declared two-unit threshold. The governed fixture permits two calls from differently labeled clients, retains spend across Pod recreation, and refuses the third without an extra charge or persisted sample. A distinct synthetic scope receives its own binary release. Evidence contains counts and decisions and omits sampled bit values.

The fixture covers a single node and one reviewed mechanism. Independently verify protected population and composition assumptions, trusted scope assignment, authentication, multiple release mechanisms, and durable accounting across replicas for production.

[NIST SP 800-226](https://csrc.nist.gov/pubs/sp/800/226/final)

## Verify an adopting implementation

Identify the actual privacy population, contribution bound, composition
relation, mechanism, unit and trusted scope. Confirm a persisted privacy
ledger charges before release, survives restart, isolates scopes, and
refuses a release beyond threshold without storing the sample. Assess
replica/concurrency behavior. The fixture tests one binary randomized-
response mechanism and an SQLite PVC ledger. It does not prove deployed
statistical privacy guarantees or population authority.
