# SAF-K8S-0303-006 AppArmor profile refinement

Run `python3 lab.py test SAF-K8S-0303-006` with the catalog revision recorded in
the verified result. This case requires the local `openssl` command. A
restricted Kind Job starts a pinned disconnected Linux guest. AppArmor loads,
profile mode, audit events and allowed or denied file operations are observed
inside that guest.

Two ordinary cycles miss an unexercised recovery path. The excluded canary
calibrates the audit channel. The recovery path is then observed in complain
mode and denied in enforce mode. A synthetic reviewer signs the exact prior
and candidate profile digests and the path inventory. The runner verifies the
signature using the reviewed public key pin and sends the approved digest to
the guest in an immutable ConfigMap. The fixture includes public evidence only.

The guest rejects a changed candidate without replacing the active profile.
The exact approved revision permits the intended workloads and still denies
the excluded canary. Rolling back restores the original enforcement behavior.
A new workload path generates a policy event and must still be denied after
the controlled return to enforcement.

## Adopter checks

Inventory applicable normal, dependency, failure and recovery operations for
each governed workload and platform. Calibrate the event collection path
using an expected audit event, then verify actual allow/deny outcomes with the
candidate in enforce mode. Record intended behavior, observed path coverage,
effective profile and version, and event capture gaps. Bind approvals to exact
profile and test evidence using a reviewer identity controlled separately
from applicants. Test that an altered candidate is rejected and that a return
to the prior approved bytes restores the expected behavior. Trigger another
review when material workload or platform assumptions change. Repeat this
verification on the actual supported node and runtime when adopting the
control.

- [Linux kernel AppArmor documentation](https://docs.kernel.org/admin-guide/LSM/apparmor.html)
- [AppArmor policy reference](https://apparmor.dev/man/apparmor.d/)
- [OpenSSL signature verification](https://docs.openssl.org/3.5/man1/openssl-dgst/)
