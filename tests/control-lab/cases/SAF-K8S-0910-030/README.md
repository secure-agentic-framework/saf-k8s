# SAF-K8S-0910-030 mTLS verification for registry replication

Run from the framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0910-030 --docker-context desktop-linux
```

The fixture reads a deterministic OCI manifest and blob in its source Kind
cluster. An exact receiver in a second disposable Kind cluster accepts the
approved replication connection only after verifying the source certificate
and expected service URI. The source verifies the receiver's DNS identity
and chain. A separate observer confirms the exact manifest and blob digest
at the destination.

The comparisons cover a baseline that trusts a different source identity
from the same CA, rejection of that identity under the intended policy,
rejection of an absent client certificate or wrong receiver name, and an
approved transfer. The fixture uses a synthetic issuer, one private bridge
and no deployed registry credentials.

## Verify an adopting implementation

1. Inventory each source and destination registry, replication route,
   termination point, exact client URI and receiver DNS identity, and issuer
   or trust domain. Verify each required hop is protected.
2. Exercise an approved replication and independently read back the
   destination digest. Compare missing, untrusted or wrong-source identity
   and a receiver identity mismatch in an approved staging environment.
3. Record replication authority separately from peer authentication.
   Inspect certificate issuance, trust distribution, permitted TLS settings,
   rotation, revocation, and alerts. Correlate each receipt to its approved
   replication job, artifact and exact route.

[NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
