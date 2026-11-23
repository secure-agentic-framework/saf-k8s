# SAF-K8S-0602-006 — Image signature verification fails closed

Run `python3 lab.py test SAF-K8S-0602-006` from the control lab. The test uses
the owned OCI registry and pinned Kyverno installation shared with
SAF-K8S-0605-002 and SAF-K8S-1006-005.

The same unsigned immutable image is initially admitted by a server-side dry
run, then denied after enforcing signature verification in the test namespace.
A valid signature from the ephemeral client key permits a separate digest.

The test then stops only the owned registry container and redirects its Service to a closed
port on the test node for immediate connection refusal. The reachable
verifier must report a retrieval failure and deny a previously unseen signed
digest. The same digest must pass after restarting the registry. Block the API server's network path to the owned admission webhook without
removing the webhook registration. The API must reject
another previously unseen signed digest when the matching mutating webhook
call fails first. Verify both registered hooks use `Fail`.
Restore transport and verify that digest and a fresh signed digest pass.

Admission scope, cache behavior, all container classes, pre-existing workloads
and deployed signer trust require separate evidence.
