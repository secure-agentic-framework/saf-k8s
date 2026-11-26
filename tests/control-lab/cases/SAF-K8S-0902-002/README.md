# SAF-K8S-0902-002 — Model startup and runtime integrity

Run from the framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0902-002 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
A mismatched startup digest prevents the serving process from starting.
The approved digest starts it, and Kubernetes shows the serving mount
is read-only. An independent reader verifies the expected bytes.

A separate read-only consumer observes the expected file on an owned
PVC. The mounted consumer cannot open the file for writing. Once a
separate approved fixture writer makes an atomic change to the one
inert marker, the already-running monitor reports the expected and
observed digests. The case uses a disposable local-path volume and a
fixed synthetic artifact.

## Verify the adopted serving path

1. Inventory actual model versions, artifact and cache endpoints,
   the independent authority for approved digests or trusted signing
   identities, and the governed path from retrieval to runtime.
2. Compare an approved artifact and an approved test mismatch at
   startup. Independently verify that only the approved bytes are
   served. Repeat across each applicable startup, reload, replica and
   cache refresh path.
3. Verify effective serving mounts and actual writer identities.
   Compare a failed serving-side write with a separately authorized
   isolated change. Observe runtime detection of the exact governed
   file and delivery to the actual monitoring and response path.
4. Compare the adopted response, including alerting, serving withdrawal
   or approved recovery where required. Retain source digest or
   signature, effective identity, decision evidence and restored
   artifact identity.

[Kubernetes volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/volumes/),
[Kubernetes persistent volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/),
and [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
