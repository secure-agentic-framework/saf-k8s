# Verify digest-linked lineage for an imported model

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0905-059 --docker-context desktop-linux
```

The baseline publishes a fixed JSON model marker without lineage. A separate
scanner Job reads the marker from a fixture source, validates its JSON shape,
and reports the exact byte digest. Intake accepts that receipt only for the
bytes it publishes. A read-only observer independently reads the approved
OCI manifest, model layer, referrers index and attached lineage. The case
also reads the approved publication back after replacing the registry Pod.

For an actual import, preserve the authenticated external origin, independent
scanner identity and version, policy and results, approver decision, and
authoritative timestamp. Bind those records to the accepted artifact digest.
Verify the registry's write permissions and longer-term retention for each
required model format. The fixture uses a local source, synthetic approval
and timestamp, and a disposable registry.
