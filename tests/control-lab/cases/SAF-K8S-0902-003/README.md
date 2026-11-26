# SAF-K8S-0902-003 — Inference request validation boundaries

Run from the framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0902-003 --docker-context desktop-linux
```

From the lab checkout, invoke `python3 lab.py` with the same arguments.
An owned mock gateway and serving process validate the configured JSON
schema and the 128-byte limit. The case uses fixed benign requests,
an independent backend counter and an exact allowed marker. In the
gateway-only comparison, the deployed gateway check is on and the model
check is off. Each invalid fixture receives its expected refusal and
the independent backend counter remains unchanged. The separate direct
model path compares the model's own enabled validation.

## Verify each actual request path

1. Inventory authorized gateways, direct serving paths and deployed
   protocols, including gRPC, streaming or batch where applicable.
   Record ownership, expected identities, request format, schema, byte
   or message bounds, refusal semantics and model dispatch evidence.
2. In approved staging, compare normal, boundary and rejected fixed
   benign inputs for each route. Verify the actual gateway and server
   separately. Record authenticated routing, exact refusal and independent
   backend readback for decisions made before dispatch.
3. Where a streaming or batch path exists, check the applicable
   per-message or aggregate bounds and behavior when a governed input
   is refused. Keep protocol-specific receipts attached to its route.
4. Validate any applicable application preprocessing or model input
   safety requirement separately with approved evaluation data and an
   accountable application owner. Retain policy versions and evidence
   for changes to gateways, routing or model serving.

[NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
