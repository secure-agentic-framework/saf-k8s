# SAF-K8S-0910-032 cross-cluster telemetry

Run `python3 lab.py test SAF-K8S-0910-032` from the control-lab directory.

The existing case proves an approved client SPIFFE identity sends bounded synthetic JSON over one private route to a separately owned peer collector, which measures actual bytes and record identifiers. An authenticated observer correlates the observed payload digests/count/bytes to the generated count-threshold event. It also proves quiet behavior with monitoring disabled and an ordinary two-record quiet sample after enabling it. The original four-record alert is count-triggered; total bytes are below the byte threshold.

The additive check exercises both endpoints and the second threshold condition:

- A new client with a new SPIFFE URI signed by the same disposable CA is refused with HTTP 403, and the observer sees no stored record or alert.
- The approved source uses a mismatching server name on the same owned route; strict certificate verification must reject it before an HTTP request reaches the collector. Output records only a fixed failure classification. The observer again sees no record/event.
- Two fixed inert records each remain below the 1024-byte per-record cap, while their combined observed bytes exceed the configured 1024-byte alert threshold. The record count remains at two, below the count threshold of three, so a correlated alert demonstrates the byte condition independently.

The four checks cover the original comparisons and the grouped endpoint and byte-threshold comparison. All certificate identities, traffic, and API resources belong to the disposable test fixture. No external endpoints or actual workload telemetry are involved.

The evidence supports a narrow reference mechanism. Adopters still need to inventory and monitor their real source/destination routes, set representative volume and timing thresholds, validate dashboard coverage, route alerts over an authenticated path to assigned roles, and exercise operational response.
