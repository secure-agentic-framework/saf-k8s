# SAF-K8S-0504-009 API request contract validation

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0504-009 --docker-context desktop-linux
```

This test uses a pinned Apache APISIX 3.21.0 standalone data plane with an internal Service. The only target is a case-owned marker backend. The method, path and header route checks are enabled throughout. Installing the real APISIX request-validation plugin causes three well-formed JSON contract violations to return the exact configured HTTP 422 without reaching the backend. A valid JSON request with reordered fields and whitespace still reaches it.

The file-backed configuration disables the administration endpoint and uses no etcd, external route, or test credentials. Deployed evidence should identify the actual gateway, schema source, endpoint and media-type coverage, allowed requests, and policy decisions before the backend.

[APISIX request-validation plugin](https://apisix.apache.org/docs/apisix/plugins/request-validation/) and [APISIX standalone deployment](https://apisix.apache.org/docs/apisix/deployment-modes/).

## Adopter verification

Inventory governed routes and enforcement components, schema versions, permitted methods, fields, media types and backend alternatives. Use synthetic test payloads on approved destinations. Compare representative valid and out-of-contract requests including empty or malformed bodies and missing required fields. Independently correlate gateway decisions with backend logs to verify rejected requests stay at the boundary. Review every path to the backend, version and rollback behavior, and any justified protocol exceptions.
