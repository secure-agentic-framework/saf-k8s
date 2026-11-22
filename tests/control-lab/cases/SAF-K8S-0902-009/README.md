# SAF-K8S-0902-009 — Synthetic response filtering and output cap

The case uses one checked-in fixture, a local source Pod, a response-filter Pod
behind a stable ClusterIP Service, and a separate client Pod. The source returns
fixed bytes for `/fixture`, `/intended`, `/at-cap`, and `/over-cap`; it does not run a model,
read prompts, use external data, or log response contents. The client calls the
same Service before and after the filter setting changes.

The red comparator has the filter disabled: the independent client must receive
the exact fixture response, including its explicitly synthetic private dummy
marker, and the fixture's 97-byte body. Green enables an exact-string rule for
only the fixture-designated dummy marker and caps forwarded response bodies at
exactly 96 UTF-8 bytes. The public marker must remain byte-for-byte unchanged,
the dummy marker must be replaced, a 96-byte response must pass unchanged, and
the 97-byte response must receive a bounded HTTP 413 response. A separate
intended output must still return exactly.
The filter returns a fixed denial body when the cap is exceeded; it does not
truncate output.

## Run and evidence

From the control-lab root, the supervisor can execute the case on the harness's
fresh disposable Kind cluster:

```sh
python3 lab.py test SAF-K8S-0902-009 --docker-context desktop-linux
```

The case expects Kind v0.32.0 and verifies the API server reports Kubernetes
v1.36.1. The node and all workload images are digest pinned. The author did not
run Docker, Kind, or kubectl. The supervisor should retain the harness results
for both comparator and enforced checks. The case writes
`response-filter-observations.raw.json` and
`response-filter-workloads.raw.json` in the evidence directory. They contain
only synthetic fixture bytes, bounded client observations, and case-owned
Kubernetes objects; no Secret objects or credentials are read.

## Coverage boundary

This is a case-owned HTTP proxy demonstration for one nonstreaming mock
response. It establishes that this local rule changes the exact response
observed by an independent in-cluster client and enforces its small byte cap.
It does not establish deployment coverage for every inference route or replica,
HTTP/gRPC frameworks, batch jobs, streaming channels, confidence precision,
PII or proprietary-data detection, memorization/extraction detection, model
alignment, or production response middleware. The control's rationale and
implementation claims for those paths remain unverified by this case. The
control record does not cite implementation-level evidence for those claims;
they remain source assertions requiring separate validation.

## Official primary references

- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — identifies the Kubernetes v1.36.1 node image and its digest.
- [Kubernetes ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/) — describes non-confidential configuration mounted into Pods; this case stores only synthetic code and fixtures there.
- [Kubernetes Services](https://kubernetes.io/docs/concepts/services-networking/service/) — documents stable in-cluster Service endpoints used by the independent client.
- [Python 3.13 `http.server`](https://docs.python.org/3.13/library/http.server.html) and [`urllib.request`](https://docs.python.org/3.13/library/urllib.request.html) — standard-library HTTP fixture primitives.
- [Docker Official Images source for Python](https://github.com/docker-library/official-images/blob/master/library/python) — metadata source for the digest-pinned official Python image.

The control maps to NIST SP 800-53 SI-15 in `control.md`; this small case does
not assert that the mapping or the broader control rationale has been
independently validated.
