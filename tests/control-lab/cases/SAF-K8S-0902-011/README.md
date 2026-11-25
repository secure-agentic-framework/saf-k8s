# SAF-K8S-0902-011 — Streaming response marker filtering

Run `python3 lab.py test SAF-K8S-0902-011 --docker-context desktop-linux`.
An independent loopback client reads a prefix from an HTTP/1.1 chunked
response before allowing the server to release the remaining fixed chunks.
The same benign input is used twice. The disabled filter exposes the dummy
marker. The enabled filter keeps the dummy marker from the client even
though it spans source chunks, preserves the public marker, and returns
the exact same response with one replacement. The fixture bounds input
and retains client observations without collecting real content.

The evidence covers this exact synthetic marker and transport. Production
protocols, response stacks, classifiers, privacy classes, and operational
policies require separate evidence.

- [HTTP/1.1 chunked transfer coding](https://www.rfc-editor.org/rfc/rfc9112.html#name-chunked-transfer-coding)

## Verify an adopting implementation

Enumerate every deployed streaming protocol and response path. At the actual trusted egress filter, test a benign allowed response and policy marker split across transport chunks, and compare with the filter disabled in an isolated nonproduction environment. Record false-positive/negative handling, buffering/latency limits, fail-open/closed behavior, and alert/escalation ownership. The fixture tests one synthetic marker over HTTP/1.1 chunking. It does not validate classifiers or production policy.
