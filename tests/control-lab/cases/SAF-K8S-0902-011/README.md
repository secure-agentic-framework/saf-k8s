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
