# SAF-K8S-0503-013 WAF request filtering

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0503-013 --docker-context desktop-linux
```

The test runs a pinned ModSecurity and OWASP CRS reverse proxy in front of a case-owned HTTP backend. It sends one fixed harmless header value before and after loading a custom rule. The test checks the exact HTTP 403, rule ID in proxy telemetry, unchanged backend arrivals for the denied request, and a successful independent permitted request. The proxy and backend use ClusterIP Services, and the runner accesses only the proxy through dynamic local port forwards.

The fixture verifies custom-rule enforcement on the owned proxy path. Production WAF attachment, configured and updated managed rules, protocol and inspection coverage, exceptions and alert routing need evidence from the deployed ingress.

[OWASP CRS documentation](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/) and [CRS container configuration](https://github.com/coreruleset/modsecurity-crs-docker).
