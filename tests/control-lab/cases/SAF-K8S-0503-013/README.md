# Verify a web application firewall on its Gateway route

Run `python3 tests/control-lab/lab.py test SAF-K8S-0503-013 --docker-context desktop-linux`
from the framework checkout. The pinned Envoy Gateway programs one owned
HTTPRoute to the existing ModSecurity/OWASP CRS Service. The case verifies the
actual route/backend and controller and proxy pins. All three marker checks
traverse the proxy's ClusterIP through its dynamically allocated loopback
forward. The harmless marker passes in the control arm, produces the exact
WAF denial with no backend dispatch after activation, and the permitted
marker still reaches the backend.

For adoption, inventory actual endpoints, route and TLS boundaries, WAF
attachment and effective managed or custom rules. Use a harmless owned canary
and independently verify WAF and backend observations. Record enforced source
and destination restrictions, authorized exceptions, event delivery, retention
and responder ownership. Where applying SI-10(6), verify that the adopted
rules inspect the relevant organization-defined inputs and injection classes.

- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [Envoy Gateway v1.10.0 release](https://github.com/envoyproxy/gateway/releases/tag/v1.10.0)
