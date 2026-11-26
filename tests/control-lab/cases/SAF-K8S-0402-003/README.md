# SAF-K8S-0402-003 Protect service account authenticators

Run `python3 tests/control-lab/lab.py test SAF-K8S-0402-003 --docker-context desktop-linux` from the framework checkout.

The case compares raw and filtered Pod output. It observes a fixed account identifier, preserves unrelated and shared-prefix names, and removes the value of an inert Authorization bearer header before collection. Both Kubernetes workloads disable token automount. A temporary Git repository records an inert marker and then removes it. The case independently checks presence in the current tree before removal and continuing presence in history after removal. Only fixed canary observations are retained.

## Verify an adopting implementation

1. Treat ServiceAccount tokens, other bearer authenticators, private keys, and credential-bearing authorization headers as secrets. Treat account names and subjects as identifiers; decide which names reveal sensitive structure and where their disclosure is acceptable.
2. Scan current and historical source repositories, CI logs/artifacts, built image layers, and published documentation using approved secret-scanning rules for Kubernetes token forms and other organization credentials. Separately search for protected account names/subjects, with explicit allowlisted operational locations to avoid breaking auditability.
3. In each supported application and log path, emit fixed invalid canary strings in a disposable environment. Verify the aggregator/parser prevents the credential value from reaching retained logs while keeping required event context. Verify expected request/error responses do not echo credentials. Keep results sanitized; never test with live tokens.
4. Confirm exceptions are limited, owned, documented, and revisited. Keep logs access-controlled and retain identity fields needed for audit where policy permits; redaction should remove authenticator values without erasing authorization-relevant event identity.
5. Verify the actual deployment's secret scanner, retention/rewrite process for historical findings, image scanning scope, and log/API redaction configuration. Record exact repository/image/log-pipeline versions, coverage, allowed exceptions, test canary digests or labels, and finding disposition.

The fixture covers specific fixed marker behavior. Verify the deployed credential matcher, scan inputs, historical coverage, artifact layers, log pipeline and outside-facing responses using the intended policies and sanitized test evidence.

- [Kubernetes v1.36 ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
- [Kubernetes v1.36 authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
