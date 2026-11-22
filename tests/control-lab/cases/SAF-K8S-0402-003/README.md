# SAF-K8S-0402-003 — Service account identifier exposure prevention

```sh
python3 lab.py test SAF-K8S-0402-003 --docker-context desktop-linux
```

On a fresh kind Kubernetes v1.36.1 cluster, two short-lived non-root Pods
process the same three inert input lines. The baseline prints them verbatim.
The filtered Pod replaces the one line carrying the exact configured synthetic
ServiceAccount name before writing stdout. A separate name and a longer name
with the same prefix retain their original content. Both Pods disable
ServiceAccount token automount. The runner reads only their disposable stdout.

Kubernetes uses a ServiceAccount name in Pod identity configuration and uses a
ServiceAccount token as a bearer credential. This fixture tests account-name
filtering with inert text. Credential protection and coverage of production
logs, source history, image layers, errors and public responses need their own
evidence. The primary Bead links both runs and the remaining scope.

The framework retains `verified/SAF-K8S-0402-003.json` with the source digest
and passing observations. A rerun writes `result.json` and command evidence
under the case evidence directory.

- [Kubernetes v1.36 ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
- [Kubernetes v1.36 authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/)
