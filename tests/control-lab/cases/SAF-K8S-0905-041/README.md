# SAF-K8S-0905-041 Zot source-to-local-alert candidate

This is a scratch-only extension of the current five-check case. It adds one
grouped sixth assertion and has not been executed. It preserves the original
normalized eight-event cases and scoped disposition checks.

The addition reuses the existing project pin for Zot v2.1.23 and the existing
Python client pin. It starts one case-owned local Zot registry with the
documented audit-file setting, creates a temporary random fixture publisher
identity, and uses a client to push and pull one OCI artifact containing only
an empty `{}` config, no layers, and a fixed inert marker annotation. It
selects exactly one native Zot audit row by message, method, exact marker path,
status 201, and fixture actor. The raw row is captured by a private subprocess,
never sent to `lab.check` or written to evidence. The normalizer derives one
fixed bounded event projection from those observed fields and forwards it to
the existing monitor.

The monitor sends its alert projection to a new case-owned in-cluster HTTP
receiver. One grouped assertion compares the receiver before and after the
actual Zot event, verifies the exact sensitive-publish alert, checks that the
existing ordinary and out-of-scope fixtures remain absent, and replays the
same event to verify the receiver does not receive a duplicate. Existing
fixture event quiet/replay assertions remain in place. There are no external
notifications, providers, public targets, model weights, or non-fixture
artifacts. The receiver is deliberately unauthenticated and stores only in a
memory-backed `emptyDir`; it is not evidence of an authenticated production
notification channel or durable SIEM retention.

The randomly generated publisher password and htpasswd file are fixture-only.
The files are created mode 0600 under the runner's temporary kubeconfig parent
and removed in a `finally` block after the Kubernetes Secret is created. The
secret remains only in the disposable case namespace until cluster teardown.
No credential value is passed to the evidence logger. The Zot audit rows are
read through a private subprocess, filtered in process, and discarded.

The Zot source is authenticated to its temporary fixture registry, but source
authentication into the monitor is not tested: the event bridge is trusted
because it reads the selected case-owned native audit file. The monitor and
receiver use a local unauthenticated HTTP service in this isolated reference.
Production deployment must authenticate the registry event producer and
forwarder, protect the receiver route, prove event completeness and schema
integrity, route to named responders, test failure/retry behavior, preserve
durable original records, and retain review/acknowledgment evidence. The Zot
example does not establish behavior for Harbor, MLflow, Hugging Face, or other
registry providers.

## Crosswalk conditions for adoption

- **NIST AU-6:** Map as `partial`, `moderate`, `conditional` only when the
  deployed registry supplies an authenticated and sufficiently complete audit
  source, and the organization defines review frequency, unusual/inappropriate
  activity criteria, impact analysis, reporting roles, and risk-based review
  changes. The candidate adds only a single local Zot source event to the
  synthetic review fixture; it does not establish those organizational or
  deployed-system conditions.
- **NIST SI-4(5):** Map as `supports`, `moderate`, `conditional` only when the
  organization defines covered registry behavior as an indication requiring
  an alert and routes it through an authenticated delivery path to named
  personnel or roles. The receiver in this candidate is local and
  unauthenticated. The source event is selected from a case-owned native Zot
  log via a privileged local read; that does not authenticate an external
  producer or forwarder. The fixture anomaly classification remains supplied
  input rather than a detection result.

These are partial contributions. They do not justify `direct / strong /
required` mappings for AU-6 or SI-4(5), nor an assertion that the local route
proves production recipient identity, source authenticity, analyst response,
or durable retention.

Pinned primary references: [Zot v2.1.23 monitoring and audit configuration](https://zotregistry.dev/v2.1.23/articles/monitoring/),
[Zot v2.1.23 audit implementation](https://github.com/project-zot/zot/blob/v2.1.23/pkg/api/session.go#L141),
and [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/).
