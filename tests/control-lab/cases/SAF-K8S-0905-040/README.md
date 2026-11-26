# SAF-K8S-0905-040 — Forward model registry audit events

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-040 --docker-context desktop-linux` from the framework checkout. The runner host needs `htpasswd` and the OpenSSL CLI.

Two separate Zot deployments run the same authenticated OCI operations on an inert manifest. Both log successful mutating operations to the native audit file and all four tested operations to the HTTP access file. Only one deployment runs Fluent Bit. The test matches actor, action, path, status, and timestamp against records fetched from the independent receiver. It then replaces the receiver Pod, compares the old corpus, and verifies fresh delivery. The receiver stores events on a disposable PVC.

The case retains its original three checks for manifest publication, pull, retagging, and digest deletion. It adds one grouped credential check: a separate synthetic wrong credential receives HTTP 401 from the fixture sink, while the Fluent Bit arm proves its valid synthetic credential is accepted by forwarding the exact corpus. Both output routes use a short-lived TLS certificate with the exact sink Service DNS SAN, `serverAuth` EKU, SKI and AKI; Fluent Bit validates the mounted ephemeral CA. The independent readback client also validates the same CA and DNS name.

The TLS CA/leaf and valid/invalid Basic Auth values are generated at runtime in a mode-0700 temporary directory. OpenSSL writes private keys only via `-keyout` file arguments. The runner creates Kubernetes TLS/Auth/forwarder-config Secrets with file-path arguments; no credential or private-key value appears in a CLI argument, event payload, log, or evidence. The Fluent Bit configuration containing the synthetic auth value is generated in the same private temporary directory and mounted only into the Fluent Bit container from a Secret; it is not written to the receiver PVC or evidence. The output explicitly enables certificate chain and hostname verification against the exact service SAN. The invalid-credential probe prints only status and a boolean. The temporary directory is removed after Secret creation.

## Verify an adopting implementation

Identify each required event class and its actual source. Use approved inert operations to independently compare registry and central records, including permission changes and administrative actions through the provider's audit surface. Match the event's subject, action, time, resource and result. Confirm the transport requires the expected receiver identity and authorized sender credentials. Track delivery through a scoped interruption, check for loss and duplicate records, and confirm retrieval after receiver replacement and for the approved retention interval. Verify clock tolerance across the selected component set.

The fixture exercises one forwarding and receiver path with a disposable PVC. External SIEM delivery, outage/retry recovery, deduplication, and the required retention period remain open.

- [Zot 2.1.23 monitoring](https://zotregistry.dev/v2.1.23/articles/monitoring/)
- [Zot pinned audit implementation](https://github.com/project-zot/zot/blob/v2.1.23/pkg/api/session.go#L141)
- [Fluent Bit 5.1.2 tail implementation](https://github.com/fluent/fluent-bit/tree/v5.1.2/plugins/in_tail)
- [Fluent Bit HTTP output](https://docs.fluentbit.io/manual/data-pipeline/outputs/http)
- [Fluent Bit scheduling and retries](https://docs.fluentbit.io/manual/administration/scheduling-and-retries)
