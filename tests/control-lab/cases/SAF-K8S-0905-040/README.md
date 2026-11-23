# SAF-K8S-0905-040 — Forward model registry audit events

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-040 --docker-context desktop-linux` from the framework checkout. The runner host needs `htpasswd`.

Two separate Zot deployments run the same authenticated OCI operations on an inert manifest. Both log successful mutating operations to the native audit file and all four tested operations to the HTTP access file. Only one deployment runs Fluent Bit. The test matches actor, action, path, status, and timestamp against records fetched from the independent receiver. It then replaces the receiver Pod, compares the old corpus, and verifies fresh delivery. The receiver stores events on a disposable PVC.

The case covers manifest publication, pull, retagging, and digest deletion. Verify administrative and permission events through the applicable source for each deployed registry. Production delivery, loss recovery during sink outage, and the required retention period remain open.

- [Zot 2.1.23 monitoring](https://zotregistry.dev/v2.1.23/articles/monitoring/)
- [Zot pinned audit implementation](https://github.com/project-zot/zot/blob/v2.1.23/pkg/api/session.go#L141)
- [Fluent Bit 5.1.2 tail implementation](https://github.com/fluent/fluent-bit/tree/v5.1.2/plugins/in_tail)
- [Fluent Bit HTTP output](https://docs.fluentbit.io/manual/data-pipeline/outputs/http)
