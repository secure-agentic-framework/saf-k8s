# SAF-K8S-0704-014 Audit retention and retrieval

This case configures the actual Kubernetes file audit backend in a disposable Kind cluster with a 1 MiB rotation threshold and one rotated backup. The policy records only patches to the fixture ConfigMap at RequestResponse level and the patches contain exclusively public test markers and padding. Assertions verify the first record, the eventual backup bound and removal of the oldest record, and continued retrieval from the active log. Evidence contains only observed flags, counts and marker-presence results.

This demonstrates size-triggered log rotation and immediate local retrieval. Managed-provider source coverage, time-based retention, authorized query and archive restore need separately observed destination evidence.
