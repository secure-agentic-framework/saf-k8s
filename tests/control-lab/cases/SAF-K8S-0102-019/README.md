# SAF-K8S-0102-019 Separate client and peer ingress policy

Two public TCP markers model distinct etcd endpoint classes inside disposable Kind. The test compares unfiltered connectivity with scoped ingress policy, including the two intended connections and denied workload and unintended cross-class paths. The fixture does not connect to any actual etcd endpoint. Production host and node networking, TLS, peer identity and managed provider paths require distinct deployment evidence.
