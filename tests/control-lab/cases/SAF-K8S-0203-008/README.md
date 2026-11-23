# SAF-K8S-0203-008 Metadata access path boundaries

A governed test Pod connects only to two owned marker Pods. The egress policy denies the marker representing node metadata while preserving the approved identity path. Restricted admission separately rejects a host-network declaration using server dry-run. No real metadata endpoint, provider credential or host-network connection is used. Verify actual node, provider, IPv6 and approved identity paths independently.
