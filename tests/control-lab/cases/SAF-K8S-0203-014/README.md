# SAF-K8S-0203-014 — Intent headers, expiring sessions, and authenticated peers

```sh
python3 lab.py test SAF-K8S-0203-014 --docker-context desktop-linux
```

One restricted Job serves a public marker on loopback. A fixed request
intent header admits a caller without a session. A separate route
requires an issued session and rejects the same session after it expires.
A third listener uses native mutual TLS. It refuses connections without
a client certificate and refuses a client from a separate trust root even
when it presents the same subject label. The trusted client completes a
verified handshake and receives the marker. All keys and session values
are disposable. The receipt contains only outcomes and the public test label.

## Verify deployment applicability and evidence

1. For each governed cloud node pool, record the provider product, expected
   access mechanism, available versions, who owns the applied settings,
   approved node dependencies and any exception. Collect the applied
   provider and instance configuration through a read-only export.
2. On eligible EC2 nodes with metadata enabled, verify the approved
   `HttpTokens` setting and supported IMDSv2 mode in applied configuration.
   Assess endpoint enablement, response hop limit, IPv6 and effective
   routing separately. Provider defaults, launch policy and applied
   instance values can come from different layers.
3. For GKE and AKS, inventory the supported metadata path and relevant
   workload identity and network restrictions. A request-intent header
   expresses protocol intent. For a supported client-authenticated path,
   verify the provisioned trust roots, client identities and peer
   authentication through the actual provider mechanism.
4. Use authorized, disposable staging and harmless values when comparing
   approved and denied responses. Collect expected status, mode, observed
   behavior and retained node or workload functionality by caller class.
   Keep provider-managed evidence and unsupported or excepted cases explicit.

This fixture compares protocol contracts. Applied provider settings and
compatibility are verified separately for each selected platform.

[EC2 metadata settings](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html) ·
[Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service) ·
[GKE workload identity](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity) ·
[Python SSL peer certificate verification](https://docs.python.org/3.13/library/ssl.html)
