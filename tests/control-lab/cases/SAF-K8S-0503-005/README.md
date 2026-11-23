# SAF-K8S-0503-005 CoreDNS logging and detection canary

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0503-005 --docker-context desktop-linux
```

A dedicated CoreDNS instance serves two names in a closed fixture zone. The same fixed canary answers without a log record before logging and with an exact structured record after logging. A normal name also resolves and produces a structured record. The test delivers both real records to a separate observer Job, which reports exactly one synthetic alert. The fixture has no upstream resolver.

These checks cover the live log and observer path for the fixed names. Production detector coverage, forwarding to the organization's analysis service, alert response, and DNS enforcement remain separate evidence requirements.

[CoreDNS query logging](https://coredns.io/plugins/log/) and [Kubernetes DNS debugging](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/dns-debugging-resolution/).
