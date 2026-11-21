# SAF-K8S-0102-021 — etcd certificate expiration alerts

```sh
python3 lab.py test SAF-K8S-0102-021 --docker-context desktop-linux
```

Read the public expiry and local CA verification for the kubeadm etcd server,
etcd peer and API-server-to-etcd client leaves. Evaluate the rules using
Prometheus 3.5.0 in an isolated container. Healthy input includes the observed
expiry time of each leaf. Synthetic groups cover each role one second beyond the
30-day alert boundary, exactly at the boundary, one second after expiration,
and missing telemetry. Missing data must stay absent for five minutes before
alerting. The red arm expects a boundary alert and deliberately omits the rule
file, so the same evaluator reports the missing alert.

The case uses example thresholds and a synthetic metric contract for a single
cluster. Deployment verification still needs a collector, expected member
inventory, remediation and routing requirements, and test notifications. The
certificates inspected are public. The case files, evaluation inputs and
disposable Kubernetes cluster are cleaned up by the runner.

- [Kubernetes v1.36 Certificate Management with kubeadm](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-certs/)
- [Kubernetes v1.36 PKI certificates and requirements](https://v1-36.docs.kubernetes.io/docs/setup/best-practices/certificates/)
- [Prometheus 3.5.0 alert test format](https://github.com/prometheus/prometheus/blob/v3.5.0/docs/configuration/unit_testing_rules.md)
