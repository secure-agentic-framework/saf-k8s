# SAF-K8S-0502-004 — CNI plugin hardening and lifecycle management

Run from the framework root.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0502-004 --docker-context desktop-linux
```

The disposable Kubernetes v1.36.1 profile uses Helm 3.17, Kind v0.32.0 and a kernel supported by Cilium. The case installs the digest-verified Cilium v1.20.5 chart, checks the pinned agent and operator images and confirms a synthetic Service answers.

A schema-invalid readiness threshold is rejected by the API server. Without atomic rollback Helm leaves a failed revision. With atomic rollback it creates a failed revision followed by a deployed rollback. The case verifies the exact approved values and image pins are restored and the Service again returns the marker. This checks rejection before a new version of the workload starts.

For adoption, capture the actual plugin version, approved chart and images, hardening values and policy baseline. In an equivalent nonproduction topology exercise an approved version change with relevant CRDs, datapath and node lifecycle. Record agent and operator readiness, policy enforcement and independent marker traffic before, during and after a representative failure and recovery. Retain the known-good configuration, rollback result, recovery time, patch/advisory owner and any provider-specific commitments. The conditional CM-3(2) contribution covers the tested change-validation and recovery slice.

[Cilium v1.20 Kind installation](https://docs.cilium.io/en/v1.20/installation/kind/) · [Helm v3 upgrade](https://helm.sh/docs/v3/helm/helm_upgrade/) · [Kubernetes v1.36 workload probes](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/)
