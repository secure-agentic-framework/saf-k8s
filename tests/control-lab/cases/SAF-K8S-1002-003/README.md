# SAF-K8S-1002-003 — AI workload telemetry integration

```sh
python3 lab.py test SAF-K8S-1002-003 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the same arguments. The test uses the checksum-pinned Prometheus Operator v0.85.0 release bundle and digest-pinned images on a fresh Kubernetes v1.36.1 Kind cluster.

The fixture's training service runs three small CPU training epochs. Its separate inference service measures a classification pass and reports the measured latency and exact seven-of-eight quality score. Both endpoints are healthy before enrollment, when Prometheus has zero fixture targets and zero samples. A ServiceMonitor enrolls the training service and a PodMonitor independently enrolls the inference Pod. The test checks four exact series, both active scrape pools, and a healthy unselected comparison endpoint.

The scraper service account can list EndpointSlices in the fixture namespace. Kubernetes denies the same discovery request in another namespace and denies Secret reads. Check the retained observations for raw Prometheus query results, target states and discovery decisions.

Production training and serving framework instrumentation, GPU nodes and taints, exporter field availability, and real device metrics require separate deployment evidence.

[Prometheus Operator v0.85.0](https://github.com/prometheus-operator/prometheus-operator/releases/tag/v0.85.0) · [Prometheus Operator troubleshooting](https://prometheus-operator.dev/docs/platform/troubleshooting/) · [NVIDIA DCGM Exporter](https://docs.nvidia.com/datacenter/cloud-native/gpu-telemetry/latest/dcgm-exporter.html)

For adoption, record the actual vendor, hardware, driver, exporter version and metric field support for accelerator signals. Compare the exporter output with independently scraped, workload-attributed samples for the deployed nodes. For training and inference, record each real source, signal semantics, runtime version, identity labels, authorized scrape selectors and controlled coverage limits. The fixture's fixed quality, training and inference values exercise collection.

- [NVIDIA DCGM Exporter installation and compatibility](https://docs.nvidia.com/datacenter/dcgm/latest/installation/install-dcgm-exporter.html)
- [NVIDIA DCGM Exporter metric support](https://docs.nvidia.com/datacenter/dcgm/latest/reference/dcgm-exporter-metrics.html)
