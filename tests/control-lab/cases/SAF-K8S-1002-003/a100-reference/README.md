# A100 GPU telemetry reference

This reference used one A100-SXM4-40GB with NVIDIA driver `580.178.04`,
K3s `v1.36.6+k3s1`, Kubernetes device plugin `v0.20.2`, and DCGM `4.6.1`
with exporter `4.8.4`. A CUDA vector workload passed. The reference joined
its live Kubernetes Pod UID and kubelet PodResources assignment to the A100
device and to the matching series in both the exporter and Prometheus.

A fixture process allocated 128 MiB. Both sources observed
`DCGM_FI_DEV_FB_USED` rise from 0 to 556 MiB for the same workload and GPU.
The metric totals include driver and CUDA context overhead. The selected
Prometheus sample was under 15 seconds old at capture. This is one hardware
run with one confirmed field on a specific stack.

The lab observed Alertmanager delivery and retained an immutable hold. Its
admission test did not establish escalation denial. Google Cloud preempted
the Spot guest during a second attempt. Routing and escalation outcomes
have separate review records. The exported reference here covers the live
telemetry stages.

## Replay readiness

Use a disposable AMD64 Linux A100 host with K3s, a working NVIDIA
RuntimeClass and device plugin, and one allocatable GPU. The fixtures install
the exporter, Prometheus, and CUDA witness into dedicated namespaces.
`deploy-and-baseline.sh` expects the lab hostname to match
`saf-a100-[0-9]{10}` and the workload namespace to be unused.
Run in the checkout on that host. Use Go 1.26.8 to match the tested helper.

```sh
(cd podresources-list && CGO_ENABLED=0 go build -trimpath -o ../podresources-list-linux-amd64 .)
sudo bash deploy-and-baseline.sh
sudo python3 a100_readiness.py \
  --kubeconfig /etc/rancher/k3s/k3s.yaml \
  --exporter-selector 'app.kubernetes.io/name=dcgm-exporter' \
  --podresources-binary "$PWD/podresources-list-linux-amd64" \
  --output "$PWD/evidence/readiness.json"
```

This preflight matches one GPU through the local kubelet Unix socket and
port-forwards only the selected exporter and Prometheus to IPv4 loopback.
The optional `--framebuffer-helper` records the original fixture binary's
verified digest. The retained reference includes that pin. The read-only
capture itself needs no CUDA allocator. Replaying the allocation stage needs
a separately built and reviewed binary from the included
`fixtures/framebuffer-witness.c` and an owned workload.

Review the retained identity joins, metric values, and timing locally with
`python3 review-recorded-telemetry.py`. The readiness receipt omits the
instance hostname and stores workload and hardware identifiers as hashes.

- [DCGM exporter v4.8.4](https://github.com/NVIDIA/dcgm-exporter/releases/tag/4.8.4)
- [NVIDIA DCGM Exporter metric support](https://docs.nvidia.com/datacenter/dcgm/latest/reference/dcgm-exporter-metrics.html)
