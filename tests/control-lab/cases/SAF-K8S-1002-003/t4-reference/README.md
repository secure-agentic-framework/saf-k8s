# Tesla T4 telemetry reference for SAF-K8S-1002-003

This reference uses a dedicated Linux VM with one whole NVIDIA Tesla T4 and a disposable single-node K3s cluster. It correlates the CUDA workload, kubelet allocation, DCGM Exporter and independent Prometheus scrapes. The framebuffer witness allocates, fills, holds and releases 128 MiB through the CUDA Driver API. Both observed framebuffer gauges must increase by at least 128 MiB for the same Pod UID and GPU UUID.

## Reproduce

Use a dedicated x86-64 Ubuntu 22.04 VM with full passthrough of one Tesla T4, a private Kubernetes API, and a bounded lifetime. Name the guest `saf-dcgm-t4-` followed by ten digits. The recorded run used GCE image `ubuntu-2204-jammy-v20261124` with kernel `6.8.0-1074-gcp`. Place this directory at `~/saf-t4-lab` on the guest. The replay deletes and recreates the disposable K3s cluster on that guest.

Build both witness binaries before copying the directory to the guest. The kubelet client uses Go 1.26.8 and the Kubernetes v0.36.6 API bindings. The memory witness uses Zig 0.14.0 to target the container’s libc ABI.

```sh
(cd capture/podresources-list && GOTOOLCHAIN=go1.26.8 GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -o podresources-list-linux-amd64 .)
zig cc -target x86_64-linux-gnu.2.17 -O2 -Wall -Wextra -Werror \
  fixtures/framebuffer-witness.c -o fixtures/framebuffer-witness-linux-amd64 -ldl
```

On the new guest, install the driver and runtime. Apply the exporter and Prometheus, then run the CUDA workload and capture the matched observations.

```sh
cd ~/saf-t4-lab
sudo apt-get update
sudo bash install-driver.sh
sudo bash guest-bootstrap.executed.sh
sudo bash deploy-and-baseline.sh
sudo bash measure-framebuffer.sh run-1
```

Preserve `evidence/run-1` and `capture/run-1`. Independently replay the same checks on a new cluster datastore and verify its new node UID.

```sh
sudo bash replay.sh "$PWD"
```

The capture reads the local kubelet PodResources v1 socket and uses IPv4 loopback port forwards to the selected exporter and Prometheus Pods. The receipt identifies the workload, GPU allocation, exporter image digest and exact scrape timestamps. Review those observations and preserve `evidence/run-2` and `capture/run-2` before deleting the VM and its temporary storage.

| Component | Tested version |
| --- | --- |
| NVIDIA driver | 580.178.04 |
| NVIDIA Container Toolkit | 1.20.2 |
| K3s | v1.36.6+k3s1 |
| NVIDIA device plugin | v0.20.2 |
| NVIDIA DCGM and DCGM Exporter | 4.6.1 and 4.8.4 |
| Prometheus | 3.5.0 |

The rendered exporter DaemonSet comes from the [NVIDIA DCGM Exporter](https://github.com/NVIDIA/dcgm-exporter) Helm chart 4.8.4 under Apache-2.0. The chart archive SHA-256 is `047b75f5775c66346f96373504e08c81e2f3e2768b4ef64c5314768307ad643c`.

The recorded result covers GPU utilization and framebuffer use on this full-device T4 profile. MIG, confidential computing, firmware attestation, and DPU behavior require distinct hardware profiles. [NVIDIA DCGM platform support](https://docs.nvidia.com/datacenter/dcgm/latest/user-guide/getting-started.html) · [Exporter version pairing](https://docs.nvidia.com/datacenter/dcgm/latest/installation/install-dcgm-exporter.html) · [Kubelet PodResources socket](https://kubernetes.io/docs/reference/node/kubelet-files/) · [K3s NVIDIA runtime](https://docs.k3s.io/advanced#nvidia-container-runtime)
