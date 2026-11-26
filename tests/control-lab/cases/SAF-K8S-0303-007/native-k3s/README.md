# SAF-K8S-0303-007 native AppArmor guest proof

This package contains the exact guest script that completed the v10 direct-guest run and a small Lima launcher for repeating that single-kernel reference check. It is a scratch publication package; it does not modify the published seven-check case.

## Evidence established by the v10 run

The guest result recorded a Debian 13 ARM64 VM, active AppArmor in the LSM list, Kubernetes/K3s and kubelet v1.36.6+k3s1, and a single node using the guest kernel. On that kernel, a baseline Pod read two fixed harmless markers; a second Pod requested the exact loaded Localhost profile, read the permitted marker, failed to read the denied marker, and reported the exact profile in enforce mode. The runner captured only the JSON receipt, then stopped and deleted the VM. The retained result says the owned K3s process, namespace, profile and temporary state were cleaned up.

This is one guest/kernel/profile witness. It does not establish profile rollout across nodes, provider behavior, production readiness, or a second independent replay receipt.

## Inputs and reproducibility

Requirements: Apple Silicon macOS, Lima 2.0 or later, `shasum`, `python3`, `od`, and the pinned ARM64 K3s binary. `test-vm.yaml` is the adjacent immutable VM configuration copied from SAF-K8S-0701-003; SHA-256 is `7069d871394496a49ce511fc81dba76c70909e4c4bdee06376819b9ec7088d00`. It allocates 3 CPUs, 4 GiB memory, 12 GiB disk, no mounts, and pins the Debian 13 ARM64 cloud image digest. The launcher also requests Lima `--plain --mount-none`.

The unchanged tested guest script SHA-256 is `71bfd23ba15274c5ba86280bd79337ee86e9c0c90db35a8392479b13d30c658f`. Supply the official `k3s-arm64` release asset for K3s v1.36.6+k3s1; the script and launcher both require SHA-256 `49dcecdb4f64f5e92bdc52d204d407fb39729e492f09074488125ee58b6f2895`. Obtain the public binary from the [official K3s v1.36.6+k3s1 release](https://github.com/k3s-io/k3s/releases/tag/v1.36.6%2Bk3s1). The launcher does not download code or binary inputs.

Run from this directory:

```sh
./run-lima.sh /path/to/evidence /path/to/k3s-arm64
```

The launcher creates a unique Lima instance name and refuses to reuse an existing one. It stages only the pinned binary and the exact guest script into a private guest directory. The guest API binds to loopback. Temporary host-side logs and receipt staging are removed. After the guest reports success, the launcher stops/deletes the VM, verifies deletion, validates the sanitized result schema and pinned hashes, then atomically adds one uniquely named JSON receipt in the requested evidence directory. It never overwrites an earlier receipt. On failure it publishes no receipt. It does not retain Lima logs, guest logs, kubeconfig, private keys, or marker values in the evidence directory.

## Limitations

Only the small receipt JSON is retained. A future matched replay should use a fresh unique VM and preserve the second result separately. Keep deployment acceptance tied to actual target node OS/kernel, active LSM/profile delivery, workload identity and policy rollout; this reference does not replace those adopter checks.
