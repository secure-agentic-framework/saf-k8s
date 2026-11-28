# Physical A100 MIG placement candidate

Google documents a 1g.5gb partition for A100 40 GB in its A2 managed GKE
path. NVIDIA documents MIG in supported Linux passthrough guests and
explains why an A100 may need an ordinary guest reboot for pending mode.
The guest K3s demonstration below remains unverified.
[Google A2 GPU partition example](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/gpus-multi)
and [NVIDIA MIG setup](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/620/getting-started-with-mig.html).

Run only on a separately authorized disposable A100-SXM4-40GB test guest.
Use the existing signed driver, pinned K3s and NVIDIA runtime setup, the
staged device plugin manifest, and the existing PodResources helper in
`capture`. Install `psmisc` during host bootstrap so the transition can
check for clients that still have GPU device handles.

1. Finish and export the whole-GPU telemetry evidence. Run
   `sudo bash request-mig-mode.sh`. It stops only the owned GPU fixture and
   its monitoring/runtime consumers. Preserve the reported current and
   pending state. If the script reports `MIG_PENDING`, reboot the guest
   and verify current mode when reconnecting. Collect independent signed
   driver and provider boot evidence after the reboot.
2. Run `configure-mig` through the [campaign runner](../campaign/README.md).
   It requires the approved A100 model and driver, active MIG mode, and an
   empty fixture namespace. It records a reservation for this boot before
   creating two `1g.5gb` GPU and compute instances. Start a retry in a new
   attempt directory and preserve the original journal. The retry reuses
   exactly the approved geometry and any existing matching Device Plugin.
   Partial geometry, a different boot or an unreserved or changed plugin
   requires operator review. The runner confirms the exact kubelet resource
   count and saves a hashed preparation receipt.
   [NVIDIA MIG inventories](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/620/getting-started-with-mig.html)
   and [NVIDIA Device Plugin configuration](https://github.com/NVIDIA/k8s-device-plugin/tree/v0.20.2#configuration-option-details).
3. Run the placement test by ID. It requires the running GPU and plugin
   to match the reservation, then demonstrates the same whole-GPU dry-run
   before and after the case policy. Require the exact named Forbidden
   response and an independent absence readback. Both CUDA fixtures must
   run while the kubelet reports two distinct assignments joined to the
   driver inventory. Preserve the preparation receipt and the placement
   receipt. The case removes its own test Pods, policy and binding before
   emitting a passing placement receipt.

This verifies placement and a CUDA witness on two actual partitions when
the full guest test passes. It leaves remanence, broader physical isolation,
and side channels outside the demonstrated scope.
