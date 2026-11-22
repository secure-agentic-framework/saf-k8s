# SAF-K8S-0104-016 — CIS Benchmark remediation workflow tracking

```sh
python3 lab.py test SAF-K8S-0104-016 --docker-context desktop-linux
```

The workflow fixture tracks an inert configuration finding from detection
through ownership, deadline, remediated revision, independent retest and
closure. A counterfactual assigns the retest to the remediation owner. The
validator rejects that record and accepts the evidence-linked independent
review. The finding, people, dates and historical results are synthetic.

A separate read-only check inside the case-owned kind Kubernetes v1.36.1 node
confirms the current kubelet has its secure listener and no read-only listener.
It inspects only the target configuration field and local kernel socket metadata.
The test leaves the kubelet configuration as provisioned.

The framework retains `verified/SAF-K8S-0104-016.json` after lab and framework
replays. Organization-wide benchmark coverage, ownership and timeliness remain
tracked on the primary Bead and its deployment follow-up.

- [Kubernetes v1.36 kubelet configuration reference](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)
- [Kubernetes v1.36 kubelet files](https://v1-36.docs.kubernetes.io/docs/reference/node/kubelet-files/)
