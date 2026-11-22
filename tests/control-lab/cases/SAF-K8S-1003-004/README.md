# SAF-K8S-1003-004 — ATT&CK for Containers coverage mapping

```sh
python3 lab.py test SAF-K8S-1003-004 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the same arguments. The case runs three native Kubernetes Jobs on v1.36.1 Kind. The Jobs mount the three selected Containers technique records, their corresponding tactic metadata from MITRE v20.1, and synthetic detection and mitigation evidence.

The ungated Job accepts an invalid register. The enabled validator rejects a wrong tactic, a mismatched event, a missing gap owner and an unsupported deployment claim. The corrected register passes with three accountable gaps and an explicit unknown deployment state. The fixture records the full upstream release digest and includes the corresponding selected metadata.

A production review needs a deployment inventory, prioritization across the applicable matrix, verifiable detection and mitigation evidence, and a review schedule that responds to changes in the release or infrastructure.

[MITRE ATT&CK v20.1 release](https://github.com/mitre-attack/attack-stix-data/releases/tag/v20.1) · [Containers matrix](https://attack.mitre.org/versions/v20/matrices/enterprise/containers/) · [Kubernetes Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/)
