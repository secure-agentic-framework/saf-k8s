# Verify selected delivery lifecycle checkpoints

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-017 --docker-context desktop-linux
```

The disposable Kubernetes example exercises separate delivery checks. At Develop, Restricted Pod Security compares an approved Pod with one missing a required setting. At Distribute, the approved object is stored and read back with its expected digest, and the changed bytes are refused. At Deploy, native admission denies tag-only input and accepts the digest-pinned image. At Runtime, the exact admitted Pod becomes Ready and returns its public marker.

For adoption, identify each required Develop, Distribute and Deploy decision and the stage that can prevent progression. Select a governed test artifact and retain its source revision, immutable build digest and exact readback at distribution. Check approved and refused cases at each effective boundary. Retain the admission decision, resulting workload and image identity, and health evidence. Assess Runtime monitoring and response separately using the actual telemetry, delivery target, response owner and a harmless observed signal. Track applicable coverage and approved exceptions across delivery paths.

[NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) · [Separate monitored rollout response example](https://github.com/secure-agentic-framework/saf-k8s/blob/f23c417d/tests/control-lab/verified/SAF-K8S-0905-035.json)
