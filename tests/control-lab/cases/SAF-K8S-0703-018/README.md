# Verify stable workload attribution on Kind

```sh
python3 lab.py test SAF-K8S-0703-018 --docker-context desktop-linux
```

Inert Pods use two synthetic scheduler slots and emit fixture activity markers
with their real Kubernetes UIDs. The test reuses one Pod name, checks a stale
sample at the allocation boundary, and independently reconciles a synthetic
node bill by allocation duration. Zero activity retains a nonzero allocation
share, and an unmatched charge remains unallocated.

The timestamp offsets, utilization signals, rate policy and charge lines are
synthetic. Hardware telemetry, provider exports and real costs require
separate verification.
