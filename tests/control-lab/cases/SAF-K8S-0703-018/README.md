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

## Adopter verification

1. Inventory actual devices, capacity and usable allocation units, workload
   identity and ownership, telemetry sources, and provider billing records.
   Preserve each source's units, reporting window and completeness.
2. Join workload observations to immutable Pod UIDs and effective ownership
   during the exact reported window. Check same-name replacement, late or
   missing samples and overlapping billing intervals.
3. Reconcile source line items with approved cost-allocation rules. Retain
   measured usage, capacity, charged quantities, shared allocations and
   amounts that could not be allocated, with their separate evidence.
4. Review representative report totals and evidence with the accountable
   finance and platform owners, and record cadence and adjustments.
