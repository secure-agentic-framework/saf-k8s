# SAF-K8S-0801-011 local demonstration

A real Kubernetes admission policy checks a synthetic sharing-risk record for an approved workload, mode, trust class and compensating control reference. A CPU-only fixture Pod runs under the approved record. The wrong sharing mode and an approval withdrawn after the run are refused. This exercises governance enforcement, with synthetic approvals and no GPU or vendor sharing mode.
