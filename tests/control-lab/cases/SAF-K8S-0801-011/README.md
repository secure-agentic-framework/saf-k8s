# SAF-K8S-0801-011 local demonstration

A real Kubernetes admission policy checks a synthetic sharing-risk record for an approved workload, mode, trust class and compensating control reference. A CPU-only fixture Pod runs under the approved record. The wrong sharing mode and an approval withdrawn after the run are refused. This exercises governance enforcement, with synthetic approvals and no GPU or vendor sharing mode.

## Adopter verification

1. Record the workload and data scopes, device and sharing configuration, tenant relationships, owner and review deadline. Match the approved decision to those exact values.
2. Independently verify named isolation, monitoring and emergency safeguards on the selected hardware and platform. Capture applicable provider limits and known residual risks.
3. Use inert approved declarations to verify normal admission and refusal for a withdrawn decision, an expired approval, a different share mode or the wrong trust scope. Check approval authority is separate from the ordinary workload submitter.
4. Retain the decision and guardrail evidence. Revalidate on workload, hardware, sharing configuration and risk acceptance changes.
