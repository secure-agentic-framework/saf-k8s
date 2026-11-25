# SAF-K8S-0801-013 Sharing eligibility across trust domains

The live Kubernetes API initially admits a synthetic shared resource from an unapproved trust namespace. Namespace resource quotas then limit each trust boundary to its own approved resource name. Each namespace runs one CPU workload with its corresponding synthetic resource. The case verifies the tested resource-key admission scope. A separate synthetic resource name provides no physical isolation or sanitation evidence.

## Adopter verification

1. Identify which tenants and sensitivity levels may share devices. Record actual driver, firmware, runtime, topology and sharing mode for each approved device pool.
2. Use authoritative evidence to establish the applicable memory isolation or sanitization guarantee and its prerequisites. Where independent isolation is unsupported or unverified, show that effective allocation prevents incompatible co-location.
3. Trace an authorized workload and a negative cross-boundary declaration through actual admission, quota, scheduling, allocators and workload-visible inventory. Verify movement or reallocation does not silently broaden the boundary.
4. Retain proof scope, workload and device identities, coverage gaps, approvals and independent review.
