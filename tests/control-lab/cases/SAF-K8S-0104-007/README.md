# SAF-K8S-0104-007 Emergency maintenance validation

This Kind exercise records a protected drain that stops when the only Ready fixture Pod cannot be evicted. After adding capacity, the worker drains and the workload reschedules. An independent client reads the live HTTP marker through the Service before and after drain. The case uncordons the worker and confirms it accepts a new marker. It checks live runbook gates, rather than installing a software patch. Deployed emergency approvals, platform-specific patching and independent recovery need their own evidence.
