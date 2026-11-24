# SAF-K8S-0910-017 cross-cluster audit collection

Run `python3 lab.py test SAF-K8S-0910-017` from the control-lab directory.
This case owns three single-control-plane clusters. Provision the lab and
independent replay sequentially on a host whose concurrency limit is four.

Source clusters emit native Kubernetes Metadata-level audit records for
authorized synthetic placement updates. The case verifies the exact source
contexts, filters the audit fields, and writes the batch through a scoped
collector identity to the independent Kubernetes store. A scoped reader
retrieves the exact batch after both source clusters are removed. The absent
baseline and unapproved reader denial are independently measured.

Run-driven forwarding and one central ConfigMap illustrate the boundary.
Verify production transport continuity, signatures or other integrity
assurance, alerting, clock skew and retention separately.
