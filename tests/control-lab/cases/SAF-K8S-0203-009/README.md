# SAF-K8S-0203-009 Workload-specific identity mapping

Three Pods consume tokens projected by Kubernetes. A local TLS endpoint performs real TokenReview and applies an explicitly scoped identity-to-role mapping. An alternate valid subject and the wrong audience are rejected, and the intended workload is routed to its fixture principal. The short-lived token values and test TLS private key never enter receipts. Production identity federation, provider API authorization, and actual fallback assessment require deployment evidence.
