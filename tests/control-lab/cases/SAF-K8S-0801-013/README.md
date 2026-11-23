# SAF-K8S-0801-013 Sharing eligibility across trust domains

The live Kubernetes API initially admits a synthetic shared resource from an unapproved trust namespace. Namespace resource quotas then limit each trust boundary to its own approved resource name. Each namespace runs one CPU workload with its corresponding synthetic resource. The case verifies the tested resource-key admission scope. A separate synthetic resource name provides no physical isolation or sanitation evidence.
