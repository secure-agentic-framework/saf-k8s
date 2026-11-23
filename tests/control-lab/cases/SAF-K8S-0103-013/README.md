# SAF-K8S-0103-013 Controller credential boundaries

The Kubernetes API issues short-lived fixture tokens bound to an owned Pod and explicit audiences. Review the intended audience, denial at another audience, distinct reissue and invalidation after the old Pod is deleted. The runner uses the tokens only in memory against its own API server and retains sanitized outcomes. This checks Kubernetes issuance and binding. Provider exchange, issuer trust, automatic consumer refresh and cloud credential retirement need separate deployed evidence.
