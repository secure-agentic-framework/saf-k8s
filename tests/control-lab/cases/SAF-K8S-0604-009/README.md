# Verify workload-aware remediation targets

```sh
python3 lab.py test SAF-K8S-0604-009 --docker-context desktop-linux
```

This case evaluates fictional findings against a versioned deadline policy in
Kind. The evidence records workload and artifact matching, risk order, assigned
owners, exception expiry, and the same deadline before and after remediation.
An overdue case fails the release Job. Verified remediation clears it while
the original missed target remains in the audit record.

The numerical targets and findings are fixture data. Deployed source coverage,
exception authority, portfolio thresholds and audit routing need separate
verification.
