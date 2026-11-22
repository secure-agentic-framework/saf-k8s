# SAF-K8S-0904-007 — Scheduled feature job hardening

The fixture submits the same inert definitions to native admission before
and after activating scoped bindings. The authorization path checks named
reviewer, editor, and workload identities. The restricted editor suspends
the CronJob after the real controller makes its owned Job. That child Job
completes with a hardened Pod and a known harmless marker. A separate
running sleeper exercises Job-controller deadline enforcement.

This case shows the selected CronJob policy fields, workload Pod settings,
and actual ownership and expiry. It covers tagged fixtures in one namespace.
It leaves production data permissions, governance and change monitoring,
selection and lifecycle coverage, and overlapping schedule behavior for
separate evidence.
