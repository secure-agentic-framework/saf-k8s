# Verify GPU telemetry triage rules on Kind

```sh
python3 lab.py test SAF-K8S-0703-022 --docker-context desktop-linux
```

Prometheus scrapes two owned fixture endpoints and evaluates actual rules.
High synthetic activity alone includes an approved fixture. The correlated
rules preserve two distinct review reasons for missing and inconsistent
approval context. The approved high-activity fixture remains observable.

Hardware telemetry, production coverage, alert delivery and confirmed
incident dispositions require separate evidence.
