# SAF-K8S-0601-019 runtime exposure monitoring and exception governance

`python3 tests/control-lab/lab.py test SAF-K8S-0601-019 --docker-context desktop-linux`

An owned Kind API reports two actual running containers. The baseline has neither
a monitoring role nor a report. The enabled inventory reader lists Pods in the
fixture namespace through Kubernetes authorization and is refused access to Secrets.
An inert HIGH finding is correlated to the actual Pod UID and runtime image ID.
An unrelated Pod and an incorrect image ID fail that correlation.

The test records a governed short exception and results for wrong-scope, expired,
premature, overlong, and self-approved inputs. An independent identity can record
review on the fixture ConfigMap. The workload owner cannot make that patch. The
reviewed report keeps the alert visible, and the ordinary workload continues running.

This case covers one inventory read, one synthetic advisory, and one fixture report.
The deployment evidence still needs actual scanner cadence, dependency detection,
fleet coverage, alert delivery, authenticated reviewer controls, expiry, and remediation.
