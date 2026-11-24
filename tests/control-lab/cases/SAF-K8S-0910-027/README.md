# SAF-K8S-0910-027 admission-policy drift and repair

Run `python3 lab.py test SAF-K8S-0910-027` from the control-lab directory.

Two separately owned Kubernetes API servers begin on the same native
admission baseline. A scoped actor changes only the remote binding from Deny
to Warn. The test observes the actual mismatch and the resulting admission
decision while the healthy member keeps denying. A distinct reconciler
restores the baseline with bounded, version-conditional writes. An independent
consumer checks the restored binding, both rejection paths, and both permitted
paths. Probes are gated from scheduling.

The fixture covers this repair cycle. Deployed coverage, periodic detection,
alert delivery, and temporary exception governance require separate evidence.
