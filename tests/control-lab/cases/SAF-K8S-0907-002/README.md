# SAF-K8S-0907-002 training-data privacy

Run `python3 lab.py test SAF-K8S-0907-002` from the control-lab directory.

This case uses invented records only. It compares an unchecked writer and a
classified intake that minimizes the approved training data and holds an
unapproved version. An independent Pod examines the resulting files. Distinct
non-root, read-only readers make actual file requests. Their observed Linux
UID, Pod service account, dataset version and decision appear in scoped
Kubernetes Pod logs. Only the designated auditor can query both reader logs
under the fixture Role. Actual Kubernetes ConfigMap reads separately check
RBAC for metadata access.

The fixture provisions local filesystem modes and checks Pod-level application
events. Deployed object or storage audit, Kubernetes API-server audit, identity
custody, authorization, de-identification evaluation, and log integrity and
retention need separate evidence.

## Purpose and derivative approval

An immutable, separately pinned policy binds an approved source dataset and
digest, an explicit purpose, a processor identity and a minimized derivative
version and digest. The case checks the approved path and holds requests with
the wrong purpose, source version, parent digest or workload identity. A
separate read-only Pod verifies the exact derivative and absence of the
invented identifiers. The processor may read the named policy ConfigMap
through Kubernetes RBAC and cannot update it.

For the adopted system, verify the actual approval and classification
authority, original and derivative storage paths, trainer purpose
enforcement, data access and provider audit evidence, and residual
disclosure and re-identification risk.
