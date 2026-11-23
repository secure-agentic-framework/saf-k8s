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
