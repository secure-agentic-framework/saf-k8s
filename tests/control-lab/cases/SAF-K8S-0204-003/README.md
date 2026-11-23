# SAF-K8S-0204-003 Container filesystem drift

The case ties two Kind Jobs to the same built image and approved file digest. It detects a harmless real change in the comparison Job, observes write refusal and unchanged content in the read-only Job, and verifies the separately approved writable volume in both.

Production sensor coverage, anomaly classification, alert delivery and workload exceptions require further deployment evidence.

```sh
python3 lab.py test SAF-K8S-0204-003 --docker-context desktop-linux
```
