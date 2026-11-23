# SAF-K8S-0905-006

Run `python3 lab.py test SAF-K8S-0905-006`. The fixture compares persisted
notices after walking only the immediate lineage with notices after walking
the full fixed graph. Kubernetes keeps the fixture PVC pending while an
active Pod references it, then releases it. The retained archive bytes and
notice are checked after logical deletion. Backing data erasure, external
registry integration and deployed ML-BOM coverage require separate evidence.
