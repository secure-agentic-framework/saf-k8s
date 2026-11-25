# SAF-K8S-0702-026 Pipeline classification taxonomy

```sh
python3 lab.py test SAF-K8S-0702-026 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0702-026.md)
requires a defined and maintained classification taxonomy across pipeline data
flows. Three Kubernetes Jobs consume synthetic taxonomy documents mounted
from immutable ConfigMaps. The validator rejects a duplicate synonym and a
missing handling rule, then accepts separate complete revisions. A later
consumer can select version 1.1.0 while the original version remains
available. The fixture shows where to record definitions, handling rules,
owners, reviewers, and approval references.

Production verification requires the approved taxonomy, its real owners and
review history, and its coverage across ETL, training, and serving stages.
The separate [label propagation](../SAF-K8S-0702-027/README.md) and
[admission](../SAF-K8S-0702-028/README.md) cases demonstrate downstream usage.

- [Kubernetes v1.36 ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/)
- [Kubernetes v1.36 Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/)

## Adopter verification

1. Produce the organization-approved taxonomy with named owner, approver, version, effective date, review interval, data categories, synonyms, and handling rule for each category.
2. Demonstrate that ETL, preprocessing, feature engineering, training, checkpoint, and serving stages use the same approved version or a documented compatible version.
3. Retain versioned approval and change history. Verify consumers resolve the chosen revision and that prior definitions remain available where records or reproducibility require them.
4. Link the approved production taxonomy and stage coverage evidence to the in-cluster consumer proof. The synthetic categories only validate structure; they do not define the organization's classification values.
