# SAF-K8S-0804-005 Modeled release policy and actual access scope

A modeled appraisal gates a RoleBinding for a public fixture ConfigMap. The test verifies that expired and mismatched results leave the marker inaccessible, the intended subject can retrieve only its marker, and revocation denies later reads. It never creates a Secret, reads service account credentials or uses a TEE, cloud KMS or external broker.
