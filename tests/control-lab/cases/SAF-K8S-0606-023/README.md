# SAF-K8S-0606-023 IaC scanning as a promotion gate

Run from the SAF-K8S framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-023 --docker-context desktop-linux
```

Checkov 3.3.16 scans two inert Terraform files using CKV_AWS_20. The
public ACL fixture produces the exact failed rule and process exit 1.
The private ACL fixture passes the same rule and exits 0.
The runner retains both original scanner reports.

A separate Job uses its fixture ServiceAccount to read the actual scanner
Job and matches its terminal condition, image, and immutable input
reference. The Job computes the SHA-256 of the mounted Terraform file and
compares it with the scan evidence. It withholds the marker after the
failed scan and creates an inert ConfigMap tied to the clean scan and
the matching digest after the successful scan.

The case performs static scanning on local fixtures. Its adopter procedure
covers the actual CI gate, approval protections, rules, and deployment
paths for each configured format.

- [Checkov 3.3.16 policy](https://github.com/bridgecrewio/checkov/blob/3.3.16/checkov/terraform/checks/graph_checks/aws/S3PublicACLRead.yaml)
- [Kubernetes v1.36 Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/)

## CloudFormation comparison

The same pinned scanner and selected rule evaluate two inert CloudFormation templates. The native Jobs must verify the expected failing and passing exit status and resource report. A separate promotion Job checks the scanner Job identity and exact mounted template digest. The failing input leaves its marker absent, and the successful input produces an immutable marker for that exact template hash. The cases use the local Kubernetes API and deploy only fixture marker ConfigMaps.

## Digest mismatch

A separate promotion Job supplies a changed artifact digest while preserving
the clean scan Job lookup and original mounted bytes. It withholds the
release marker for that mismatched digest.

## Adopter verification

Inventory the languages and repositories that the actual deployment workflow accepts. For each, record the scanner and rule revision, required severity gates, artifact identity, authorized exceptions and deployment identity. Verify a harmless failing change blocks the approved path, an approved passing change promotes the exact scanned bytes, and unrelated artifacts or bypass paths are refused. Record Pulumi separately when it is in scope, along with the actual CI workflow and approval requirements.
