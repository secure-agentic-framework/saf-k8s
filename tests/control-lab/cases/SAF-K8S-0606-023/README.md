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

The case performs static scanning on local fixtures. Deployed CI policy,
approval protections, broader rules and template coverage, other IaC
engines, and integration with production infrastructure require separate
evidence.

- [Checkov 3.3.16 policy](https://github.com/bridgecrewio/checkov/blob/3.3.16/checkov/terraform/checks/graph_checks/aws/S3PublicACLRead.yaml)
- [Kubernetes v1.36 Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/)
