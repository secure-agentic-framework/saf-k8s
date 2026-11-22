# SAF-K8S-0606-023 source review

The pinned control at revision 133a8698a45e2b335b51728bf4c62f7bda98d15f
requires a CI scan for staging and production infrastructure templates and
a promotion gate that blocks findings.

Checkov 3.3.16 includes CKV_AWS_20 for public S3 bucket ACLs. The lab scans
two inert Terraform inputs which differ in the fixture ACL and verifies the
actual check ID, resource address, file, Job condition and container exit
status. The passing comparison exercises the same check. [Versioned policy](https://github.com/bridgecrewio/checkov/blob/3.3.16/checkov/terraform/checks/graph_checks/aws/S3PublicACLRead.yaml)

The independent promotion Job reads the scanner Job using a scoped namespace
ServiceAccount. It checks the terminal condition, scanner image, immutable
input, and Terraform SHA-256 before deciding. Only the clean scan reaches the
case-owned marker. [Kubernetes v1.36 Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/)

This demonstrates one Terraform rule and the fixture promotion path.
Production CI, enforced scanner coverage and review policies, evidence source
integrity, and deployment integration require separate evidence. Workflows
for Pulumi and CloudFormation remain outside this fixture.
