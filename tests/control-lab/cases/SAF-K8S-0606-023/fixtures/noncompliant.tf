# Static-only fixture. This Terraform is intentionally unsafe for scanner evaluation
# and is never initialized, planned, applied, or connected to an AWS account.
resource "aws_s3_bucket" "saf_lab_public_acl" {
  bucket = "saf-k8s-0606-023-inert-fixture"
  acl    = "public-read"
}
