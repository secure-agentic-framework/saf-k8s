# Static-only positive fixture. This Terraform is never initialized, planned, or applied.
resource "aws_s3_bucket" "saf_lab_public_acl" {
  bucket = "saf-k8s-0606-023-inert-fixture"
  acl    = "private"
}
