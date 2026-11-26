#!/bin/sh
set -eu
export AWS_EC2_METADATA_DISABLED=true AWS_PAGER=""
export AWS_CONFIG_FILE=/tmp/saf-s3-replica.ini
printf '%s\n' '[default]' 's3 =' '    addressing_style = path' > "$AWS_CONFIG_FILE"

s3_source() {
  aws --endpoint-url "$SOURCE_ENDPOINT_URL" --cli-connect-timeout 3 --cli-read-timeout 8 \
    --region us-east-1 s3api "$@"
}
s3_replica() {
  AWS_ACCESS_KEY_ID="$REPLICA_AWS_ACCESS_KEY_ID" \
  AWS_SECRET_ACCESS_KEY="$REPLICA_AWS_SECRET_ACCESS_KEY" \
    aws --endpoint-url "$REPLICA_ENDPOINT_URL" --cli-connect-timeout 3 --cli-read-timeout 8 \
      --region us-east-1 s3api "$@"
}
digest() { sha256sum "$1" | cut -d ' ' -f 1; }
error_code() { sed -n 's/^.*An error occurred (\([A-Za-z0-9]*\)) .*$/\1/p' "$1" | head -n 1; }
valid_version() {
  test "$1" != None && test "$1" != null &&
    printf '%s\n' "$1" | grep -Eq '^[A-Za-z0-9._~+=/-]+$'
}

if [ "${1:-}" = recover ]; then
  until s3_replica list-buckets >/tmp/replica-ready 2>&1; do sleep 1; done
  valid_version "$REPLICA_VERSION_ID"
  s3_replica get-object --bucket "$REPLICA_BUCKET" --key "$REPLICA_KEY" \
    --version-id "$REPLICA_VERSION_ID" /tmp/replica-recovered.jsonl >/dev/null
  mode=$(s3_replica get-object-retention --bucket "$REPLICA_BUCKET" --key "$REPLICA_KEY" \
    --version-id "$REPLICA_VERSION_ID" --query 'Retention.Mode' --output text)
  until=$(s3_replica get-object-retention --bucket "$REPLICA_BUCKET" --key "$REPLICA_KEY" \
    --version-id "$REPLICA_VERSION_ID" --query 'Retention.RetainUntilDate' --output text)
  test "$(digest /tmp/replica-recovered.jsonl)" = "$EXPECTED_SHA256"
  test "$mode" = COMPLIANCE && test "$until" = "$REPLICA_RETAIN_UNTIL"
  printf '{"exact_replica_version":true,"content_digest_matches":true,'
  printf '"replica_retention_unchanged":true,"replica_version_id":"%s"}\n' "$REPLICA_VERSION_ID"
  exit 0
fi

# Wait for verified application readiness on each case-owned endpoint.
for attempt in 1 2 3 4 5 6 7 8; do
  if s3_source list-buckets >/tmp/source-ready 2>&1 &&
     s3_replica list-buckets >/tmp/replica-ready 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [ "${ready:-false}" != true ]; then
  echo 'A case-owned S3 endpoint did not confirm application readiness' >&2
  exit 1
fi

# A separate gateway and PVC are the receiver for a client-mediated protected copy.
s3_replica create-bucket --bucket "$REPLICA_BUCKET" --object-lock-enabled-for-bucket >/dev/null
config=$(printf '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":%s}}}' \
  "$REPLICA_RETENTION_DAYS")
s3_replica put-object-lock-configuration --bucket "$REPLICA_BUCKET" \
  --object-lock-configuration "$config" >/dev/null
replica_mode=$(s3_replica get-object-lock-configuration --bucket "$REPLICA_BUCKET" \
  --query 'ObjectLockConfiguration.Rule.DefaultRetention.Mode' --output text)
replica_days=$(s3_replica get-object-lock-configuration --bucket "$REPLICA_BUCKET" \
  --query 'ObjectLockConfiguration.Rule.DefaultRetention.Days' --output text)
replica_versioning=$(s3_replica get-bucket-versioning --bucket "$REPLICA_BUCKET" \
  --query Status --output text)
if [ "$replica_mode" != COMPLIANCE ] || [ "$replica_days" != "$REPLICA_RETENTION_DAYS" ] \
   || [ "$replica_versioning" != Enabled ]; then
  echo 'Independent replica bucket did not enable versioning and the expected synthetic retention default' >&2
  exit 1
fi

# This key is intentionally absent before promotion; retain the exact miss code as baseline evidence.
if s3_replica head-object --bucket "$REPLICA_BUCKET" --key "$REPLICA_KEY" \
  >/tmp/replica-baseline.out 2>/tmp/replica-baseline.err; then
  echo 'Independent replica unexpectedly contained the object before copy' >&2
  exit 1
fi
baseline_error=$(error_code /tmp/replica-baseline.err)
case "$baseline_error" in 404|NoSuchKey|NoSuchVersion|NotFound) ;; *)
  printf 'Unexpected replica baseline status (%s)\n' "$baseline_error" >&2; exit 1;; esac

# Read only the exact protected source version, verify bytes, and write them to a different gateway.
s3_source get-object --bucket "$SOURCE_BUCKET" --key "$SOURCE_KEY" \
  --version-id "$SOURCE_VERSION_ID" /tmp/source-event.jsonl >/dev/null
source_digest=$(digest /tmp/source-event.jsonl)
test "$source_digest" = "$EXPECTED_SHA256"
replica_version_id=$(s3_replica put-object --bucket "$REPLICA_BUCKET" --key "$REPLICA_KEY" \
  --body /tmp/source-event.jsonl --query VersionId --output text)
valid_version "$replica_version_id"
s3_replica get-object --bucket "$REPLICA_BUCKET" --key "$REPLICA_KEY" \
  --version-id "$replica_version_id" /tmp/replica-copy.jsonl >/dev/null
replica_digest=$(digest /tmp/replica-copy.jsonl)
mode=$(s3_replica get-object-retention --bucket "$REPLICA_BUCKET" --key "$REPLICA_KEY" \
  --version-id "$replica_version_id" --query 'Retention.Mode' --output text)
retain_until=$(s3_replica get-object-retention --bucket "$REPLICA_BUCKET" --key "$REPLICA_KEY" \
  --version-id "$replica_version_id" --query 'Retention.RetainUntilDate' --output text)
source_epoch=$(date -u -d "$SOURCE_RETAIN_UNTIL" +%s)
replica_epoch=$(date -u -d "$retain_until" +%s)
test "$mode" = COMPLIANCE && test "$replica_epoch" -ge "$source_epoch"
test "$replica_digest" = "$EXPECTED_SHA256"
if s3_replica delete-object --bucket "$REPLICA_BUCKET" --key "$REPLICA_KEY" \
  --version-id "$replica_version_id" >/tmp/replica-delete.out 2>/tmp/replica-delete.err; then
  echo 'Early deletion of the protected independent replica unexpectedly succeeded' >&2
  exit 1
fi
replica_delete_error=$(error_code /tmp/replica-delete.err)
case "$replica_delete_error" in AccessDenied|InvalidRequest) ;; *)
  printf 'Unexpected protected replica delete result (%s)\n' "$replica_delete_error" >&2; exit 1;; esac
s3_replica get-object --bucket "$REPLICA_BUCKET" --key "$REPLICA_KEY" \
  --version-id "$replica_version_id" /tmp/replica-after-delete-denial.jsonl >/dev/null
test "$(digest /tmp/replica-after-delete-denial.jsonl)" = "$EXPECTED_SHA256"
printf '{"replica_baseline_absent":true,"baseline_error":"%s",' "$baseline_error"
printf '"source_exact_version_read":true,"replica_exact_version_read":true,'
printf '"replica_content_matches":true,"replica_mode":"%s",' "$mode"
printf '"replica_retention_covers_source":true,"replica_delete_denied":true,'
printf '"replica_delete_error":"%s","replica_version_survived_denial":true,' "$replica_delete_error"
printf '"replica_version_id":"%s","replica_retain_until":"%s"}\n' "$replica_version_id" "$retain_until"
