#!/bin/sh
set -eu
export AWS_EC2_METADATA_DISABLED=true AWS_PAGER=""
export AWS_CONFIG_FILE=/tmp/saf-s3-client.ini
printf '%s\n' '[default]' 's3 =' '    addressing_style = path' > "$AWS_CONFIG_FILE"

s3() {
  aws --endpoint-url "$AWS_ENDPOINT_URL" --cli-connect-timeout 3 --cli-read-timeout 8 \
    --region us-east-1 s3api "$@"
}
digest() { sha256sum "$1" | cut -d ' ' -f 1; }
error_code() { sed -n 's/^.*An error occurred (\([A-Za-z0-9]*\)) .*$/\1/p' "$1" | head -n 1; }
valid_version() {
  test "$1" != None && test "$1" != null &&
    printf '%s\n' "$1" | grep -Eq '^[A-Za-z0-9._~+=/-]+$'
}

attempt=0
until s3 list-buckets >/tmp/gateway-ready 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    printf "Owned gateway readiness failed (%s)\n" "$(error_code /tmp/gateway-ready)" >&2
    exit 1
  fi
  sleep 1
done

created_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
required_until=$(date -u -d "$created_at +$REQUIRED_DAYS days" '+%Y-%m-%dT%H:%M:%SZ')
shorter_until=$(date -u -d "$created_at +1 day" '+%Y-%m-%dT%H:%M:%SZ')
s3 create-bucket --bucket "$S3_BUCKET" --object-lock-enabled-for-bucket >/dev/null

# This matching control version is written before the bucket receives its default rule.
unlocked_key="$S3_KEY-unlocked-counterpart"
unlocked_version=$(s3 put-object --bucket "$S3_BUCKET" --key "$unlocked_key" \
  --body /fixture/audit-event.jsonl --query VersionId --output text)
valid_version "$unlocked_version"
s3 get-object --bucket "$S3_BUCKET" --key "$unlocked_key" --version-id "$unlocked_version" \
  /tmp/unlocked-before.jsonl >/dev/null
unlocked_digest=$(digest /tmp/unlocked-before.jsonl)

default_config=$(printf '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":%s}}}' \
  "$DEFAULT_DAYS")
s3 put-object-lock-configuration --bucket "$S3_BUCKET" \
  --object-lock-configuration "$default_config" >/dev/null
default_mode=$(s3 get-object-lock-configuration --bucket "$S3_BUCKET" \
  --query 'ObjectLockConfiguration.Rule.DefaultRetention.Mode' --output text)
default_days=$(s3 get-object-lock-configuration --bucket "$S3_BUCKET" \
  --query 'ObjectLockConfiguration.Rule.DefaultRetention.Days' --output text)

case "$default_mode" in COMPLIANCE|GOVERNANCE) ;; *)
  printf 'Bucket default mode was absent or invalid (%s)\n' "$default_mode" >&2; exit 1;; esac
case "$default_days" in ''|*[!0-9]*)
  printf 'Bucket default retention days were absent or invalid (%s)\n' "$default_days" >&2; exit 1;; esac

locked_version=$(s3 put-object --bucket "$S3_BUCKET" --key "$S3_KEY" \
  --body /fixture/audit-event.jsonl --query VersionId --output text)
valid_version "$locked_version"
s3 get-object --bucket "$S3_BUCKET" --key "$S3_KEY" --version-id "$locked_version" \
  /tmp/locked-before.jsonl >/dev/null
locked_digest=$(digest /tmp/locked-before.jsonl)
effective_mode=$(s3 get-object-retention --bucket "$S3_BUCKET" --key "$S3_KEY" \
  --version-id "$locked_version" --query 'Retention.Mode' --output text)
retain_until=$(s3 get-object-retention --bucket "$S3_BUCKET" --key "$S3_KEY" \
  --version-id "$locked_version" --query 'Retention.RetainUntilDate' --output text)
test -n "$retain_until"

# Delete the identical unlocked version and independently confirm it is no longer addressable.
test "$unlocked_digest" = "$EXPECTED_SHA256"
test "$locked_digest" = "$EXPECTED_SHA256"
s3 delete-object --bucket "$S3_BUCKET" --key "$unlocked_key" \
  --version-id "$unlocked_version" >/dev/null
unlocked_deleted=true
if s3 head-object --bucket "$S3_BUCKET" --key "$unlocked_key" --version-id "$unlocked_version" \
  >/tmp/unlocked-head 2>&1; then
  echo 'Deleted unlocked version remained addressable' >&2
  exit 1
fi
unlocked_status=$(error_code /tmp/unlocked-head)
case "$unlocked_status" in 404|NoSuchKey|NoSuchVersion|NotFound) ;; *)
  printf "Unexpected unlocked-version lookup status (%s)\n" "$unlocked_status" >&2; exit 1;; esac

# Capture only the API error code; never emit request credentials or full error text.
if s3 delete-object --bucket "$S3_BUCKET" --key "$S3_KEY" --version-id "$locked_version" \
  >/tmp/locked-delete.out 2>/tmp/locked-delete.err; then
  locked_delete_denied=false
  locked_delete_error=none
  echo 'Early deletion of the protected version unexpectedly succeeded' >&2
  exit 1
else
  locked_delete_denied=true
  locked_delete_error=$(error_code /tmp/locked-delete.err)
fi
case "$locked_delete_error" in AccessDenied|InvalidRequest) ;; *)
  printf "Unexpected protected-version delete status (%s)\n" "$locked_delete_error" >&2; exit 1;; esac

if s3 put-object-retention --bucket "$S3_BUCKET" --key "$S3_KEY" \
  --version-id "$locked_version" \
  --retention "Mode=COMPLIANCE,RetainUntilDate=$shorter_until" \
  >/tmp/shorten.out 2>/tmp/shorten.err; then
  shorten_denied=false
  shorten_error=none
  echo 'Shortening the protected version unexpectedly succeeded' >&2
  exit 1
else
  shorten_denied=true
  shorten_error=$(error_code /tmp/shorten.err)
fi
case "$shorten_error" in AccessDenied|InvalidRequest) ;; *)
  printf "Unexpected retention shortening status (%s)\n" "$shorten_error" >&2; exit 1;; esac
mode_after=$(s3 get-object-retention --bucket "$S3_BUCKET" --key "$S3_KEY" \
  --version-id "$locked_version" --query 'Retention.Mode' --output text)
until_after=$(s3 get-object-retention --bucket "$S3_BUCKET" --key "$S3_KEY" \
  --version-id "$locked_version" --query 'Retention.RetainUntilDate' --output text)
test "$effective_mode" = "$mode_after" && test "$retain_until" = "$until_after"

# A normal put creates a new current version; exact-version retrieval must return the source bytes.
printf '%s\n' '{"fixture":"benign synthetic successor"}' > /tmp/successor.jsonl
successor_digest=$(digest /tmp/successor.jsonl)
successor_version=$(s3 put-object --bucket "$S3_BUCKET" --key "$S3_KEY" \
  --body /tmp/successor.jsonl --query VersionId --output text)
valid_version "$successor_version"
test "$successor_version" != "$locked_version"
s3 get-object --bucket "$S3_BUCKET" --key "$S3_KEY" /tmp/current.jsonl >/dev/null
current_digest=$(digest /tmp/current.jsonl)
s3 get-object --bucket "$S3_BUCKET" --key "$S3_KEY" --version-id "$locked_version" \
  /tmp/locked-after.jsonl >/dev/null
locked_after_digest=$(digest /tmp/locked-after.jsonl)
test "$current_digest" = "$successor_digest"
test "$locked_after_digest" = "$EXPECTED_SHA256"

# Only synthetic identifiers, hashes, timestamps, and S3 error codes enter this output.
printf '{\n'
printf '  "bucket_default":{"mode":"%s","days":%s},\n' "$default_mode" "$default_days"
printf '  "required_until":"%s",\n' "$required_until"
printf '  "effective_retention":{"mode":"%s","retain_until":"%s","version_id":"%s"},\n' \
  "$effective_mode" "$retain_until" "$locked_version"
printf '  "unlocked_counterpart":{"version_id":"%s","source_sha256":"%s",' \
  "$unlocked_version" "$unlocked_digest"
printf '"deleted":%s,"after_delete_status":"%s"},\n' "$unlocked_deleted" "$unlocked_status"
printf '  "protected_version":{"delete_denied":%s,"delete_error":"%s",' \
  "$locked_delete_denied" "$locked_delete_error"
printf '"shorten_denied":%s,"shorten_error":"%s",' "$shorten_denied" "$shorten_error"
printf '"retention_unchanged":%s},\n' true
printf '  "replacement":{"version_id":"%s","successor_sha256":"%s",' \
  "$successor_version" "$successor_digest"
printf '"current_sha256":"%s","original_sha256":"%s"}\n' \
  "$current_digest" "$locked_after_digest"
printf '}\n'
