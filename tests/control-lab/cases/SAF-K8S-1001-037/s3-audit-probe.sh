#!/bin/sh
set -eu
export AWS_EC2_METADATA_DISABLED=true AWS_PAGER=""
export AWS_CONFIG_FILE=/tmp/saf-s3-client.ini
printf '%s\n' '[default]' 's3 =' '    addressing_style = path' > "$AWS_CONFIG_FILE"

s3() { aws --endpoint-url "$AWS_ENDPOINT_URL" --cli-connect-timeout 3 --cli-read-timeout 5 s3api "$@"; }
digest() { sha256sum "$1" | cut -d ' ' -f 1; }
error_code() { sed -n 's/^.*An error occurred (\([A-Za-z0-9]*\)) .*$/\1/p' "$1"; }
version() {
  test "$1" != None && test "$1" != null &&
    printf '%s\n' "$1" | grep -Eq '^[A-Za-z0-9._~+=/-]+$'
}

attempt=0
until s3 list-buckets >/tmp/gateway-ready 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 25 ]; then
    tail -n 4 /tmp/gateway-ready >&2
    exit 1
  fi
  sleep 1
done

s3 create-bucket --bucket "$S3_BUCKET" --object-lock-enabled-for-bucket >/dev/null
unlocked_key="$S3_KEY-unlocked-control"
unlocked=$(s3 put-object --bucket "$S3_BUCKET" --key "$unlocked_key" \
  --body /fixture/audit-event.jsonl --query VersionId --output text)
version "$unlocked"
s3 get-object --bucket "$S3_BUCKET" --key "$unlocked_key" --version-id "$unlocked" /tmp/audit-control.jsonl >/dev/null
unlocked_digest=$(digest /tmp/audit-control.jsonl)
test "$unlocked_digest" = "$EXPECTED_SHA256"
s3 delete-object --bucket "$S3_BUCKET" --key "$unlocked_key" --version-id "$unlocked" >/dev/null
if s3 head-object --bucket "$S3_BUCKET" --key "$unlocked_key" --version-id "$unlocked" >/tmp/unlocked-head 2>&1; then
  echo 'Unlocked exact version remained after version-specific delete' >&2
  exit 1
fi
unlocked_error=$(error_code /tmp/unlocked-head)
case "$unlocked_error" in 404|NotFound|NoSuchKey|NoSuchVersion) ;; *) cat /tmp/unlocked-head >&2; exit 1;; esac

expiry=$(date -u -d '+2 days' '+%Y-%m-%dT%H:%M:%SZ')
locked=$(s3 put-object --bucket "$S3_BUCKET" --key "$S3_KEY" \
  --body /fixture/audit-event.jsonl --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date "$expiry" --query VersionId --output text)
version "$locked"
s3 get-object --bucket "$S3_BUCKET" --key "$S3_KEY" --version-id "$locked" /tmp/audit-before.jsonl >/dev/null
before=$(digest /tmp/audit-before.jsonl)
test "$before" = "$EXPECTED_SHA256"

retention() { s3 get-object-retention --bucket "$S3_BUCKET" --key "$S3_KEY" --version-id "$locked" \
  --query 'Retention.[Mode,RetainUntilDate]' --output text; }
locked_retention=$(retention)
mode=$(printf '%s' "$locked_retention" | awk '{print $1}')
retain_until=$(printf '%s' "$locked_retention" | awk '{print $2}')
test "$mode" = COMPLIANCE
test "$(date -u -d "$retain_until" +%s)" = "$(date -u -d "$expiry" +%s)"
test "$(date -u -d "$retain_until" +%s)" -gt "$(date -u +%s)"
shorter=$(date -u -d '+1 day' '+%Y-%m-%dT%H:%M:%SZ')
if s3 put-object-retention --bucket "$S3_BUCKET" --key "$S3_KEY" --version-id "$locked" \
    --retention "Mode=COMPLIANCE,RetainUntilDate=$shorter" >/tmp/shorten 2>&1; then
  echo 'A shorter retention period was accepted' >&2
  exit 1
fi
shorten_error=$(error_code /tmp/shorten)
case "$shorten_error" in AccessDenied|InvalidRequest|ObjectLockConfigurationNotFoundError) ;;
  *) cat /tmp/shorten >&2; exit 1;; esac
test "$(retention)" = "$locked_retention"

# An ordinary write gets a new version and leaves the archived bytes intact.
printf '%s\n' '{"fixture":"distinct synthetic successor"}' > /tmp/successor.jsonl
new_version=$(s3 put-object --bucket "$S3_BUCKET" --key "$S3_KEY" --body /tmp/successor.jsonl \
  --query VersionId --output text)
version "$new_version"
test "$new_version" != "$locked"
s3 get-object --bucket "$S3_BUCKET" --key "$S3_KEY" /tmp/current.jsonl >/dev/null
current=$(digest /tmp/current.jsonl)
test "$current" = "$(digest /tmp/successor.jsonl)"
test "$current" != "$before"

if s3 delete-object --bucket "$S3_BUCKET" --key "$S3_KEY" --version-id "$locked" >/tmp/locked-delete 2>&1; then
  echo 'Permanent deletion of a retained version unexpectedly succeeded' >&2
  exit 1
fi
locked_error=$(error_code /tmp/locked-delete)
case "$locked_error" in AccessDenied|InvalidRequest) ;; *) cat /tmp/locked-delete >&2; exit 1;; esac

marker_record=$(s3 delete-object --bucket "$S3_BUCKET" --key "$S3_KEY" --query '[DeleteMarker,VersionId]' --output text)
marker_flag=$(printf '%s' "$marker_record" | awk '{print $1}')
marker=$(printf '%s' "$marker_record" | awk '{print $2}')
test "$marker_flag" = True || test "$marker_flag" = true
version "$marker"
test "$marker" != "$new_version" && test "$marker" != "$locked"
if s3 get-object --bucket "$S3_BUCKET" --key "$S3_KEY" /tmp/hidden.jsonl >/tmp/hidden-get 2>&1; then
  echo 'Unversioned lookup did not observe the delete marker' >&2
  exit 1
fi
hidden_error=$(error_code /tmp/hidden-get)
case "$hidden_error" in 404|NotFound|NoSuchKey) ;; *) cat /tmp/hidden-get >&2; exit 1;; esac
s3 get-object --bucket "$S3_BUCKET" --key "$S3_KEY" --version-id "$locked" /tmp/audit-after.jsonl >/dev/null
after=$(digest /tmp/audit-after.jsonl)
test "$after" = "$before"
test "$(retention)" = "$locked_retention"

# All interpolated fields are generated digests, dates, version IDs or API error codes.
printf '%s\n' '{'
printf '  "versions":{"unlocked":"%s","locked":"%s","successor":"%s","delete_marker":"%s"},\n' "$unlocked" "$locked" "$new_version" "$marker"
printf '  "sha256":{"unlocked":"%s","locked_before":"%s","visible_successor":"%s","locked_after":"%s"},\n' "$unlocked_digest" "$before" "$current" "$after"
printf '  "retention":{"mode":"%s","configured_until":"%s","observed_until":"%s","shorter_until":"%s"},\n' "$mode" "$expiry" "$retain_until" "$shorter"
printf '  "api_errors":{"unlocked_version":"%s","retention_shortening":"%s","locked_delete":"%s","current_without_version":"%s"}\n' "$unlocked_error" "$shorten_error" "$locked_error" "$hidden_error"
printf '%s\n' '}'
