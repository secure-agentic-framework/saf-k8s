#!/bin/sh
set -eu
export AWS_EC2_METADATA_DISABLED=true AWS_PAGER=""
export AWS_CONFIG_FILE=/tmp/saf-s3-client.ini
printf '%s\n' '[default]' 's3 =' '    addressing_style = path' > "$AWS_CONFIG_FILE"
bucket=saf-k8s-0701-009
locked_bucket=saf-k8s-0701-009-lock
s3() { aws --endpoint-url "$AWS_ENDPOINT_URL" --cli-connect-timeout 3 --cli-read-timeout 5 s3api "$@"; }
same_bytes() {
  actual=$(sha256sum "$1")
  expected=$(sha256sum "$2")
  test "${actual%% *}" = "${expected%% *}"
}

attempt=0
until s3 list-buckets >/tmp/gateway-ready 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 25 ]; then
    printf '%s\n' 'The signed ListBuckets readiness check did not succeed' >&2
    tail -n 3 /tmp/gateway-ready >&2
    exit 1
  fi
  sleep 1
done

echo "Signed bucket listing succeeded"
baseline=baseline/feature.txt
s3 create-bucket --bucket "$bucket" >/dev/null
s3 put-object --bucket "$bucket" --key "$baseline" --body /fixture/baseline-v1.txt >/dev/null
s3 put-object --bucket "$bucket" --key "$baseline" --body /fixture/baseline-v2.txt >/dev/null
s3 get-object --bucket "$bucket" --key "$baseline" /tmp/baseline-current.txt >/dev/null
same_bytes /tmp/baseline-current.txt /fixture/baseline-v2.txt
s3 delete-object --bucket "$bucket" --key "$baseline" >/dev/null
if s3 head-object --bucket "$bucket" --key "$baseline" >/tmp/baseline-head 2>&1; then
  echo 'Unlocked object is readable after deletion' >&2
  exit 1
fi
grep -Eq '\((404|NotFound|NoSuchKey)\)' /tmp/baseline-head || { cat /tmp/baseline-head >&2; exit 1; }

echo "Unlocked overwrite and deletion verified"
s3 create-bucket --bucket "$locked_bucket" --object-lock-enabled-for-bucket >/dev/null
expiry=$(date -u -d '+2 days' '+%Y-%m-%dT%H:%M:%SZ')
for label in dataset artifact; do
  printf "Checking the retained %s version\n" "$label"
  key="training/$label.txt"
  v1=$(s3 put-object --bucket "$locked_bucket" --key "$key" --body "/fixture/$label-v1.txt" \
        --object-lock-mode COMPLIANCE --object-lock-retain-until-date "$expiry" --query VersionId --output text)
  test -n "$v1" && test "$v1" != None && test "$v1" != null
  mode=$(s3 get-object-retention --bucket "$locked_bucket" --key "$key" --version-id "$v1" \
         --query Retention.Mode --output text)
  test "$mode" = COMPLIANCE
  s3 get-object --bucket "$locked_bucket" --key "$key" --version-id "$v1" /tmp/locked-before >/dev/null
  same_bytes /tmp/locked-before "/fixture/$label-v1.txt"
  v2=$(s3 put-object --bucket "$locked_bucket" --key "$key" --body "/fixture/$label-v2.txt" \
        --object-lock-mode COMPLIANCE --object-lock-retain-until-date "$expiry" --query VersionId --output text)
  test -n "$v2" && test "$v2" != None && test "$v2" != null && test "$v1" != "$v2"
  s3 get-object --bucket "$locked_bucket" --key "$key" /tmp/locked-current >/dev/null
  same_bytes /tmp/locked-current "/fixture/$label-v2.txt"
  s3 get-object --bucket "$locked_bucket" --key "$key" --version-id "$v1" /tmp/locked-after >/dev/null
  same_bytes /tmp/locked-after "/fixture/$label-v1.txt"

  # The same credential can remove an unlocked version in this bucket.
  unlocked="$key-unlocked"
  control_version=$(s3 put-object --bucket "$locked_bucket" --key "$unlocked" \
          --body "/fixture/$label-v1.txt" --query VersionId --output text)
  test -n "$control_version" && test "$control_version" != None && test "$control_version" != null
  s3 delete-object --bucket "$locked_bucket" --key "$unlocked" --version-id "$control_version" >/dev/null
  if s3 head-object --bucket "$locked_bucket" --key "$unlocked" --version-id "$control_version" \
          >/tmp/unlocked-version-head 2>&1; then
    echo 'Unlocked version is readable after deletion' >&2
    exit 1
  fi
  grep -Eq '\((404|NotFound|NoSuchKey|NoSuchVersion)\)' /tmp/unlocked-version-head || { cat /tmp/unlocked-version-head >&2; exit 1; }

  if s3 delete-object --bucket "$locked_bucket" --key "$key" --version-id "$v1" >/tmp/locked-delete 2>&1; then
    echo 'Permanent deletion of a locked version succeeded' >&2
    exit 1
  fi
  grep -Eqi 'AccessDenied|ObjectLock|retention' /tmp/locked-delete || { cat /tmp/locked-delete >&2; exit 1; }
  marker=$(s3 delete-object --bucket "$locked_bucket" --key "$key" --query DeleteMarker --output text)
  test "$marker" = True || test "$marker" = true
  if s3 get-object --bucket "$locked_bucket" --key "$key" /tmp/locked-hidden >/tmp/hidden-get 2>&1; then
    echo 'Unversioned lookup still reaches the hidden key' >&2
    exit 1
  fi
  grep -Eq '\((404|NotFound|NoSuchKey)\)' /tmp/hidden-get || { cat /tmp/hidden-get >&2; exit 1; }
  s3 get-object --bucket "$locked_bucket" --key "$key" --version-id "$v1" /tmp/locked-after-delete >/dev/null
  same_bytes /tmp/locked-after-delete "/fixture/$label-v1.txt"
done

printf '%s\n' '{"baseline":{"overwrite_visible":true,"deleted":true},"dataset":{"versioning":{"new_current_version":true,"prior_unchanged":true,"retention_mode":"COMPLIANCE"},"retention":{"permanent_delete_denied":true,"delete_marker_created":true,"locked_version_still_readable":true}},"artifact":{"versioning":{"new_current_version":true,"prior_unchanged":true,"retention_mode":"COMPLIANCE"},"retention":{"permanent_delete_denied":true,"delete_marker_created":true,"locked_version_still_readable":true}}}'
