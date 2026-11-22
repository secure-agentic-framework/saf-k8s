#!/bin/sh
set -eu
export AWS_EC2_METADATA_DISABLED=true AWS_PAGER=""
export AWS_CONFIG_FILE=/tmp/saf-s3-client.ini
printf '%s\n' '[default]' 's3 =' '    addressing_style = path' > "$AWS_CONFIG_FILE"
s3() { aws --endpoint-url "$AWS_ENDPOINT_URL" --cli-connect-timeout 3 --cli-read-timeout 5 s3api "$@"; }
deadline() { date -u -d "$created_at +$1 days" '+%Y-%m-%dT%H:%M:%SZ'; }
key() { printf 'ai-logs/%s/%s-%s.jsonl' "$1" "$RUN_ID" "$2"; }
retention() { s3 get-object-retention --bucket "$S3_BUCKET" --key "$1" --version-id "$2" --output json | tr -d '\n'; }

append_record() {
  item_key=$(key "$1" "$2")
  item_version=$(s3 put-object --bucket "$S3_BUCKET" --key "$item_key" --body "/fixture/$2.jsonl" \
    --object-lock-mode COMPLIANCE --object-lock-retain-until-date "$(deadline "$3")" --query VersionId --output text)
  test "$item_version" != None && test "$item_version" != null
  printf '%s\n' "$item_version" | grep -Eq '^[A-Za-z0-9._~+=/-]+$'
  printf '%s' "$item_version"
}

inspect_record() {
  item_key=$(key "$1" "$2")
  item_version="$3"
  s3 get-object --bucket "$S3_BUCKET" --key "$item_key" --version-id "$item_version" "/tmp/$2.jsonl" >/dev/null
  printf '%s.key=%s\n' "$2" "$item_key"
  printf '%s.version=%s\n' "$2" "$item_version"
  printf '%s.retention=%s\n' "$2" "$(retention "$item_key" "$item_version")"
  printf '%s.bytes=%s\n' "$2" "$(base64 -w 0 "/tmp/$2.jsonl")"
}

attempt=0
until s3 list-buckets >/tmp/gateway-ready 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 25 ]; then tail -n 4 /tmp/gateway-ready >&2; exit 1; fi
  sleep 1
done

s3 create-bucket --bucket "$S3_BUCKET" --object-lock-enabled-for-bucket >/dev/null
created_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf 'created_at=%s\n' "$created_at"
audit_version=$(append_record audit audit "$AUDIT_INITIAL_DAYS")
training_version=$(append_record training training "$TRAINING_DAYS")
inference_version=$(append_record inference inference "$INFERENCE_DAYS")
audit_key=$(key audit audit)
printf 'audit.initial=%s\n' "$(retention "$audit_key" "$audit_version")"
s3 put-object-retention --bucket "$S3_BUCKET" --key "$audit_key" --version-id "$audit_version" \
  --retention "Mode=COMPLIANCE,RetainUntilDate=$(deadline "$AUDIT_CORRECTED_DAYS")" >/dev/null
new_audit_version=$(append_record audit audit-next "$AUDIT_CORRECTED_DAYS")

inspect_record audit audit "$audit_version"
inspect_record audit audit-next "$new_audit_version"
inspect_record training training "$training_version"
inspect_record inference inference "$inference_version"
