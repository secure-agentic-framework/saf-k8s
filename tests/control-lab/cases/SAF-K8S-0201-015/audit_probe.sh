#!/usr/bin/env bash
# Run only inside the fresh, isolated fixture VM.
set -euo pipefail
export LC_ALL=C
test "$(id -u)" = 0
test "$(systemd-detect-virt)" = apple
test "$(auditctl -l)" = "No rules"
systemctl is-active --quiet auditd
auditctl -s | awk '$1 == "enabled" && $2 == 1 {enabled=1} $1 == "pid" && $2 > 0 {daemon=1} END {exit !(enabled && daemon)}'

fixture=$(mktemp -d /var/tmp/saf-kubelet-audit.XXXXXXXX)
key="saf${fixture##*.}"
mkdir "$fixture/pki"
paths=("$fixture/config.yaml" "$fixture/kubeconfig" "$fixture/pki/synthetic-cert.pem")
heartbeat="$fixture/heartbeat"
for path in "${paths[@]}" "$heartbeat"; do
  printf 'synthetic fixture only\n' > "$path"
done

rules=()
install_rule() {
  local path=$1 permission=$2 rule_key=$3
  auditctl -w "$path" -p "$permission" -k "$rule_key"
  rules+=("$path" "$permission" "$rule_key")
}
cleanup() {
  local rc=$? i removed=true
  for ((i=0;i<${#rules[@]};i+=3)); do
    auditctl -W "${rules[i]}" -p "${rules[i+1]}" -k "${rules[i+2]}" || removed=false
  done
  test "$(auditctl -l)" = "No rules" || removed=false
  rm -f -- "${paths[@]}" "$heartbeat"
  rmdir -- "$fixture/pki" "$fixture"
  printf '{"rules_removed":%s}\n' "$removed"
  test "$removed" = true || rc=1
  exit "$rc"
}
trap cleanup EXIT

touch_paths() {
  local path
  for path in "${paths[@]}"; do
    /usr/bin/cat "$path" > /dev/null
    printf 'inert test content\n' | /usr/bin/tee "$path" > /dev/null
  done
}
expect_event() {
  local path=$1 process=$2 rule_key=$3 count
  for ((count=0; count<12; count++)); do
    if ausearch --input-logs --key "$rule_key" --file "$path" --comm "$process" \
       --success yes --just-one --raw 2>/dev/null | grep '^type=SYSCALL ' > /dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}
install_rule "$heartbeat" w "${key}_heartbeat"
touch_paths
printf 'collector ready\n' | /usr/bin/tee "$heartbeat" > /dev/null
expect_event "$heartbeat" tee "${key}_heartbeat"
for path in "${paths[@]}"; do
  if result=$(ausearch --input-logs --file "$path" --just-one 2>&1); then
    echo "unwatched operation unexpectedly produced an audit event" >&2
    exit 1
  fi
  test "$result" = '<no matches>'
done
printf '{"baseline_unwatched":true,"collector_canary_logged":true}\n'

indices=(0 1 2)
for i in "${indices[@]}"; do
  install_rule "${paths[i]}" rw "${key}_$i"
done
loaded=$(auditctl -l)
for i in "${indices[@]}"; do
  grep -F -- "-w ${paths[i]} -p rw -k ${key}_$i" <<< "$loaded" > /dev/null
done
touch_paths
for i in "${indices[@]}"; do
  expect_event "${paths[i]}" cat "${key}_$i"
  expect_event "${paths[i]}" tee "${key}_$i"
done
auditctl -s | awk '$1 == "lost" && $2 == 0 {found=1} END {exit !found}'
printf '{"watched_config_read_write":true,"watched_kubeconfig_read_write":true,"watched_pki_read_write":true,"no_audit_loss":true}\n'
