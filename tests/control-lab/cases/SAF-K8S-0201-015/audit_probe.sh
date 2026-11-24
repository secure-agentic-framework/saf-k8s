#!/usr/bin/env bash
# Watch only the files created in this case's mount-free disposable guest.
set -euo pipefail
export LC_ALL=C
test "$(id -u)" = 0
test "$(systemd-detect-virt)" = apple
test "$(auditctl -l)" = "No rules"
systemctl is-active --quiet auditd
auditctl -s | awk '$1=="enabled" && $2==1 {enabled=1} $1=="pid" && $2>0 {daemon=1} END {exit !(enabled && daemon)}'

fixture=$(mktemp -d /var/tmp/saf-kubelet-audit.XXXXXXXX)
key="saf${fixture##*.}"
unit=saf-audit-check
persistent=/etc/audit/rules.d/81-saf-fixture.rules
test ! -e "$persistent"
test ! -e "/run/systemd/system/$unit.timer"
mkdir "$fixture/pki"
paths=("$fixture/config.yaml" "$fixture/kubeconfig" "$fixture/pki/synthetic-cert.pem")
kinds=(config kubeconfig pki)
heartbeat="$fixture/heartbeat"
for path in "${paths[@]}" "$heartbeat"; do
  printf 'synthetic fixture only\n' > "$path"
done

cleanup() {
  local rc=$? removed=true
  systemctl stop "$unit.timer" "$unit.service" >/dev/null 2>&1 || true
  rm -f -- "/run/systemd/system/$unit.timer" "/run/systemd/system/$unit.service" "$persistent"
  systemctl daemon-reload
  auditctl -W "$heartbeat" -p w -k "${key}_heartbeat" >/dev/null 2>&1 || true
  augenrules --load >/dev/null 2>&1 || removed=false
  test "$(auditctl -l)" = "No rules" || removed=false
  test ! -e "$persistent" || removed=false
  rm -f -- "${paths[@]}" "$heartbeat" "$fixture/check" "$fixture/samples" "$fixture/expected"
  rmdir -- "$fixture/pki" "$fixture"
  printf '{"rules_removed":%s}\n' "$removed"
  test "$removed" = true || rc=1
  exit "$rc"
}
trap cleanup EXIT

auditd_version=$(dpkg-query -W -f='${Version}' auditd)
auditctl_version=$(auditctl -v | awk '{print $NF}')
arch=$(uname -m)
kernel=$(uname -r)
printf '{"platform":{"package":"%s","auditctl":"%s","architecture":"%s","kernel":"%s","rule_form":"legacy-file-watch"}}\n' \
  "$auditd_version" "$auditctl_version" "$arch" "$kernel"

touch_paths() {
  local path
  for path in "${paths[@]}"; do
    /usr/bin/cat "$path" > /dev/null
    printf 'inert test content\n' | /usr/bin/tee "$path" > /dev/null
  done
}

event() {
  local path=$1 process=$2 rule_key=$3 kind=$4 operation=$5 result line serial arch_id syscall symbol flags i
  for ((i=0; i<16; i++)); do
    if result=$(ausearch --input-logs --key "$rule_key" --file "$path" --comm "$process" \
         --success yes --just-one --raw 2>/dev/null) && grep -q '^type=PATH ' <<< "$result"; then
      line=$(awk '/^type=SYSCALL / {print; exit}' <<< "$result")
      if [[ $line =~ msg=audit\([0-9.]+:([0-9]+)\):\ arch=([[:xdigit:]]+)\ syscall=([0-9]+)\ success=yes ]]; then
        serial=${BASH_REMATCH[1]} arch_id=${BASH_REMATCH[2]} syscall=${BASH_REMATCH[3]}
        symbol=$(ausyscall "$syscall")
        case "$symbol" in
          open) [[ $line =~ [[:space:]]a1=([[:xdigit:]]+) ]] ;;
          openat) [[ $line =~ [[:space:]]a2=([[:xdigit:]]+) ]] ;;
          *) echo "Unexpected synthetic fixture syscall $symbol" >&2; return 1 ;;
        esac
        flags=${BASH_REMATCH[1]}
        if [[ $operation == read ]]; then
          (( (16#$flags & 3) == 0 ))
        else
          (( (16#$flags & 3) == 1 || (16#$flags & 3) == 2 ))
        fi
        printf '{"event":{"serial":"%s","kind":"%s","operation":"%s","success":true,"syscall":"%s","kernel_arch":"%s","marker_key":"%s"}}\n' \
          "$serial" "$kind" "$operation" "$symbol" "$arch_id" "$rule_key"
        return 0
      fi
    fi
    sleep 1
  done
  echo "No qualifying $operation event for synthetic marker $kind" >&2
  return 1
}

auditctl -w "$heartbeat" -p w -k "${key}_heartbeat"
touch_paths
printf 'collector ready\n' | /usr/bin/tee "$heartbeat" > /dev/null
event "$heartbeat" tee "${key}_heartbeat" heartbeat write
for path in "${paths[@]}"; do
  if result=$(ausearch --input-logs --file "$path" --just-one 2>&1); then
    echo "Unwatched operation unexpectedly produced a marker event" >&2
    exit 1
  fi
  test "$result" = '<no matches>'
done
printf '{"baseline_unwatched":true,"collector_canary_logged":true}\n'

for i in 0 1 2; do
  printf -- '-w %s -p rw -k %s_%s\n' "${paths[i]}" "$key" "$i"
done > "$fixture/expected"
install -m 0600 "$fixture/expected" "$persistent"
augenrules --load
cat > "$fixture/check" <<'TIMER'
#!/usr/bin/env bash
set -euo pipefail
fixture=$1
active=$(auditctl -l)
index=0
missing=none
while IFS= read -r rule; do
  if ! grep -Fxq -- "$rule" <<< "$active"; then
    missing=${missing/none/}
    missing="${missing}$index"
  fi
  index=$((index+1))
done < "$fixture/expected"
printf '%s %s\n' "$INVOCATION_ID" "$missing" >> "$fixture/samples"
TIMER
chmod 0700 "$fixture/check"
touch "$fixture/samples"
printf '[Service]\nType=oneshot\nExecStart=%s/check %s\n' "$fixture" "$fixture" > "/run/systemd/system/$unit.service"
cat > "/run/systemd/system/$unit.timer" <<'TIMER'
[Timer]
OnActiveSec=1s
OnUnitActiveSec=2s
AccuracySec=100ms
TIMER
systemctl daemon-reload
systemctl start "$unit.timer"

sample() {
  local after=$1 desired=$2 attempt
  for ((attempt=0; attempt<22; attempt++)); do
    match=$(awk -v after="$after" -v state="$desired" 'NR>after && $2==state {print NR, $1; exit}' "$fixture/samples")
    if [[ -n $match ]]; then
      printf '%s\n' "$match"
      return 0
    fi
    sleep 1
  done
  return 1
}
read -r seq_ok invocation_ok < <(sample 0 none)
auditctl -W "${paths[1]}" -p rw -k "${key}_1"
read -r seq_gap invocation_gap < <(sample "$seq_ok" 1)
augenrules --load
read -r seq_restored invocation_restored < <(sample "$seq_gap" none)
test "$invocation_ok" != "$invocation_gap"
test "$invocation_ok" != "$invocation_restored"
test "$invocation_gap" != "$invocation_restored"
systemctl is-active --quiet "$unit.timer"
printf '{"recurrence":{"initial":{"invocation":"%s","sequence":%s,"missing":0},"drift":{"invocation":"%s","sequence":%s,"missing":1,"kind":"kubeconfig"},"restored":{"invocation":"%s","sequence":%s,"missing":0},"restored_from_persistent_source":true}}\n' \
  "$invocation_ok" "$seq_ok" "$invocation_gap" "$seq_gap" "$invocation_restored" "$seq_restored"

touch_paths
for i in 0 1 2; do
  event "${paths[i]}" cat "${key}_$i" "${kinds[i]}" read
  event "${paths[i]}" tee "${key}_$i" "${kinds[i]}" write
done
auditctl -s | awk '$1=="lost" && $2==0 {found=1} END {exit !found}'
printf '{"watched_config_read_write":true,"watched_kubeconfig_read_write":true,"watched_pki_read_write":true,"no_audit_loss":true}\n'
