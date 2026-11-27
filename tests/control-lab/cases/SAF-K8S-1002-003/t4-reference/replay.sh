#!/usr/bin/env bash
set -euo pipefail
lab=$1
[[ $(hostname) =~ ^saf-dcgm-t4-[0-9]{10}$ ]]
[[ "$lab" == /home/*/saf-t4-lab ]]
[[ -x /usr/local/bin/k3s-uninstall.sh && -s "$lab/evidence/run-1/framebuffer.log" ]]
grep -Fxq FRAMEBUFFER_WITNESS_PASS "$lab/evidence/run-1/framebuffer.log"
old=$(k3s kubectl get node "$(hostname)" -o jsonpath='{.metadata.uid}')
[[ -n "$old" ]]
/usr/local/bin/k3s-uninstall.sh
[[ ! -e /var/lib/rancher/k3s/server/db ]]
bash "$lab/guest-bootstrap.executed.sh"
new=$(k3s kubectl get node "$(hostname)" -o jsonpath='{.metadata.uid}')
[[ -n "$new" && "$new" != "$old" ]]
printf 'INDEPENDENT_CLUSTER_PASS fresh Kubernetes node UID and datastore\n'
bash "$lab/deploy-and-baseline.sh"
bash "$lab/measure-framebuffer.sh" run-2
