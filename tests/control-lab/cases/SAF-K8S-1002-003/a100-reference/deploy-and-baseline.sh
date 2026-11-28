#!/usr/bin/env bash
set -euo pipefail
umask 077
here=$(cd -- "$(dirname -- "$0")" && pwd)
[[ $(hostname) =~ ^saf-a100-[0-9]{10}$ ]]
k() { /usr/local/bin/k3s kubectl "$@"; }
evidence="$here/evidence"
mkdir -p "$evidence"
node=$(k get nodes -o jsonpath='{.items[0].metadata.name}')
[[ $(k get node "$node" -o jsonpath='{.status.allocatable.nvidia\.com/gpu}') == 1 ]]
k get namespace saf-gpu-a100 >/dev/null 2>&1 && { printf 'Unexpected pre-existing workload namespace\n' >&2; exit 1; }
k apply -f "$here/fixtures/prometheus.yaml"
k -n saf-gpu-observe apply -f "$here/fixtures/dcgm-exporter-rendered.yaml"
k -n saf-gpu-observe rollout status daemonset/dcgm-exporter --timeout=10m
k -n saf-gpu-observe rollout status deployment/saf-prometheus --timeout=10m
k -n saf-gpu-observe port-forward --address 127.0.0.1 service/saf-prometheus 19091:9090 > "$evidence/baseline-forward.log" 2>&1 &
forward=$!
trap 'kill "$forward" 2>/dev/null || true' EXIT
up=0
for _ in $(seq 1 25); do
    if curl --fail --silent --max-time 2 -G http://127.0.0.1:19091/api/v1/query --data-urlencode 'query=up{job="saf-a100-dcgm"}' > "$evidence/baseline-up.raw.json"; then
        if python3 - "$evidence/baseline-up.raw.json" <<'PY'
import json,sys
with open(sys.argv[1]) as f:
    response = json.load(f)
items = response['data']['result']
sys.exit(0 if len(items)==1 and items[0]['value'][1]=='1' else 1)
PY
        then up=1; break; fi
    fi
    sleep 2
done
[[ "$up" == 1 ]]
curl --fail --silent --max-time 4 -G http://127.0.0.1:19091/api/v1/query \
  --data-urlencode 'query=DCGM_FI_DEV_GPU_UTIL{namespace="saf-gpu-a100",pod="a100-vector-witness"}' > "$evidence/baseline-workload.raw.json"
python3 - "$evidence/baseline-workload.raw.json" <<'PY'
import json,sys
with open(sys.argv[1]) as f:
    response = json.load(f)
assert response['status']=='success' and response['data']['result']==[]
print('BASELINE_PASS exporter scrape target up, zero series for the absent case workload')
PY
k apply -f "$here/fixtures/a100-vector-witness.yaml"
k -n saf-gpu-a100 wait pod/a100-vector-witness --for=condition=Ready --timeout=10m
for _ in $(seq 1 45); do
  k -n saf-gpu-a100 logs pod/a100-vector-witness -c vector --tail=10 > "$evidence/vector-first.log"
  if grep -Eq '^vectorAdd_test_passed_iteration=[0-9]+$' "$evidence/vector-first.log"; then break; fi
  sleep 2
done
grep -Eq '^vectorAdd_test_passed_iteration=[0-9]+$' "$evidence/vector-first.log"
printf 'WORKLOAD_PASS '
tail -n 1 "$evidence/vector-first.log"
