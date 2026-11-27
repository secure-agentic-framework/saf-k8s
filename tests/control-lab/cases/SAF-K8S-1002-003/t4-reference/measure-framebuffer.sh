#!/usr/bin/env bash
set -euo pipefail
umask 077
here=$(cd -- "$(dirname -- "$0")" && pwd)
[[ $(hostname) =~ ^saf-dcgm-t4-[0-9]{10}$ ]]
[[ ${1:-} =~ ^(run-1|run-2)$ ]]
run=$1
out="$here/evidence/$run"
mkdir -p "$out"
exe="$here/fixtures/framebuffer-witness-linux-amd64"
[[ -s "$exe" ]]
worker=''
cleanup() {
  if [[ -n "$worker" ]]; then kill "$worker" 2>/dev/null || true; fi
}
trap cleanup EXIT
capture() {
  local phase=$1
  python3 -B "$here/capture/capture_t4.py" --kubeconfig /etc/rancher/k3s/k3s.yaml \
    --output-root "$here/capture/$run/$phase" | tee "$out/$phase.json"
}
framebuffer() {
  python3 - "$here/capture/validate_dcgm_receipt.py" "$out/$1.json" <<'PY'
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[1]).parent))
from validate_dcgm_receipt import validate
pointer=json.loads(Path(sys.argv[2]).read_text())
receipt=json.loads((Path(pointer['capture_directory'])/'receipt.json').read_text())
validated=validate(receipt)
sample,=[s for s in validated['samples'] if s['metric']=='DCGM_FI_DEV_FB_USED']
assert sample['uid_binding']=='direct_pod_uid_label'
print(sample['direct_value'],sample['prometheus_value'])
PY
}
cp "$here/evidence/baseline-up.raw.json" "$here/evidence/baseline-workload.raw.json" "$here/evidence/vector-first.log" "$out/"
capture idle
printf 'IDLE_FRAMEBUFFER_MIB '; framebuffer idle
sha256sum "$exe" | awk '{print $1}' > "$out/framebuffer-binary.sha256"
k3s kubectl -n saf-gpu-t4 exec -i pod/t4-vector-witness -c vector -- /bin/sh -c \
    'umask 077; p=/tmp/saf-framebuffer-witness; cat > "$p"; chmod 700 "$p"; exec "$p"' \
    < "$exe" > "$out/framebuffer.log" 2>&1 &
worker=$!
for _ in $(seq 1 20); do
  if grep -Fxq framebuffer_witness_allocated_bytes=134217728 "$out/framebuffer.log"; then break; fi
  if ! kill -0 "$worker" 2>/dev/null; then tail -n 6 "$out/framebuffer.log" >&2; wait "$worker"; fi
  sleep 1
done
grep -Fx framebuffer_witness_allocated_bytes=134217728 "$out/framebuffer.log"
# The pinned exporter uses a 30s hardware collection cadence; leave time for
# one fresh collection before the separate Prometheus scrape.
sleep 35
capture allocated
printf 'ALLOCATED_FRAMEBUFFER_MIB '; framebuffer allocated
python3 - "$out/idle.json" "$out/allocated.json" <<'PY'
import json,sys
from pathlib import Path

def frame(path):
    pointer = json.loads(Path(path).read_text())
    receipt=json.loads((Path(pointer['capture_directory'])/'receipt.json').read_text())
    record,=[s for s in receipt['prometheus_query']['selected_results'] if s['metric']=='DCGM_FI_DEV_FB_USED']
    query=record['api_response']['data']['result'][0]['values']
    direct,=[s for s in receipt['exporter_exposition']['selected_lines'] if s.startswith('DCGM_FI_DEV_FB_USED{')]
    timestamp, value=query[-1]
    return (receipt['pod_after']['uid'],receipt['hardware']['gpu_uuid'],float(direct.rsplit(' ',1)[1]),float(value),timestamp)

idle, allocated=map(frame,sys.argv[1:])
assert allocated[:2]==idle[:2]
assert allocated[2]>=idle[2]+128 and allocated[3]>=idle[3]+128,(idle[2:4],allocated[2:4])
assert allocated[4]>idle[4]
print('FRAMEBUFFER_CHANGE_PASS both independent observations increased at least 128 MiB on the same Pod and GPU')
PY
wait "$worker"
worker=''
grep -Fx FRAMEBUFFER_WITNESS_PASS "$out/framebuffer.log"
