"""Scan fixture files and OCI layers, then promote by exact artifact digest."""
import base64
import json
from pathlib import Path
import subprocess
from time import monotonic, sleep

ROOT = Path(__file__).resolve().parent
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
TRIVY = "ghcr.io/aquasecurity/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"
CLAIM = "saf-0403-scan-input"
SCAN = "saf-0403-trivy"
PROMOTE = "saf-0403-promote"
OBSERVE = "saf-0403-observe-promotion"

SCAN_SCRIPT = r'''set -eu
marker="$(printf '%s_%s_%s_%s' 'training' 'sample' 'synthetic' 'only')"
mkdir -p /tmp/cache /out/results
printf 'rules:\n  - id: saf-public-fixture-marker\n    category: general\n    title: Public synthetic fixture marker\n    severity: LOW\n    keywords:\n      - "%s"\n    regex: "%s"\n' "$marker" "$marker" > /tmp/rules.yml
printf '%s\n' 'rules: [' > /tmp/invalid.yml
cp /out/input/green.json /out/input/changed.json
scan() {
  name="$1"; mode="$2"; file="$3"; config="$4"
  artifact="/out/input/$file"
  target="$artifact"
  before="$(sha256sum "$artifact" | cut -d ' ' -f1)"
  if [ "$mode" = image ]; then
    target="/tmp/$name"
    mkdir "$target"
    tar -xf "$artifact" -C "$target"
    set -- --input "$target"
  else
    set -- "$target"
  fi
  set +e
  trivy "$mode" --quiet --scanners secret --secret-config "$config" \
    --skip-db-update --skip-java-db-update --offline-scan --skip-version-check --disable-telemetry \
    --cache-dir /tmp/cache --format template \
    --template '{{ range . }}{{ range .Secrets }}{{ println .RuleID }}{{ end }}{{ end }}' \
    --exit-code 17 "$@" > "/tmp/$name.rules" 2> "/tmp/$name.stderr"
  rc=$?
  set -e
  after="$(sha256sum "$artifact" | cut -d ' ' -f1)"
  state=error
  if [ "$before" = "$after" ]; then
    if [ "$rc" = 0 ] && [ ! -s "/tmp/$name.rules" ]; then state=clean; fi
    if [ "$rc" = 17 ] && grep -Fxq saf-public-fixture-marker "/tmp/$name.rules"; then state=finding; fi
  fi
  printf '%s %s\n' "$state" "$before" > "/out/results/$name"
  printf '%s=%s\n' "$name" "$state"
}
scan file-red fs red.json /tmp/rules.yml
scan file-green fs green.json /tmp/rules.yml
scan image-red image red.oci.tar /tmp/rules.yml
scan image-green image green.oci.tar /tmp/rules.yml
scan invalid-rules fs green.json /tmp/invalid.yml
scan changed fs changed.json /tmp/rules.yml
# A clean file changes after its scan, before the separate promoter sees it.
printf '\n' >> /out/input/changed.json
'''

PROMOTION_CASES = {
    "file-red": "red.json", "file-green": "green.json", "image-red": "red.oci.tar",
    "image-green": "green.oci.tar", "invalid-rules": "green.json", "changed": "changed.json",
}

PROMOTER = r'''import hashlib, json, pathlib, re, sys
root = pathlib.Path('/out')
output = root / 'promotion'
output.mkdir()
decisions = {}
for name, filename in json.loads(sys.argv[1]).items():
    scan = root / 'results' / name
    observation = scan.read_text().split() if scan.is_file() else []
    verdict = 'denied_scanner_error'
    if len(observation) == 2 and re.fullmatch('[a-f0-9]{64}', observation[1]):
        state, digest = observation
        if state == 'finding':
            verdict = 'denied_finding'
        elif state == 'clean':
            data = (root / 'input' / filename).read_bytes()
            verdict = 'denied_digest_mismatch'
            if hashlib.sha256(data).hexdigest() == digest:
                (output / name).write_bytes(data)
                verdict = 'promoted'
    decisions[name] = verdict
(output / 'decisions.json').write_text(json.dumps(decisions, sort_keys=True))
'''

OBSERVER = r'''import hashlib, json, pathlib, sys
root = pathlib.Path('/out')
outputs = root / 'promotion'
decisions = json.loads((outputs / 'decisions.json').read_text())
observed = {}
for name, filename in json.loads(sys.argv[1]).items():
    artifact = outputs / name
    evidence = {'decision': decisions.get(name), 'exists': artifact.is_file(), 'exact_bytes': False}
    if artifact.is_file():
        approved = (root / 'results' / name).read_text().split()[1]
        data = artifact.read_bytes()
        evidence['exact_bytes'] = (hashlib.sha256(data).hexdigest() == approved
                                    and data == (root / 'input' / filename).read_bytes())
    observed[name] = evidence
print(json.dumps(observed, sort_keys=True))
'''


def workload(name, image, command, *, read_only=False, scanner=False):
    mounts = [{"name": "artifacts", "mountPath": "/out", "readOnly": read_only}]
    if scanner:
        mounts.append({"name": "cache", "mountPath": "/tmp"})
    return {"name": name, "image": image, "command": command, "imagePullPolicy": "IfNotPresent",
            "resources": {"requests": {"cpu": "25m", "memory": "64Mi"},
                          "limits": {"cpu": "500m", "memory": "384Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}}, "volumeMounts": mounts}


def create_job(lab, name, main, *, init=None):
    volumes = [{"name": "artifacts", "persistentVolumeClaim": {"claimName": CLAIM}}]
    spec = {"restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "fsGroup": 1000,
                                "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [main], "volumes": volumes}
    if init:
        spec["initContainers"] = [init]
        volumes.append({"name": "cache", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}})
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 135, "ttlSecondsAfterFinished": 420,
                         "template": {"spec": spec}}})
    deadline = monotonic() + 145
    while monotonic() < deadline:
        state = json.loads(lab.kubectl("get", "job", name, "-o", "json", timeout=15).stdout) or {}
        statuses = {x.get("type") for x in (state.get("status", {}).get("conditions") or []) if x.get("status") == "True"}
        if "Complete" in statuses:
            return
        if "Failed" in statuses:
            break
        sleep(1)
    lab.block(f"Fixture Job {name} did not complete within its deadline")


def safe_log(lab, name, container):
    result = subprocess.run(["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                             "-n", "saf-test", "logs", f"job/{name}", "-c", container], env=lab.env,
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        lab.block(f"Sanitized fixture status for {name} could not be read")
    return result.stdout


def run(lab):
    lab.create({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": CLAIM},
                "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "32Mi"}}}})
    arch = json.loads(lab.kubectl("get", "nodes", "-o", "json", timeout=15).stdout)["items"][0]["status"]["nodeInfo"]["architecture"]
    generator = workload("generator", IMAGE, ["python", "-c", (ROOT / "oci_fixture.py").read_text(), "/out/input", arch])
    scanner = workload("trivy", TRIVY, ["/bin/sh", "-c", SCAN_SCRIPT], scanner=True)
    create_job(lab, SCAN, scanner, init=generator)
    cases = json.dumps(PROMOTION_CASES)
    create_job(lab, PROMOTE, workload("promoter", IMAGE, ["python", "-c", PROMOTER, cases]))
    create_job(lab, OBSERVE, workload("observer", IMAGE, ["python", "-c", OBSERVER, cases], read_only=True))
    scans = dict(line.split("=", 1) for line in safe_log(lab, SCAN, "trivy").strip().splitlines())
    proof = json.loads(safe_log(lab, OBSERVE, "observer"))
    for kind in ("file", "image"):
        red = f"{kind}-red"
        green = f"{kind}-green"
        flagged = (scans.get(red) == "finding"
                   and proof.get(red) == {"decision": "denied_finding", "exists": False, "exact_bytes": False})
        lab.check("red", f"Trivy detects the fixture marker in the {kind} and promotion is denied",
                  flagged, {"expected_rule_matched_and_artifact_absent": flagged})
        clean = (scans.get(green) == "clean"
                 and proof.get(green) == {"decision": "promoted", "exists": True, "exact_bytes": True})
        lab.check("green", f"The clean {kind} is promoted byte-for-byte against its scan digest",
                  clean, {"clean_scan_and_exact_artifact_present": clean})
    errored = (scans.get("invalid-rules") == "error"
               and proof.get("invalid-rules") == {"decision": "denied_scanner_error", "exists": False, "exact_bytes": False})
    lab.check("positive", "Malformed scanner rules produce an error and the release remains withheld",
              errored, {"scanner_error_and_artifact_absent": errored})
    changed = (scans.get("changed") == "clean"
               and proof.get("changed") == {"decision": "denied_digest_mismatch", "exists": False, "exact_bytes": False})
    lab.check("green", "Promotion rejects a file whose bytes changed after a successful scan",
              changed, {"digest_mismatch_and_artifact_absent": changed})
    marker = "_".join(("training", "sample", "synthetic", "only")).encode()
    excludes = all(not any(value in path.read_bytes() for value in (marker, base64.b64encode(marker)))
                   for path in lab.evidence.rglob("*") if path.is_file())
    lab.check("positive", "Evidence excludes complete fixture marker bytes",
              excludes, {"plaintext_and_encoded_marker_absent": excludes})
