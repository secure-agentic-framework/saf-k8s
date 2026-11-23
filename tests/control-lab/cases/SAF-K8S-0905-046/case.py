"""Kubernetes fixture for training/build artifact signature verification."""
import base64
import hashlib
import json
import time

IMAGE = "docker.io/alpine/openssl:3.3.2@sha256:5008e829163320a6e8166883c03e68189e8925ade68cde36584dc2a41cfa5248"
PYTHON_IMAGE = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
NS = "saf-test"
IDENTITY = "spiffe://saf.example.test/ml/training/build-pipeline"
FILES = ("input-manifest.json", "intermediate.json", "model.json", "release.json", "provenance.json")
SCOPE = ("Disposable Kind v1.36.1; restricted builder, isolated signer and separate verifier Jobs. Synthetic input manifest, intermediate, model, packaged release and provenance record are signed with an ephemeral OpenSSL key generated only inside the signer pod. Verifier checks signatures, bounded identity and actual bytes; disabled signature, tampered model and wrong-key probes must fail. Does not prove production key custody, signer-to-pipeline binding, external producer authenticity, durable storage or production CI/CD adoption.")

def cm(name, *, data=None, binary=None):
    obj = {"apiVersion":"v1", "kind":"ConfigMap", "metadata":{"name":name,"namespace":NS}}
    if data is not None: obj["data"] = data
    if binary is not None: obj["binaryData"] = {k:base64.b64encode(v).decode() for k,v in binary.items()}
    return obj

def job(name, script, mounts, volumes, env=None, image=IMAGE):
    return {"apiVersion":"batch/v1","kind":"Job","metadata":{"name":name,"namespace":NS},"spec":{"backoffLimit":0,"activeDeadlineSeconds":90,"ttlSecondsAfterFinished":300,"template":{"metadata":{"labels":{"app":name}},"spec":{"restartPolicy":"Never","automountServiceAccountToken":False,"securityContext":{"runAsNonRoot":True,"runAsUser":1000,"fsGroup":1000,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":name,"image":image,"imagePullPolicy":"IfNotPresent","command":["/bin/sh","-c",script],"env":env or [],"resources":{"requests":{"cpu":"10m","memory":"16Mi"},"limits":{"cpu":"100m","memory":"64Mi"}},"securityContext":{"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]}},"volumeMounts":mounts}],"volumes":volumes}}}}

def wait(lab, name):
    until=time.monotonic()+100
    while time.monotonic()<until:
        j=json.loads(lab.kubectl("get","job",name,"-o","json").stdout)
        states={c["type"] for c in j.get("status",{}).get("conditions",[]) if c.get("status")=="True"}
        if "Complete" in states: return True
        if "Failed" in states: return False
        time.sleep(.5)
    lab.block(f"Job {name} timed out")

def logs(lab,name):
    pods=json.loads(lab.kubectl("get","pods","-l",f"job-name={name}","-o","json").stdout)["items"]
    if len(pods)!=1: lab.block(f"Job {name} did not have exactly one pod")
    return lab.kubectl("logs",pods[0]["metadata"]["name"]).stdout

def block(log, start, end):
    if start not in log or end not in log: raise ValueError("bounded fixture output absent")
    return dict(row.split("=",1) for row in log.split(start,1)[1].split(end,1)[0].splitlines() if "=" in row)

BUILDER = r'''set -eu; mkdir -p /out
python -B - <<'PY'
import base64
import hashlib
import json
from pathlib import Path
source = Path('/input/input-manifest.json').read_bytes()
data = json.loads(source)
rows = data['records']
xs = [float(row['x']) for row in rows]; ys = [float(row['y']) for row in rows]
mx = sum(xs) / len(xs); my = sum(ys) / len(ys)
w = sum((x-mx)*(y-my) for x,y in zip(xs,ys)) / sum((x-mx)**2 for x in xs)
b = my - w*mx
intermediate = json.dumps({'weight': w, 'bias': b}, sort_keys=True, separators=(',', ':')).encode()
model = json.dumps({'algorithm':'linear-regression-v1', 'parameters':json.loads(intermediate)}, sort_keys=True, separators=(',', ':')).encode()
release = json.dumps({'format': 'fixture-release-v1', 'model': json.loads(model)}, sort_keys=True, separators=(',', ':')).encode()
provenance = json.dumps({'pipeline':'fixture-v1', 'identity':'spiffe://saf.example.test/ml/training/build-pipeline', 'input_sha256':hashlib.sha256(source).hexdigest(), 'model_sha256':hashlib.sha256(model).hexdigest(), 'release_sha256':hashlib.sha256(release).hexdigest()}, sort_keys=True, separators=(',', ':')).encode()
files = {'input-manifest.json':source, 'intermediate.json':intermediate, 'model.json':model, 'release.json':release, 'provenance.json':provenance}
for name, raw in files.items(): Path('/out', name).write_bytes(raw)
print('BUILD_BEGIN')
for name, raw in files.items(): print(name + '=' + base64.b64encode(raw).decode())
print('BUILD_END')
PY
'''

SIGNER = r'''set -eu; umask 077; mkdir -p /key /out
if [ "${SIGNING_ENABLED:-true}" = false ]; then echo 'SIGNING_DISABLED_NO_SIGNATURES'; exit 0; fi
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /key/private.pem 2>/dev/null; openssl pkey -in /key/private.pem -pubout -out /out/public.pem 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /key/untrusted.pem 2>/dev/null; openssl pkey -in /key/untrusted.pem -pubout -out /out/untrusted-public.pem 2>/dev/null
printf 'SIGN_BEGIN\npublic='; base64 /out/public.pem|tr -d '\n'; printf '\nwrong_public='; base64 /out/untrusted-public.pem|tr -d '\n'; printf '\n'
for f in input-manifest.json intermediate.json model.json release.json provenance.json; do d=$(sha256sum "/input/$f"|cut -d ' ' -f1); printf '{"identity":"spiffe://saf.example.test/ml/training/build-pipeline","name":"%s","sha256":"%s"}\n' "$f" "$d" > "/out/$f.statement"; openssl dgst -sha256 -sign /key/private.pem -out "/out/$f.sig" "/out/$f.statement"; for x in statement sig; do printf '%s.%s=' "$f" "$x"; base64 "/out/$f.$x"|tr -d '\n'; printf '\n'; done; done; printf 'SIGN_END\n' '''

VERIFY = r'''set -eu; cd /verify
for f in input-manifest.json intermediate.json model.json release.json provenance.json; do
  [ -s "$f.sig" ] || { echo "missing-signature:$f"; exit 21; }
  openssl dgst -sha256 -verify public.pem -signature "$f.sig" "$f.statement" >/dev/null 2>&1 || { echo "signature-rejected:$f"; exit 22; }
  d=$(sha256sum "$f" | cut -d ' ' -f 1)
  printf '{"identity":"spiffe://saf.example.test/ml/training/build-pipeline","name":"%s","sha256":"%s"}\n' "$f" "$d" |
    cmp -s - "$f.statement" || { echo "bytes-identity-or-name-rejected:$f"; exit 24; }

done; echo 'all-artifacts-signature-identity-and-bytes-verified' '''

def verify(lab,name,artifacts,signed,public,expected_failure=None):
    data={"verify.sh":VERIFY}; binary={"public.pem":public}
    for f in FILES:
        binary[f]=artifacts[f]
        for ext in ("sig","statement"):
            if f+"."+ext in signed: binary[f+"."+ext]=signed[f+"."+ext]
    cmname=name+"-data"; lab.create(cm(cmname,data=data,binary=binary))
    lab.create(job(name,"sh /verify/verify.sh",[{"name":"data","mountPath":"/verify","readOnly":True}],[{"name":"data","configMap":{"name":cmname,"defaultMode":292}}]))
    ok=wait(lab,name); output=logs(lab,name)
    if expected_failure and not ok and expected_failure not in output:
        lab.block(f"Verifier Job {name} failed without the expected rejection marker")
    if not expected_failure and not ok:
        lab.block(f"Verifier Job {name} failed during the permitted-signature check")
    return ok,output

def sign(lab, name, input_cm, *, enabled=True):
    mounts = [{"name": "input", "mountPath": "/input", "readOnly": True},
              {"name": "out", "mountPath": "/out"}, {"name": "key", "mountPath": "/key"}]
    volumes = [{"name": "input", "configMap": {"name": input_cm}},
               {"name": "out", "emptyDir": {"sizeLimit": "1Mi"}},
               {"name": "key", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}]
    lab.create(job(name, SIGNER, mounts, volumes,
                   env=[{"name": "SIGNING_ENABLED", "value": str(enabled).lower()}]))
    if not wait(lab, name):
        lab.block(f"Signer Job {name} failed")
    output = logs(lab, name)
    if not enabled:
        if output.strip() != "SIGNING_DISABLED_NO_SIGNATURES":
            lab.block("Disabled signer returned unexpected data")
        return None, {}
    fields = block(output, "SIGN_BEGIN", "SIGN_END")
    public = base64.b64decode(fields.pop("public"), validate=True)
    return public, {name: base64.b64decode(value, validate=True) for name, value in fields.items()}


def run(lab):
    version=json.loads(lab.kubectl("get","--raw=/version").stdout).get("gitVersion")
    lab.check("positive","Disposable API server is Kubernetes v1.36.1",version=="v1.36.1",{"server":version})
    fixture_cm="saf-0905-046-training-input"
    input_manifest='{"dataset_id":"synthetic-set-v1","records":[{"x":0,"y":1},{"x":1,"y":3},{"x":2,"y":5}]}\n'
    lab.create(cm(fixture_cm,data={"input-manifest.json":input_manifest}))
    lab.create(job("saf-0905-046-builder",BUILDER,[{"name":"input","mountPath":"/input","readOnly":True},{"name":"out","mountPath":"/out"}],[{"name":"input","configMap":{"name":fixture_cm}},{"name":"out","emptyDir":{"sizeLimit":"1Mi"}}],image=PYTHON_IMAGE))
    if not wait(lab,"saf-0905-046-builder"): lab.block("Synthetic builder Job failed")
    built=block(logs(lab,"saf-0905-046-builder"),"BUILD_BEGIN","BUILD_END")
    artifacts={f:base64.b64decode(built[f],validate=True) for f in FILES}
    lab.check("positive","Builder created all named artifact kinds",set(built) == set(FILES) and artifacts['input-manifest.json'] == input_manifest.encode(),{"artifact_names":sorted(artifacts)})
    intermediate=json.loads(artifacts["intermediate.json"])
    model=json.loads(artifacts["model.json"])
    model_matches=model.get("parameters") == intermediate == {"bias": 1.0, "weight": 2.0}
    model_matches = model_matches and json.loads(artifacts["release.json"])["model"] == model
    lab.check("positive","Trained model embeds the parameters computed from the synthetic input manifest",model_matches,{"model_parameters_match_training_output":model_matches})
    input_cm="saf-0905-046-signer-input"; lab.create(cm(input_cm,binary=artifacts))
    public, signed = sign(lab, "saf-0905-046-signer", input_cm)
    lab.check("green","Signer produced statements and signatures for every artifact",all(f+".sig" in signed and f+".statement" in signed for f in FILES),{"signature_count":sum(k.endswith(".sig") for k in signed),"statement_count":sum(k.endswith(".statement") for k in signed)})
    good,log=verify(lab,"saf-0905-046-verify-good",artifacts,signed,public)
    lab.check("green","Verifier accepts actual bytes under bounded pipeline identity",good and "all-artifacts-signature-identity-and-bytes-verified" in log,{"verified":good and "all-artifacts-signature-identity-and-bytes-verified" in log})
    disabled_public, disabled_signatures = sign(lab, "saf-0905-046-signer-disabled", input_cm, enabled=False)
    lab.check("positive", "Disabled signer completes without producing a signing key or signatures",
              disabled_public is None and not disabled_signatures,
              {"emitted_signature_count": len(disabled_signatures)})
    unsigned={}
    ok,log=verify(lab,"saf-0905-046-verify-disabled",artifacts,unsigned,public,"missing-signature:")
    lab.check("red","Missing signature is rejected when signing is disabled",not ok and "missing-signature:" in log,{"rejected_missing_signature":not ok and "missing-signature:" in log})
    altered=dict(artifacts); altered["model.json"]+=b"tampered"
    ok,log=verify(lab,"saf-0905-046-verify-tampered",altered,signed,public,"bytes-identity-or-name-rejected:model.json")
    lab.check("red","Tampered model bytes are rejected",not ok and "bytes-identity-or-name-rejected:model.json" in log,{"rejected_tampered_model":not ok and "bytes-identity-or-name-rejected:model.json" in log})
    alternate_public, alternate_signatures = sign(lab, "saf-0905-046-alternate-signer", input_cm)
    distinct = alternate_public != public
    alternate_labels = all(alternate_signatures[f + ".statement"] == signed[f + ".statement"] for f in FILES)
    alternate_valid, _ = verify(lab, "saf-0905-046-verify-alternate-correctly", artifacts,
                                alternate_signatures, alternate_public)
    ok, log = verify(lab, "saf-0905-046-verify-wrong-key", artifacts, alternate_signatures, public,
                     "signature-rejected:input-manifest.json")
    lab.check("red", "The trusted key rejects valid signatures made by a different signer for the same bytes and identity",
              distinct and alternate_labels and alternate_valid and not ok
              and "signature-rejected:input-manifest.json" in log,
              {"alternate_key_distinct": distinct, "identical_statement_bytes": alternate_labels,
               "alternate_signature_valid_with_own_key": alternate_valid,
               "rejected_with_fixture_trust_key": not ok})
    artifact_summaries = {}
    for name, data in artifacts.items():
        artifact_summaries[name] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "statement": json.loads(signed[name + ".statement"]),
            "signature_base64": base64.b64encode(signed[name + ".sig"]).decode(),
        }
    evidence = {"artifacts": artifact_summaries, "signer_public_key": public.decode(),
                "alternate_public_key_fingerprint": hashlib.sha256(alternate_public).hexdigest()}
    (lab.evidence / "artifact-signatures.json").write_text(json.dumps(evidence, indent=2) + "\n")
