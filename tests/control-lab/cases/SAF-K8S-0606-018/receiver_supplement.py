"""Scratch-only native receiving-stage identity check for 0606-018."""

import hashlib
import json
from pathlib import Path
import time

NAMESPACE = "saf-test"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
IDENTITY = "system:serviceaccount:saf-test:handoff-receiver"
RECEIVER = r'''import base64, hashlib, json, os, pathlib, ssl, subprocess, tempfile, urllib.error, urllib.request
AUTH=pathlib.Path('/var/run/fixture-api')
def api(method,name,fields=None):
 data=json.dumps({'data':fields}).encode() if fields is not None else None
 headers={'Authorization':'Bearer '+(AUTH/'token').read_text().strip()}
 if data is not None: headers['Content-Type']='application/merge-patch+json'
 req=urllib.request.Request('https://kubernetes.default.svc/api/v1/namespaces/saf-test/configmaps/'+name,data=data,headers=headers,method=method)
 try:
  with urllib.request.urlopen(req,context=ssl.create_default_context(cafile=str(AUTH/'ca.crt')),timeout=8) as r: return r.status,json.load(r)
 except urllib.error.HTTPError as e: return e.code,{}
def main():
 status,artifact=api('GET','handoff-artifact')
 es,evidence=api('GET','handoff-evidence')
 ts,trust=api('GET','handoff-receiver-trust')
 artifact_write,_=api('PATCH','handoff-artifact',{'fixture-attempt':'receiver-must-not-edit'})
 evidence_write,_=api('PATCH','handoff-evidence',{'fixture-attempt':'receiver-must-not-edit'})
 if (status,es,ts)!=(200,200,200) or (artifact_write,evidence_write)!=(403,403):
  print(json.dumps({'decision':'deny','reason':'input_read_failed'})); return 2
 try:
  body=evidence['data']['statement']; sig=base64.b64decode(evidence['data']['signature'],validate=True)
  statement=json.loads(body); marker=artifact['data']['marker']
  actual='sha256:'+hashlib.sha256(marker.encode()).hexdigest()
  expected=os.environ['EXPECTED_DIGEST']
  identity='system:serviceaccount:saf-test:handoff-observer'
  if statement!={'identity':identity,'subject_digest':actual} or actual!=expected: raise ValueError()
  with tempfile.TemporaryDirectory() as d:
   d=pathlib.Path(d); (d/'public.pem').write_text(trust['data']['public.pem']); (d/'body').write_text(body); (d/'sig').write_bytes(sig)
   verify=subprocess.run(['openssl','dgst','-sha256','-verify',str(d/'public.pem'),'-signature',str(d/'sig'),str(d/'body')],capture_output=True,text=True,timeout=8)
   if verify.returncode or 'Verified OK' not in verify.stdout: raise ValueError()
  code,_=api('PATCH',os.environ['RELEASE_NAME'],{'subject_digest':actual,'receiver_identity':'system:serviceaccount:saf-test:handoff-receiver','evidence_identity':identity})
  print(json.dumps({'decision':'accept' if code==200 else 'deny','subject_matches':actual==expected,'signature_verified':code==200,'release_write':code,'artifact_write_denied':artifact_write==403,'evidence_write_denied':evidence_write==403}))
  return 0 if code==200 else 3
 except (OSError, subprocess.TimeoutExpired):
  print(json.dumps({'decision':'deny','reason':'verification_io_failed'})); return 3
 except (ValueError, KeyError):
  print(json.dumps({'decision':'deny','reason':'signature_or_subject_mismatch'})); return 3
if __name__=='__main__': raise SystemExit(main())
'''


def _create_job(lab, name, expected_digest, release_name):
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 85,
                         "template": {"spec": {"serviceAccountName": "handoff-receiver",
                             "restartPolicy": "Never", "automountServiceAccountToken": False,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                 "seccompProfile": {"type": "RuntimeDefault"}},
                             "volumes": [
                                 {"name": "script", "configMap": {"name": "handoff-receiver-code"}},
                                 {"name": "temporary", "emptyDir": {}},
                                 {"name": "api", "projected": {"sources": [
                                     {"serviceAccountToken": {"expirationSeconds": 600, "path": "token"}},
                                     {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}}
                                 ]}}
                             ],
                             "containers": [{"name": "receiver", "image": IMAGE,
                                 "command": ["python3", "/fixture/receiver.py"],
                                 "env": [{"name": "EXPECTED_DIGEST", "value": expected_digest},
                                         {"name": "RELEASE_NAME", "value": release_name}],
                                 "volumeMounts": [{"name": "script", "mountPath": "/fixture", "readOnly": True},
                                                  {"name": "api", "mountPath": "/var/run/fixture-api", "readOnly": True},
                                                  {"name": "temporary", "mountPath": "/tmp"}],
                                 "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                               "limits": {"cpu": "200m", "memory": "96Mi"}},
                                 "securityContext": {"allowPrivilegeEscalation": False,
                                     "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
                             }]
                         }}}})


def _run_job(lab, name, expect_accept):
    expect = "Complete" if expect_accept else "Failed"
    deadline = time.monotonic() + 85
    terminal = set()
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        terminal = {row["type"] for row in job.get("status", {}).get("conditions", [])
                    if row["status"] == "True"} & {"Complete", "Failed"}
        if terminal:
            break
        time.sleep(0.5)
    logs = lab.kubectl("logs", f"job/{name}", allow_failure=True)
    if logs.returncode != 0 or terminal != {expect}:
        lab.block(f"Receiving-stage Job {name} did not reach its expected terminal state")
    try:
        return json.loads(logs.stdout)
    except json.JSONDecodeError:
        lab.block(f"Receiving-stage Job {name} returned no bounded decision record")


def run_receiver(lab, public_key, digest):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "handoff-receiver-code"},
                "immutable": True, "data": {"receiver.py": RECEIVER}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "handoff-receiver-trust"},
                "immutable": True, "data": {"public.pem": public_key.decode("ascii")}})
    for name in ("handoff-receiver-release", "handoff-receiver-denied"):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": {}})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "handoff-receiver"},
                "automountServiceAccountToken": False})
    resources = ["handoff-artifact", "handoff-evidence", "handoff-receiver-trust"]
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "handoff-receiver"},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": resources, "verbs": ["get"]},
                          {"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": ["handoff-receiver-release", "handoff-receiver-denied"], "verbs": ["patch"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "handoff-receiver"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "handoff-receiver"},
                "subjects": [{"kind": "ServiceAccount", "name": "handoff-receiver", "namespace": NAMESPACE}]})
    _create_job(lab, "handoff-native-receiver", digest, "handoff-receiver-release")
    accepted = _run_job(lab, "handoff-native-receiver", True)
    released = json.loads(lab.kubectl("get", "configmap", "handoff-receiver-release", "-o", "json").stdout).get("data", {})
    correct = (accepted.get("decision") == "accept" and accepted.get("signature_verified") is True
               and accepted.get("artifact_write_denied") is True and accepted.get("evidence_write_denied") is True
               and released.get("subject_digest") == digest
               and released.get("receiver_identity") == IDENTITY
               and released.get("evidence_identity") == "system:serviceaccount:saf-test:handoff-observer")

    _create_job(lab, "handoff-native-wrong-subject", "sha256:" + "0" * 64, "handoff-receiver-denied")
    denied = _run_job(lab, "handoff-native-wrong-subject", False)
    denied_data = json.loads(lab.kubectl("get", "configmap", "handoff-receiver-denied", "-o", "json").stdout).get("data", {})
    denied_absent = (denied.get("decision") == "deny" and not denied_data)
    lab.check("positive", "A distinct Kubernetes receiving identity verifies the signed handoff before publishing, and denies an expected-subject mismatch",
              correct and denied_absent,
              {"approved_receiver_release": correct, "wrong_subject_denied": denied_absent,
               "receiver_artifact_and_evidence_writes_denied": bool(accepted.get("artifact_write_denied") and accepted.get("evidence_write_denied")),
               "receiver_identity": IDENTITY, "subject_sha256": digest})
