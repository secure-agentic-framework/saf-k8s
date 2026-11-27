"""Synthetic, role-separated verifier-result and relying-party witness.

This is a local reference workflow using generated fixture signing material. It
does not implement or claim conformance to a RATS profile or attest hardware.
"""

import base64
import hashlib
import json
import tempfile
import time
from pathlib import Path

IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAMESPACE = "saf-0804-result-boundary"
PRIVATE_SECRET = "fixture-appraiser-signing-key"
FIXTURE_CONFIG = "fixture-appraisal-input"
APPRAISER_ROLE = "fixture-appraiser-create-results"
RP_ROLE = "fixture-relying-party-read-results"
APPRAISER_JOB = "fixture-appraiser"
RP_JOB = "fixture-relying-party"
RESULT_NAMES = {
    "approved": "result-approved",
    "unapproved": "result-unapproved",
    "wrong_audience": "result-wrong-audience",
    "wrong_subject": "result-wrong-subject",
    "wrong_request": "result-wrong-request",
    "expired": "result-expired",
    "unavailable": "result-unavailable",
}
MARKERS = {name: f"use-{name.replace('_', '-')}-marker" for name in RESULT_NAMES}
APPRAISER = r'''import base64,hashlib,json,os,pathlib,ssl,subprocess,tempfile,time,urllib.error,urllib.request
from urllib.request import ProxyHandler,HTTPSHandler,build_opener
p=pathlib.Path('/fixture'); key='/appraiser-key/key.pem'; ident=pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount')
try:
    v=subprocess.run(['openssl','dgst','-sha256','-verify',str(p/'authority-public.pem'),'-signature',str(p/'evidence-signature.der'),str(p/'evidence-record.json')],capture_output=True,text=True,timeout=8)
except Exception: raise SystemExit('fixture-evidence-verifier-unavailable')
if v.returncode or 'Verified OK' not in v.stdout: raise SystemExit('fixture-evidence-invalid')
evidence=p.joinpath('evidence-record.json').read_bytes(); claims=json.loads(evidence)
if claims.get('subject')!='fixture-workload' or claims.get('reference')!='fixture-approved-measurement' or claims.get('challenge')!='fixture-challenge-x': raise SystemExit('fixture-evidence-binding-invalid')
now=int(time.time()); common={'audience':'fixture-sensitive-use-rp','subject':'fixture-workload','request_reference':'fixture-request-001','challenge':'fixture-challenge-x','appraisal_status':'trusted','reference':'fixture-approved-measurement','evidence_sha256':hashlib.sha256(evidence).hexdigest(),'issued_at':now-10,'expires_at':now+600}
cases={'approved':dict(common),'unapproved':dict(common,appraisal_status='untrusted'),'wrong_audience':dict(common,audience='fixture-other-rp'),'wrong_subject':dict(common,subject='fixture-other-workload'),'wrong_request':dict(common,request_reference='fixture-request-other'),'expired':dict(common,issued_at=now-120,expires_at=now-60)}
ns=ident.joinpath('namespace').read_text().strip(); host=os.environ['KUBERNETES_SERVICE_HOST']; port=os.environ['KUBERNETES_SERVICE_PORT_HTTPS']; token=ident.joinpath('token').read_text().strip(); ca=ident/'ca.crt'
op=build_opener(ProxyHandler({}),HTTPSHandler(context=ssl.create_default_context(cafile=str(ca)))); base=f'https://{host}:{port}/api/v1/namespaces/{ns}/configmaps'; headers={'Authorization':'Bearer '+token,'Content-Type':'application/merge-patch+json','Accept':'application/json'}
made=[]
for label,record in cases.items():
    payload=json.dumps(record,sort_keys=True,separators=(',',':')).encode()
    with tempfile.NamedTemporaryFile(dir='/work',delete=True) as f:
        f.write(payload); f.flush(); sigpath=f.name+'.sig'
        try:
            signed=subprocess.run(['openssl','dgst','-sha256','-sign',key,'-out',sigpath,f.name],capture_output=True,timeout=8)
        except Exception: raise SystemExit('result-signing-unavailable')
        if signed.returncode: raise SystemExit('result-signing-failed')
        sig=pathlib.Path(sigpath).read_bytes(); pathlib.Path(sigpath).unlink(missing_ok=True)
    name='result-'+label.replace('_','-'); body={'data':{'payload':payload.decode()},'binaryData':{'signature.der':base64.b64encode(sig).decode()}}
    req=urllib.request.Request(base+'/'+name,data=json.dumps(body).encode(),headers=headers,method='PATCH')
    try:
        with op.open(req,timeout=8) as response:
            if response.status!=200: raise SystemExit('result-patch-unexpected-status')
    except urllib.error.HTTPError as e:
        if e.code==404: raise SystemExit('exact-result-slot-missing')
        raise SystemExit('result-patch-failed')
    made.append({'name':name,'payload_sha256':hashlib.sha256(payload).hexdigest(),'signature_sha256':hashlib.sha256(sig).hexdigest(),'issued_at':record['issued_at'],'expires_at':record['expires_at']})
print(json.dumps({'fixture_evidence_verified':True,'published_result_count':len(made),'result_issued_at':now-10,'rp_valid_until':now+600,'results':made},sort_keys=True))
'''

RELYING_PARTY = r'''import base64,hashlib,json,os,pathlib,ssl,subprocess,tempfile,time,urllib.error,urllib.request
from urllib.request import ProxyHandler,HTTPSHandler,build_opener
p=pathlib.Path('/fixture'); ident=pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount'); ns=ident.joinpath('namespace').read_text().strip(); host=os.environ['KUBERNETES_SERVICE_HOST']; port=os.environ['KUBERNETES_SERVICE_PORT_HTTPS']; token=ident.joinpath('token').read_text().strip(); op=build_opener(ProxyHandler({}),HTTPSHandler(context=ssl.create_default_context(cafile=str(ident/'ca.crt')))); base=f'https://{host}:{port}/api/v1/namespaces/{ns}/configmaps'; hdr={'Authorization':'Bearer '+token,'Accept':'application/json','Content-Type':'application/json'}
names={'approved':'result-approved','unapproved':'result-unapproved','wrong_audience':'result-wrong-audience','wrong_subject':'result-wrong-subject','wrong_request':'result-wrong-request','expired':'result-expired','unavailable':'result-unavailable'}
markers={k:'use-'+k.replace('_','-')+'-marker' for k in names}; expected={'audience':'fixture-sensitive-use-rp','subject':'fixture-workload','request_reference':'fixture-request-001','challenge':'fixture-challenge-x','appraisal_status':'trusted','reference':'fixture-approved-measurement'}; now=int(time.time()); out={}
def fetch(name):
    req=urllib.request.Request(base+'/'+name,headers=hdr)
    try:
        with op.open(req,timeout=8) as r: return json.load(r),None
    except urllib.error.HTTPError as e:
        if e.code==404:
            try:
                status=json.loads(e.read()); details=status.get('details',{})
                if status.get('reason')=='NotFound' and details.get('name')==name and details.get('kind')=='configmaps': return None,'NotFound'
            except Exception: pass
        return None,'transport-or-api-error'
    except Exception: return None,'transport-or-api-error'
for label,name in names.items():
    if label=='unavailable':
        obj,err=fetch(name)
        if obj is not None or err!='NotFound': raise SystemExit('missing-result-not-exact-notfound')
        out[label]={'decision':'unavailable','marker_attempted':False,'result_not_found':True}; continue
    obj,err=fetch(name)
    if err or not obj or obj.get('immutable') is True or obj.get('metadata',{}).get('name')!=name or obj.get('metadata',{}).get('namespace')!=ns: raise SystemExit('result-object-binding-invalid')
    try:
        payload=obj.get('data',{}).get('payload','').encode(); sig=base64.b64decode(obj.get('binaryData',{}).get('signature.der',''),validate=True)
        record=json.loads(payload)
        with tempfile.NamedTemporaryFile(dir='/work',delete=True) as pf, tempfile.NamedTemporaryFile(dir='/work',delete=True) as sf:
            pf.write(payload); pf.flush(); sf.write(sig); sf.flush()
            vr=subprocess.run(['openssl','dgst','-sha256','-verify',str(p/'appraiser-public.pem'),'-signature',sf.name,pf.name],capture_output=True,text=True,timeout=8)
        sig_ok=vr.returncode==0 and vr.stdout.strip()=='Verified OK'
    except Exception: sig_ok=False; record={}; payload=b''
    evidence_hash=hashlib.sha256(p.joinpath('evidence-record.json').read_bytes()).hexdigest()
    binding=all(record.get(k)==v for k,v in expected.items()) and record.get('evidence_sha256')==evidence_hash
    issued=record.get('issued_at'); expires=record.get('expires_at')
    valid_time=isinstance(issued,int) and isinstance(expires,int) and issued<=now<expires and 0<expires-issued<=900
    allowed=sig_ok and binding and valid_time
    outcome='eligible' if allowed else ('signature-invalid' if not sig_ok else ('claims-mismatch' if not binding else 'outside-live-validity'))
    marker_attempted=False
    if allowed:
        body={'data':{'use':'permitted-fixture-marker','result_sha256':hashlib.sha256(payload).hexdigest()}}
        patch_headers=dict(hdr); patch_headers['Content-Type']='application/merge-patch+json'
        req=urllib.request.Request(base+'/'+markers[label],data=json.dumps(body).encode(),headers=patch_headers,method='PATCH')
        try:
            with op.open(req,timeout=8) as r:
                if r.status!=200: raise SystemExit('marker-patch-unexpected-status')
            marker_attempted=True
        except Exception: raise SystemExit('approved-marker-patch-failed')
    out[label]={'decision':outcome,'signature_valid':sig_ok,'claims_bound':binding,'within_live_validity':valid_time,'marker_attempted':marker_attempted,'result_sha256':hashlib.sha256(payload).hexdigest()}
print(json.dumps({'rp_service_account':'fixture-relying-party','appraiser_key_signature_checked':True,'evaluated_at':now,'decisions':out},sort_keys=True))
'''


def _create(lab, namespace, obj):
    obj.setdefault("metadata", {}).setdefault("namespace", namespace)
    return lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(obj))


def _job(name, service_account, image, command, mounts, volumes, *, fs_group=False):
    pod_security = {"runAsNonRoot": True, "runAsUser": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"}}
    if fs_group:
        pod_security["fsGroup"] = 65534
        pod_security["fsGroupChangePolicy"] = "OnRootMismatch"
    return {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
            "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120,
                     "template": {"metadata": {"labels": {"saf.example/0804-role": name}},
                                  "spec": {"restartPolicy": "Never", "serviceAccountName": service_account,
                                           "automountServiceAccountToken": True, "securityContext": pod_security,
                                           "volumes": volumes,
                                           "containers": [{"name": name, "image": image, "imagePullPolicy": "IfNotPresent",
                                                           "command": command, "volumeMounts": mounts,
                                                           "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                                         "limits": {"cpu": "150m", "memory": "96Mi"}},
                                                           "securityContext": {"allowPrivilegeEscalation": False,
                                                                               "readOnlyRootFilesystem": True,
                                                                               "capabilities": {"drop": ["ALL"]}}}]}}}}


def _job_and_pod(lab, namespace, name):
    job = json.loads(lab.kubectl("-n", namespace, "get", "job", name, "-o", "json").stdout)
    pods = json.loads(lab.kubectl("-n", namespace, "get", "pods", "-l", f"saf.example/0804-role={name}", "-o", "json").stdout)
    rows = pods.get("items", [])
    if len(rows) != 1:
        lab.block(f"Expected one case-owned Pod for {name}")
    pod = rows[0]
    owner = any(ref.get("kind") == "Job" and ref.get("uid") == job.get("metadata", {}).get("uid")
                and ref.get("controller") is True for ref in pod.get("metadata", {}).get("ownerReferences", []))
    identity = owner and pod.get("spec", {}).get("serviceAccountName") == name
    return job, pod, identity


def _dry_patch(lab, namespace, service_account, name):
    subject = f"system:serviceaccount:{namespace}:{service_account}"
    patch = json.dumps({"data": {"scope_probe": "harmless-server-dry-run"}})
    return lab.kubectl("-n", namespace, "patch", "configmap", name, "--type=merge", "-p", patch,
                       "--dry-run=server", f"--as={subject}", allow_failure=True)


def _denied(result, name):
    return result.returncode != 0 and "Forbidden" in result.stderr and name in result.stderr


def await_owned_job(lab, name):
    deadline = time.monotonic() + 100
    selector = f"job-name={name}"
    while time.monotonic() < deadline:
        state = json.loads(lab.kubectl("-n", NAMESPACE, "get", "job", name, "-o", "json").stdout)
        complete = {c["type"] for c in state.get("status", {}).get("conditions", [])
                    if c.get("status") == "True"}
        if "Complete" in complete:
            return
        if "Failed" in complete or "FailureTarget" in complete:
            break
        time.sleep(0.5)
    lab.kubectl("-n", NAMESPACE, "get", "pods", "-l", selector, "-o", "wide", allow_failure=True)
    lab.kubectl("-n", NAMESPACE, "logs", f"job/{name}", "--tail=35", timeout=14, allow_failure=True)
    lab.block(f"Owned attestation fixture Job {name} did not complete")


def run(lab, fixture):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("label", "namespace", NAMESPACE, "pod-security.kubernetes.io/enforce=restricted")
    lab.kubectl("-n", NAMESPACE, "create", "serviceaccount", "fixture-appraiser")
    lab.kubectl("-n", NAMESPACE, "create", "serviceaccount", "fixture-relying-party")
    result_slots = [RESULT_NAMES[k] for k in RESULT_NAMES if k != "unavailable"]
    for name in result_slots:
        _create(lab, NAMESPACE, {"apiVersion": "v1", "kind": "ConfigMap",
                                 "metadata": {"name": name}, "data": {"slot": "awaiting-fixture-appraisal"}})
    for name in MARKERS.values():
        _create(lab, NAMESPACE, {"apiVersion": "v1", "kind": "ConfigMap",
                                 "metadata": {"name": name},
                                 "data": {"use": "not-authorized", "result_sha256": "none"}})

    baseline_appraiser = _dry_patch(lab, NAMESPACE, "fixture-appraiser", RESULT_NAMES["approved"])
    baseline_rp = _dry_patch(lab, NAMESPACE, "fixture-relying-party", MARKERS["approved"])
    baseline_denied = (_denied(baseline_appraiser, RESULT_NAMES["approved"])
                       and _denied(baseline_rp, MARKERS["approved"]))

    temp_root = Path(lab.kubeconfig).parent
    with tempfile.TemporaryDirectory(prefix="saf-0804-result-key-", dir=str(temp_root)) as tmp:
        tmp = Path(tmp)
        private = tmp / "fixture-appraiser-private.pem"
        public = tmp / "fixture-appraiser-public.pem"
        lab.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(private), timeout=20)
        lab.command("openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public), timeout=10)
        appraiser_public_sha256 = hashlib.sha256(public.read_bytes()).hexdigest()
        lab.kubectl("-n", NAMESPACE, "create", "secret", "generic", PRIVATE_SECRET,
                    f"--from-file=key.pem={private}")
        evidence_data = {name: (fixture / name).read_text(encoding="utf-8")
                         for name in ("evidence-record.json", "authority-public.pem")}
        evidence_data["appraiser.py"] = APPRAISER
        evidence_data["relying-party.py"] = RELYING_PARTY
        evidence_data["appraiser-public.pem"] = public.read_text(encoding="utf-8")
        _create(lab, NAMESPACE, {"apiVersion": "v1", "kind": "ConfigMap",
                                "metadata": {"name": FIXTURE_CONFIG}, "immutable": True,
                                "data": evidence_data,
                                "binaryData": {"evidence-signature.der": base64.b64encode(
                                    (fixture / "evidence-signature.der").read_bytes()).decode("ascii")}})

    _create(lab, NAMESPACE, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                            "metadata": {"name": APPRAISER_ROLE},
                            "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "patch"],
                                       "resourceNames": result_slots}]})
    _create(lab, NAMESPACE, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                            "metadata": {"name": APPRAISER_ROLE},
                            "subjects": [{"kind": "ServiceAccount", "name": "fixture-appraiser", "namespace": NAMESPACE}],
                            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": APPRAISER_ROLE}})
    _create(lab, NAMESPACE, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                            "metadata": {"name": RP_ROLE},
                            "rules": [
                                {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"],
                                 "resourceNames": [*result_slots, RESULT_NAMES["unavailable"]]},
                                {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "patch"],
                                 "resourceNames": [MARKERS["approved"]]},
                            ]})
    _create(lab, NAMESPACE, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                            "metadata": {"name": RP_ROLE},
                            "subjects": [{"kind": "ServiceAccount", "name": "fixture-relying-party", "namespace": NAMESPACE}],
                            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": RP_ROLE}})
    active_app_exact = _dry_patch(lab, NAMESPACE, "fixture-appraiser", RESULT_NAMES["approved"])
    active_app_crossed = _dry_patch(lab, NAMESPACE, "fixture-appraiser", MARKERS["approved"])
    active_rp_exact = _dry_patch(lab, NAMESPACE, "fixture-relying-party", MARKERS["approved"])
    active_rp_crossed = _dry_patch(lab, NAMESPACE, "fixture-relying-party", RESULT_NAMES["approved"])
    authority_matrix = (baseline_denied and active_app_exact.returncode == 0
                        and _denied(active_app_crossed, MARKERS["approved"])
                        and active_rp_exact.returncode == 0
                        and _denied(active_rp_crossed, RESULT_NAMES["approved"]))

    shared_volumes = [{"name": "fixture", "configMap": {"name": FIXTURE_CONFIG}},
                      {"name": "work", "emptyDir": {"sizeLimit": "8Mi"}}]
    shared_mounts = [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                     {"name": "work", "mountPath": "/work"}]
    appraiser_volumes = shared_volumes + [{"name": "appraiser-key", "secret": {"secretName": PRIVATE_SECRET,
                                                                                  "defaultMode": 288}}]
    appraiser_mounts = shared_mounts + [{"name": "appraiser-key", "mountPath": "/appraiser-key", "readOnly": True}]
    _create(lab, NAMESPACE, _job(APPRAISER_JOB, "fixture-appraiser", IMAGE,
                                ["python", "-B", "-c", APPRAISER], appraiser_mounts, appraiser_volumes, fs_group=True))
    await_owned_job(lab, APPRAISER_JOB)
    secret_cleanup = lab.kubectl("-n", NAMESPACE, "delete", "secret", PRIVATE_SECRET).returncode == 0
    appraiser_binding_cleanup = lab.kubectl("-n", NAMESPACE, "delete", "rolebinding", APPRAISER_ROLE).returncode == 0
    _create(lab, NAMESPACE, _job(RP_JOB, "fixture-relying-party", IMAGE,
                                ["python", "-B", "-c", RELYING_PARTY], shared_mounts, shared_volumes, fs_group=True))
    await_owned_job(lab, RP_JOB)
    rp_binding_cleanup = lab.kubectl("-n", NAMESPACE, "delete", "rolebinding", RP_ROLE).returncode == 0

    appraiser_job, appraiser_pod, appraiser_owned = _job_and_pod(lab, NAMESPACE, APPRAISER_JOB)
    rp_job, rp_pod, rp_owned = _job_and_pod(lab, NAMESPACE, RP_JOB)
    app_out = json.loads(lab.kubectl("-n", NAMESPACE, "logs", f"pod/{appraiser_pod['metadata']['name']}", timeout=20).stdout)
    rp_out = json.loads(lab.kubectl("-n", NAMESPACE, "logs", f"pod/{rp_pod['metadata']['name']}", timeout=20).stdout)
    decisions = rp_out.get("decisions", {})
    expected_labels = set(RESULT_NAMES)
    appraiser_ok = (len(app_out.get("results", [])) == 6 and app_out.get("published_result_count") == 6
                    and app_out.get("fixture_evidence_verified") is True)
    rp_expected = {"approved": "eligible", "unapproved": "claims-mismatch",
                   "wrong_audience": "claims-mismatch", "wrong_subject": "claims-mismatch",
                   "wrong_request": "claims-mismatch", "expired": "outside-live-validity",
                   "unavailable": "unavailable"}
    decisions_ok = (set(decisions) == expected_labels
                    and all(decisions[k].get("decision") == v for k, v in rp_expected.items())
                    and decisions["approved"].get("signature_valid") is True
                    and decisions["approved"].get("claims_bound") is True
                    and decisions["approved"].get("within_live_validity") is True
                    and decisions["approved"].get("marker_attempted") is True
                    and all(decisions[k].get("signature_valid") is True and decisions[k].get("claims_bound") is False
                            and decisions[k].get("within_live_validity") is True
                            for k in ("unapproved", "wrong_audience", "wrong_subject", "wrong_request"))
                    and decisions["expired"].get("signature_valid") is True
                    and decisions["expired"].get("claims_bound") is True
                    and decisions["expired"].get("within_live_validity") is False
                    and decisions["unavailable"].get("result_not_found") is True)
    marker_state = {}
    for label, name in MARKERS.items():
        result = lab.kubectl("-n", NAMESPACE, "get", "configmap", name, "-o", "json", allow_failure=True)
        if label == "approved":
            try:
                obj = json.loads(result.stdout)
                marker_state[label] = (result.returncode == 0
                                       and obj.get("metadata", {}).get("name") == name
                                       and obj.get("metadata", {}).get("namespace") == NAMESPACE
                                       and obj.get("data", {}).get("use") == "permitted-fixture-marker"
                                       and obj.get("data", {}).get("result_sha256") == decisions["approved"].get("result_sha256"))
            except (json.JSONDecodeError, AttributeError):
                marker_state[label] = False
        else:
            try:
                obj = json.loads(result.stdout)
                marker_state[label] = (result.returncode == 0
                                       and obj.get("metadata", {}).get("name") == name
                                       and obj.get("metadata", {}).get("namespace") == NAMESPACE
                                       and obj.get("data", {}).get("use") == "not-authorized"
                                       and obj.get("data", {}).get("result_sha256") == "none")
            except (json.JSONDecodeError, AttributeError):
                marker_state[label] = False
    marker_ok = marker_state.get("approved") is True and all(marker_state[k] is True for k in marker_state if k != "approved")
    distinct_identities = (appraiser_owned and rp_owned
                           and appraiser_pod.get("spec", {}).get("serviceAccountName") == "fixture-appraiser"
                           and rp_pod.get("spec", {}).get("serviceAccountName") == "fixture-relying-party"
                           and appraiser_pod.get("spec", {}).get("serviceAccountName") != rp_pod.get("spec", {}).get("serviceAccountName"))
    (lab.evidence / "verifier-rp-result-boundary.json").write_text(json.dumps({
        "namespace": NAMESPACE,
        "appraiser_job_uid": appraiser_job.get("metadata", {}).get("uid"),
        "appraiser_pod_uid": appraiser_pod.get("metadata", {}).get("uid"),
        "appraiser_service_account": appraiser_pod.get("spec", {}).get("serviceAccountName"),
        "rp_job_uid": rp_job.get("metadata", {}).get("uid"),
        "rp_pod_uid": rp_pod.get("metadata", {}).get("uid"),
        "rp_service_account": rp_pod.get("spec", {}).get("serviceAccountName"),
        "fixture_evidence_sha256": hashlib.sha256((fixture / "evidence-record.json").read_bytes()).hexdigest(),
        "appraiser_public_key_sha256": appraiser_public_sha256,
        "appraiser_raw_timing": {"issued_at": app_out.get("result_issued_at"),
                                 "valid_until": app_out.get("rp_valid_until"),
                                 "per_result": [{"name": item.get("name"), "issued_at": item.get("issued_at"),
                                                 "expires_at": item.get("expires_at")}
                                                for item in app_out.get("results", [])]},
        "rp_evaluated_at": rp_out.get("evaluated_at"),
        "result_records": app_out.get("results", []),
        "relying_party_decisions": decisions,
        "marker_state": marker_state,
        "authority_dry_run": {"no_grant_appraiser_write_denied": _denied(baseline_appraiser, RESULT_NAMES["approved"]),
                              "no_grant_rp_write_denied": _denied(baseline_rp, MARKERS["approved"]),
                              "appraiser_exact_result_slot_allowed": active_app_exact.returncode == 0,
                              "appraiser_marker_slot_denied": _denied(active_app_crossed, MARKERS["approved"]),
                              "rp_exact_approved_marker_allowed": active_rp_exact.returncode == 0,
                              "rp_result_slot_denied": _denied(active_rp_crossed, RESULT_NAMES["approved"])},
        "temporary_fixture_signing_secret_removed": secret_cleanup,
        "appraiser_rolebinding_removed_after_publication": appraiser_binding_cleanup,
        "rp_rolebinding_removed_after_decision": rp_binding_cleanup,
        "private_test_key_retained": False,
        "hardware_attestation_tested": False,
        "rfc_profile_conformance_claimed": False,
    }, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "A separate relying party accepts one live-valid signed verifier result and permits only the harmless approved marker; invalid or unavailable results leave every other marker unchanged",
              appraiser_ok and decisions_ok and marker_ok and distinct_identities and secret_cleanup
              and appraiser_binding_cleanup and rp_binding_cleanup and authority_matrix,
              {"distinct_owned_appraiser_and_rp_identities": distinct_identities,
               "six_signed_result_variants_created": appraiser_ok,
               "approved_signed_result_bound_and_live": decisions.get("approved", {}).get("signature_valid") is True
                    and decisions.get("approved", {}).get("claims_bound") is True
                    and decisions.get("approved", {}).get("within_live_validity") is True,
               "wrong_approval_audience_subject_request_expiry_and_absence_denied": decisions_ok,
               "wrong_claims_denied_with_valid_signatures_and_expiry_denied_at_time_check": decisions_ok,
               "only_approved_marker_slot_changed_to_matching_result": marker_ok,
               "baseline_denied_then_exact_and_crossed_writes_bound_by_rbac": authority_matrix,
               "temporary_fixture_signing_secret_removed": secret_cleanup,
               "writer_role_bindings_removed_after_their_phases": appraiser_binding_cleanup and rp_binding_cleanup})
