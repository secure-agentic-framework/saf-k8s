"""Cross-workload replay check for the exact inert published appraisal record."""

import base64
import hashlib
import json
from pathlib import Path

NAMESPACE = "saf-0804-challenge"
STATE = "used-fixture-challenge-x"
CONFIG = "signed-fixture-evidence"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
VERIFIERS = ("verifier-a", "verifier-b")
EXPECTED = {"subject": "fixture-workload", "reference": "fixture-approved-measurement",
            "challenge": "fixture-challenge-x", "issued": 10, "expires": 20, "now": 14}
ROLE_API = "rbac.authorization.k8s.io/v1"
CLIENT = r'''import hashlib,json,os,pathlib,ssl,subprocess,urllib.error,urllib.request
from urllib.request import ProxyHandler,HTTPSHandler,build_opener
base=pathlib.Path('/fixture'); ident=pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount')
record_path=base/'evidence-record.json'; sig_path=base/'evidence-signature.der'; key_path=base/'authority-public.pem'
record_bytes=record_path.read_bytes(); evidence_hash=hashlib.sha256(record_bytes).hexdigest()
try:
    check=subprocess.run(['openssl','dgst','-sha256','-verify',str(key_path),'-signature',str(sig_path),str(record_path)],capture_output=True,text=True,timeout=5)
except (OSError,subprocess.TimeoutExpired):
    raise SystemExit('appraisal-unavailable')
if check.returncode != 0 or 'Verified OK' not in check.stdout:
    raise SystemExit('appraisal-rejected')
record=json.loads(record_bytes)
expected={'subject':'fixture-workload','reference':'fixture-approved-measurement','challenge':'fixture-challenge-x','issued':10,'expires':20}
if any(record.get(k)!=v for k,v in expected.items()) or not record['issued'] <= 14 < record['expires']:
    raise SystemExit('appraisal-policy-rejected')
verifier=os.environ['FIXTURE_VERIFIER']
if verifier not in ('verifier-a','verifier-b'):
    raise SystemExit('verifier-identity-invalid')
namespace=ident.joinpath('namespace').read_text().strip()
host=os.environ['KUBERNETES_SERVICE_HOST']; port=os.environ['KUBERNETES_SERVICE_PORT_HTTPS']
baseurl=f'https://{host}:{port}/api/v1/namespaces/{namespace}/configmaps'
token=ident.joinpath('token').read_text().strip()
tls=ssl.create_default_context(cafile=str(ident/'ca.crt'))
client=build_opener(ProxyHandler({}),HTTPSHandler(context=tls))
headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','Accept':'application/json'}
body={'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'used-fixture-challenge-x','namespace':namespace},'immutable':True,'data':{'challenge':'fixture-challenge-x','subject':'fixture-workload','reference':'fixture-approved-measurement','evidence_sha256':evidence_hash,'appraisal':'eligible-fixture','consumed_by':verifier}}
url=baseurl+'/used-fixture-challenge-x'
request=urllib.request.Request(baseurl,data=json.dumps(body).encode(),headers=headers,method='POST')
try:
    with client.open(request,timeout=8) as response:
        outcome='created' if response.status==201 else 'unexpected-status'
except urllib.error.HTTPError as error:
    if error.code==409: outcome='already-consumed'
    else: raise SystemExit('state-create-failed')
read=urllib.request.Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/json'})
try:
    with client.open(read,timeout=8) as response:
        state=json.load(response)
except Exception:
    raise SystemExit('state-readback-failed')
data=state.get('data',{})
meta=state.get('metadata',{})
expected_state={'challenge':'fixture-challenge-x','subject':'fixture-workload','reference':'fixture-approved-measurement','evidence_sha256':evidence_hash,'appraisal':'eligible-fixture'}
if state.get('immutable') is not True or meta.get('name')!='used-fixture-challenge-x' or meta.get('namespace')!=namespace or any(data.get(k)!=v for k,v in expected_state.items()) or data.get('consumed_by') not in ('verifier-a','verifier-b'):
    raise SystemExit('state-readback-mismatch')
print(json.dumps({'verifier':verifier,'evidence_sha256':evidence_hash,'outcome':outcome,'readback_matches':True,'state_uid':meta.get('uid'),'consumed_by':data['consumed_by']},sort_keys=True))
'''


def _kubectl(lab, namespace, *args, **kwargs):
    return lab.kubectl("-n", namespace, *args, **kwargs)


def _create(lab, namespace, obj):
    obj.setdefault("metadata", {}).setdefault("namespace", namespace)
    return _kubectl(lab, namespace, "create", "-f", "-", payload=json.dumps(obj))


def _role(name):
    return {"apiVersion": ROLE_API, "kind": "Role", "metadata": {"name": name},
            "rules": [
                {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]},
                {"apiGroups": [""], "resources": ["configmaps"],
                 "resourceNames": [STATE], "verbs": ["get"]},
            ]}


def _job(name, image):
    return {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
            "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                     "template": {"metadata": {"labels": {"saf.example/attestation-verifier": name}},
                                  "spec": {"restartPolicy": "Never", "serviceAccountName": name,
                                           "automountServiceAccountToken": True,
                                           "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                               "seccompProfile": {"type": "RuntimeDefault"}},
                                           "containers": [{"name": "verifier", "image": image,
                                                           "imagePullPolicy": "IfNotPresent",
                                                           "command": ["python", "-B", "-c", CLIENT],
                                                           "env": [{"name": "FIXTURE_VERIFIER", "value": name}],
                                                           "volumeMounts": [{"name": "fixture", "mountPath": "/fixture",
                                                                             "readOnly": True}],
                                                           "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                                         "limits": {"cpu": "100m", "memory": "96Mi"}},
                                                           "securityContext": {"allowPrivilegeEscalation": False,
                                                                               "readOnlyRootFilesystem": True,
                                                                               "capabilities": {"drop": ["ALL"]}}}],
                                           "volumes": [{"name": "fixture", "configMap": {"name": CONFIG}}]}}}}


def _job_object(lab, namespace, name):
    return json.loads(_kubectl(lab, namespace, "get", "job", name, "-o", "json").stdout)


def _pod_for_job(lab, namespace, name):
    rows = json.loads(_kubectl(lab, namespace, "get", "pods", "-l", f"job-name={name}", "-o", "json").stdout)
    if len(rows.get("items", [])) != 1:
        lab.block("Each verifier Job must own exactly one Pod")
    return rows["items"][0]


def _can_i(lab, namespace, verifier, verb, resource):
    user = f"system:serviceaccount:{namespace}:{verifier}"
    result = lab.kubectl("auth", "can-i", verb, resource, "-n", namespace, "--as", user,
                         allow_failure=True)
    verdict = (result.stdout.strip(), result.returncode)
    if verdict not in {("yes", 0), ("no", 1)}:
        lab.block("The Kubernetes authorization review returned no definitive verdict")
    return verdict[0] == "yes"


def run(lab, fixture):
    namespace = NAMESPACE
    lab.kubectl("create", "namespace", namespace)
    lab.kubectl("label", "namespace", namespace, "pod-security.kubernetes.io/enforce=restricted")
    record_bytes = (fixture / "evidence-record.json").read_bytes()
    evidence_sha = hashlib.sha256(record_bytes).hexdigest()
    if not lab.command("openssl", "dgst", "-sha256", "-verify", str(fixture / "authority-public.pem"),
                       "-signature", str(fixture / "evidence-signature.der"),
                       str(fixture / "evidence-record.json"), allow_failure=True).returncode == 0:
        lab.block("Published inert evidence signature did not verify before fixture setup")
    fixture_data = {name: (fixture / name).read_text(encoding="utf-8")
                    for name in ("evidence-record.json", "authority-public.pem")}
    _create(lab, namespace, {"apiVersion": "v1", "kind": "ConfigMap",
                             "metadata": {"name": CONFIG}, "immutable": True, "data": fixture_data,
                             "binaryData": {"evidence-signature.der": base64.b64encode(
                                 (fixture / "evidence-signature.der").read_bytes()).decode("ascii")}})
    for verifier in VERIFIERS:
        _create(lab, namespace, {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": verifier}})
        _create(lab, namespace, _role(verifier))
        _create(lab, namespace, {"apiVersion": ROLE_API, "kind": "RoleBinding",
                                 "metadata": {"name": verifier},
                                 "subjects": [{"kind": "ServiceAccount", "name": verifier,
                                               "namespace": namespace}],
                                 "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": verifier}})
    for verifier in VERIFIERS:
        _create(lab, namespace, _job(verifier, IMAGE))
    for verifier in VERIFIERS:
        _kubectl(lab, namespace, "wait", "--for=condition=Complete", f"job/{verifier}",
                 "--timeout=100s", timeout=110)

    results = {}
    identities = {}
    raw_workloads = {}
    for verifier in VERIFIERS:
        job = _job_object(lab, namespace, verifier)
        pod = _pod_for_job(lab, namespace, verifier)
        job_uid = job.get("metadata", {}).get("uid")
        pod_owned = any(owner.get("kind") == "Job" and owner.get("uid") == job_uid
                        and owner.get("controller") is True for owner in pod.get("metadata", {}).get("ownerReferences", []))
        identity_ok = pod.get("spec", {}).get("serviceAccountName") == verifier
        identities[verifier] = pod_owned and identity_ok
        output = _kubectl(lab, namespace, "logs", f"pod/{pod['metadata']['name']}", timeout=20).stdout.strip()
        try:
            result = json.loads(output)
        except json.JSONDecodeError:
            lab.block("Verifier Job did not emit one bounded sanitized result")
        if set(result) != {"verifier", "evidence_sha256", "outcome", "readback_matches", "state_uid", "consumed_by"}:
            lab.block("Verifier output contained an unexpected field set")
        results[verifier] = result
        raw_workloads[verifier] = {"job_uid": job_uid, "pod_uid": pod.get("metadata", {}).get("uid"),
                                   "pod_name": pod.get("metadata", {}).get("name"),
                                   "service_account": pod.get("spec", {}).get("serviceAccountName"),
                                   "pod_owner_references": pod.get("metadata", {}).get("ownerReferences", [])}

    state = json.loads(_kubectl(lab, namespace, "get", "configmap", STATE, "-o", "json").stdout)
    state_data = state.get("data", {})
    state_uid = state.get("metadata", {}).get("uid")
    exact_shared_state = (bool(state_uid) and state.get("immutable") is True
                          and state.get("metadata", {}).get("namespace") == namespace
                          and state.get("metadata", {}).get("name") == STATE
                          and state_data.get("evidence_sha256") == evidence_sha
                          and state_data.get("challenge") == EXPECTED["challenge"]
                          and state_data.get("subject") == EXPECTED["subject"]
                          and state_data.get("reference") == EXPECTED["reference"]
                          and state_data.get("appraisal") == "eligible-fixture"
                          and state_data.get("consumed_by") in VERIFIERS)
    winners = [name for name, result in results.items() if result["outcome"] == "created"]
    losers = [name for name, result in results.items() if result["outcome"] == "already-consumed"]
    results_match = all(result.get("verifier") == name and result.get("evidence_sha256") == evidence_sha
                        and result.get("readback_matches") is True and result.get("state_uid") == state_uid
                        and result.get("consumed_by") == state_data.get("consumed_by")
                        for name, result in results.items())
    one_creator_one_conflict = len(winners) == len(losers) == 1 and state_data.get("consumed_by") == winners[0]
    lab.check("positive", "Two named verifier Jobs independently appraise the same signed fresh fixture and contend on one atomic namespace state object",
              all(identities.values()) and results_match and exact_shared_state and one_creator_one_conflict,
              {"two_distinct_verifier_service_accounts": len(set(v.get("service_account") for v in raw_workloads.values())) == 2,
               "same_evidence_digest": len({r.get("evidence_sha256") for r in results.values()}) == 1,
               "one_atomic_consumer": one_creator_one_conflict,
               "both_independently_read_matching_state": all(r.get("readback_matches") is True for r in results.values()),
               "state_immutable_and_digest_bound": exact_shared_state})

    least_privilege = all(
        _can_i(lab, namespace, verifier, "create", "configmaps")
        and _can_i(lab, namespace, verifier, "get", f"configmaps/{STATE}")
        and not _can_i(lab, namespace, verifier, "get", "configmaps/other-fixture-object")
        and not _can_i(lab, namespace, verifier, "list", "configmaps")
        and not _can_i(lab, namespace, verifier, "update", f"configmaps/{STATE}")
        and not _can_i(lab, namespace, verifier, "patch", f"configmaps/{STATE}")
        and not _can_i(lab, namespace, verifier, "delete", f"configmaps/{STATE}")
        for verifier in VERIFIERS)
    state_identity = (state_data.get("consumed_by") in VERIFIERS and one_creator_one_conflict
                      and all(identities.values()))
    default_denied = (not _can_i(lab, namespace, "default", "create", "configmaps")
                      and not _can_i(lab, namespace, "default", "get", f"configmaps/{STATE}"))
    lab.check("green", "The two named verifier identities can create challenge state in the fixture namespace and read its exact name. General reads and mutations are denied, and the default identity has neither grant",
              least_privilege and state_identity and default_denied,
              {"scoped_permissions_match": least_privilege, "default_identity_denied": default_denied,
               "state_creator_matches_winning_owned_job_identity": state_identity})
    (lab.evidence / "cross-verifier-challenge-observations.json").write_text(json.dumps({
        "namespace": namespace, "state_name": STATE, "state_uid": state_uid, "evidence_sha256": evidence_sha,
        "verifier_results": results, "persisted_state_data": state_data,
        "workloads": raw_workloads, "hardware_attestation_tested": False,
        "api_authentication_credentials_recorded": False}, indent=2, sort_keys=True) + "\n")
