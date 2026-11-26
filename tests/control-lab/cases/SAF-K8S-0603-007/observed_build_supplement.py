"""Observe a real inert build, collect its Kubernetes facts under another identity, and verify signatures."""
import base64
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

NAMESPACE = "saf-test"
PREFIX = "observed-build"
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
OPENSSL_IMAGE = "docker.io/alpine/openssl:3.3.2@sha256:5008e829163320a6e8166883c03e68189e8925ade4e7593ce242b36ee48d6b352"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
ENV_TYPE = "https://saf-k8s.example.test/build-environment/v1"
PROCESS_TYPE = "https://saf-k8s.example.test/build-process/v1"
TOKEN_VOLUME = {"name": "api", "projected": {"sources": [
    {"serviceAccountToken": {"expirationSeconds": 600, "path": "token"}},
    {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}}
]}}

BUILD_SCRIPT = r'''import datetime, hashlib, json, platform, ssl, sys, urllib.error, urllib.request
from pathlib import Path
AUTH=Path('/var/run/fixture-api')
BASE='https://kubernetes.default.svc/api/v1/namespaces/saf-test/configmaps/'
def call(method,name,obj=None):
    data=json.dumps(obj).encode() if obj is not None else None
    headers={'Authorization':'Bearer '+(AUTH/'token').read_text().strip()}
    if data is not None: headers['Content-Type']='application/merge-patch+json'
    req=urllib.request.Request(BASE+name,data=data,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,context=ssl.create_default_context(cafile=str(AUTH/'ca.crt')),timeout=8) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e: return e.code, {}
def digest(b): return hashlib.sha256(b).hexdigest()
source_bytes=Path('/input/source.json').read_bytes()
script_bytes=Path('/app/build.py').read_bytes()
source=json.loads(source_bytes)
artifact={'format':'saf-inert-transform-v1','value':source['value']+1}
artifact_bytes=json.dumps(artifact,sort_keys=True,separators=(',',':')).encode()
passed=artifact=={'format':'saf-inert-transform-v1','value':18}
facts={'tool':'python','python_version':sys.version.split()[0],'runtime_platform':platform.platform(),
       'machine':platform.machine(),'argv':sys.argv,'tool_sha256':digest(script_bytes),
       'input_sha256':digest(source_bytes),'output_sha256':digest(artifact_bytes),
       'transformation':'value-plus-one','test_passed':passed,
       'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
# The builder is deliberately unauthorized to modify collector-owned evidence.
evidence_write,_=call('PATCH','observed-evidence',{'data':{'builder-tamper':'denied'}})
artifact_write,_=call('PATCH','observed-output',{'data':{'artifact.json':artifact_bytes.decode(),
    'process.json':json.dumps(facts,sort_keys=True,separators=(',',':'))}})
print(json.dumps({'artifact_write':artifact_write,'evidence_write':evidence_write,
                  'artifact_sha256':facts['output_sha256'],'test_passed':passed}))
if artifact_write!=200 or evidence_write!=403 or not passed: sys.exit(1)
'''

COLLECTOR_SCRIPT = r'''import datetime, hashlib, json, ssl, sys, urllib.error, urllib.parse, urllib.request
from pathlib import Path
AUTH=Path('/var/run/fixture-api')
BASE='https://kubernetes.default.svc'
IMAGE=''' + repr(PYTHON_IMAGE) + r'''
def api(path):
    req=urllib.request.Request(BASE+path,headers={'Authorization':'Bearer '+(AUTH/'token').read_text().strip()})
    with urllib.request.urlopen(req,context=ssl.create_default_context(cafile=str(AUTH/'ca.crt')),timeout=8) as r:
        return json.load(r)
def patch(name,obj):
    data=json.dumps(obj).encode()
    req=urllib.request.Request(BASE+'/api/v1/namespaces/saf-test/configmaps/'+name,data=data,
      headers={'Authorization':'Bearer '+(AUTH/'token').read_text().strip(),
               'Content-Type':'application/merge-patch+json'},method='PATCH')
    with urllib.request.urlopen(req,context=ssl.create_default_context(cafile=str(AUTH/'ca.crt')),timeout=8) as r:
        return r.status
def digest(b): return hashlib.sha256(b).hexdigest()
job=api('/apis/batch/v1/namespaces/saf-test/jobs/observed-build')
query=urllib.parse.urlencode({'labelSelector':'job-name=observed-build'})
pods=api('/api/v1/namespaces/saf-test/pods?'+query)['items']
if len(pods)!=1 or job.get('status',{}).get('succeeded')!=1: sys.exit('producer Job/Pod not complete')
pod=pods[0]
container=pod['spec']['containers'][0]
status=pod.get('status',{}).get('containerStatuses',[{}])[0]
if container['image']!=IMAGE or not status.get('imageID') or not pod['spec'].get('nodeName'): sys.exit('runtime identity incomplete')
node=api('/api/v1/nodes/'+urllib.parse.quote(pod['spec']['nodeName'],safe=''))
node_info=node.get('status',{}).get('nodeInfo',{})
node_platform={k:node_info.get(k,'') for k in ('osImage','architecture','kernelVersion','containerRuntimeVersion','kubeletVersion')}
if not all(node_platform.values()): sys.exit('node platform inventory incomplete')
source=api('/api/v1/namespaces/saf-test/configmaps/observed-source')['data']['source.json'].encode()
output=api('/api/v1/namespaces/saf-test/configmaps/observed-output')['data']
artifact=output['artifact.json'].encode(); facts=json.loads(output['process.json'])
expected={'format':'saf-inert-transform-v1','value':json.loads(source)['value']+1}
if json.loads(artifact)!=expected or digest(source)!=facts['input_sha256'] or digest(artifact)!=facts['output_sha256']:
    sys.exit('collected source/process/output facts do not reconcile')
if digest(Path('/app/build.py').read_bytes())!=facts['tool_sha256'] or not facts['test_passed']:
    sys.exit('observed tool or test facts do not reconcile')
common={'name':'observed-artifact.json','digest':{'sha256':digest(artifact)}}
env={'_type':'https://in-toto.io/Statement/v1','subject':[common],
 'predicateType':'https://saf-k8s.example.test/build-environment/v1',
 'predicate':{'job_uid':job['metadata']['uid'],'pod_uid':pod['metadata']['uid'],
  'pod_name':pod['metadata']['name'],'node_name':pod['spec']['nodeName'],
  'image':container['image'],'image_id':status['imageID'],'node_platform':node_platform,
  'started_at':status.get('state',{}).get('terminated',{}).get('startedAt',''),
  'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}}
proc={'_type':'https://in-toto.io/Statement/v1','subject':[common],
 'predicateType':'https://saf-k8s.example.test/build-process/v1',
 'predicate':{'job_uid':job['metadata']['uid'],'pod_uid':pod['metadata']['uid'],
  'argv':facts['argv'],'tool':'python','python_version':facts['python_version'],
  'runtime_platform':facts['runtime_platform'],'machine':facts['machine'],
  'tool_sha256':facts['tool_sha256'],'input_sha256':facts['input_sha256'],
  'output_sha256':facts['output_sha256'],'transformation':facts['transformation'],
  'test_passed':facts['test_passed'],'observed_at':facts['observed_at'],
  'collector_recomputed_source_sha256':digest(source),
  'collector_recomputed_output_sha256':digest(artifact),
  'process_exit_code':status.get('state',{}).get('terminated',{}).get('exitCode',-1)}}
canonical=lambda x: json.dumps(x,sort_keys=True,separators=(',',':'))
code=api('/api/v1/namespaces/saf-test/configmaps/observed-code')['data']['build.py'].encode()
if digest(code)!=facts['tool_sha256']: sys.exit('code ConfigMap differs from executed tool bytes')
if proc['predicate']['process_exit_code']!=0: sys.exit('producer exit status was not successful')
status_code=patch('observed-evidence',{'data':{'environment.json':canonical(env),'process.json':canonical(proc)}})
print(json.dumps({'producer_job_complete':True,'image_id_observed':True,'node_observed':True,
 'source_output_reconciled':True,'evidence_write':status_code,'artifact_sha256':digest(artifact)}))
if status_code!=200: sys.exit(1)
'''


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def api_volume():
    return TOKEN_VOLUME


def _sa_role_binding(lab, name, rules):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name},
                "automountServiceAccountToken": False})
    role = name + "-role"
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": role}, "rules": rules})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": role},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role},
                "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": NAMESPACE}]})


def _job(lab, name, account, command, mounts, volumes):
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 100,
                         "template": {"metadata": {"labels": {"app": name}}, "spec": {
                             "serviceAccountName": account, "automountServiceAccountToken": False,
                             "restartPolicy": "Never", "volumes": [api_volume(), *volumes],
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                 "seccompProfile": {"type": "RuntimeDefault"}},
                             "containers": [{"name": "run", "image": PYTHON_IMAGE, "command": command,
                               "volumeMounts": [{"name": "api", "mountPath": "/var/run/fixture-api", "readOnly": True}, *mounts],
                               "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                             "limits": {"cpu": "100m", "memory": "96Mi"}},
                               "securityContext": {"allowPrivilegeEscalation": False,
                                                   "readOnlyRootFilesystem": True,
                                                   "capabilities": {"drop": ["ALL"]}}}]}}}})
    waited = lab.kubectl("wait", "--for=condition=complete", f"job/{name}", "--timeout=95s",
                         timeout=100, allow_failure=True)
    logs = lab.kubectl("logs", f"job/{name}", allow_failure=True)
    if waited.returncode != 0 or logs.returncode != 0:
        lab.block(f"Observed build fixture Job {name} did not complete")
    return json.loads(logs.stdout)


def _statement_for(category, payload):
    return payload.encode("utf-8")


def run_observed_build(lab):
    source_obj = {"format": "saf-inert-source-v1", "value": 17}
    source = canonical(source_obj).encode()
    code = {"build.py": BUILD_SCRIPT, "collect.py": COLLECTOR_SCRIPT}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "observed-source"},
                "immutable": True, "data": {"source.json": source.decode()}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "observed-code"},
                "immutable": True, "data": code})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "observed-output"}, "data": {}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "observed-evidence"}, "data": {}})

    _sa_role_binding(lab, "observed-builder", [{"apiGroups": [""], "resources": ["configmaps"],
        "resourceNames": ["observed-output"], "verbs": ["patch"]}])
    _sa_role_binding(lab, "observed-attestor", [
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["observed-source", "observed-code", "observed-output", "observed-evidence"],
         "verbs": ["get"]},
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["observed-evidence"], "verbs": ["patch"]},
        {"apiGroups": ["batch"], "resources": ["jobs"], "resourceNames": ["observed-build"], "verbs": ["get"]},
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]},
    ])
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "metadata": {"name": "observed-attestor-node-read"},
                "rules": [{"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                "metadata": {"name": "observed-attestor-node-read"},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                            "name": "observed-attestor-node-read"},
                "subjects": [{"kind": "ServiceAccount", "name": "observed-attestor", "namespace": NAMESPACE}]})

    builder = _job(lab, "observed-build", "observed-builder", ["python", "-B", "/app/build.py"],
                   [{"name": "code", "mountPath": "/app", "readOnly": True},
                                     {"name": "input", "mountPath": "/input", "readOnly": True}],
                   [{"name": "code", "configMap": {"name": "observed-code"}},
                    {"name": "input", "configMap": {"name": "observed-source"}}])
    output = json.loads(lab.kubectl("get", "configmap", "observed-output", "-o", "json").stdout)["data"]
    artifact = output["artifact.json"].encode()
    artifact_digest = digest(artifact)
    facts = json.loads(output["process.json"])
    expected = canonical({"format": "saf-inert-transform-v1", "value": 18}).encode()
    passed = (builder["artifact_write"] == 200 and builder["evidence_write"] == 403
              and builder["test_passed"] and artifact == expected
              and facts["input_sha256"] == digest(source)
              and facts["output_sha256"] == artifact_digest
              and facts["tool_sha256"] == digest(BUILD_SCRIPT.encode()))
    lab.check("positive", "A real build Job transforms inert bytes and reports its running tool, input, output, and denied evidence write",
              passed, {"artifact_sha256": artifact_digest, "builder_artifact_write": builder["artifact_write"],
                       "builder_evidence_write_denied": builder["evidence_write"] == 403,
                       "observed_python_version": facts["python_version"], "transformation_test_passed": facts["test_passed"]})

    collector = _job(lab, "observed-attestor", "observed-attestor", ["python", "-B", "/app/collect.py"],
                     [{"name": "code", "mountPath": "/app", "readOnly": True}],
                     [{"name": "code", "configMap": {"name": "observed-code"}}])
    evidence_data = json.loads(lab.kubectl("get", "configmap", "observed-evidence", "-o", "json").stdout)["data"]
    env_payload = json.loads(evidence_data["environment.json"])
    process_payload = json.loads(evidence_data["process.json"])
    observed = env_payload["predicate"]
    producer_job = json.loads(lab.kubectl("get", "job", "observed-build", "-o", "json").stdout)
    producer_pods = json.loads(lab.kubectl("get", "pods", "-l", "job-name=observed-build", "-o", "json").stdout)["items"]
    if len(producer_pods) != 1:
        lab.block("Expected exactly one observed build Pod")
    producer_pod = producer_pods[0]
    host_status = producer_pod["status"]["containerStatuses"][0]
    node_name = producer_pod["spec"]["nodeName"]
    host_node = json.loads(lab.kubectl("get", "node", node_name, "-o", "json").stdout)
    node_info = host_node["status"]["nodeInfo"]
    node_platform = {k: node_info[k] for k in ("osImage", "architecture", "kernelVersion",
                                               "containerRuntimeVersion", "kubeletVersion")}
    host_observed = {"job_uid": producer_job["metadata"]["uid"],
                     "pod_uid": producer_pod["metadata"]["uid"], "node_name": node_name,
                     "image": producer_pod["spec"]["containers"][0]["image"],
                     "image_id": host_status["imageID"], "node_platform": node_platform}
    reconciled = (collector["producer_job_complete"] and collector["image_id_observed"]
                  and collector["node_observed"] and collector["source_output_reconciled"]
                  and collector["evidence_write"] == 200
                  and env_payload["subject"] == process_payload["subject"]
                  and env_payload["subject"][0]["digest"]["sha256"] == artifact_digest
                  and process_payload["predicate"]["collector_recomputed_output_sha256"] == artifact_digest
                  and all(observed.get(k) == v for k, v in host_observed.items()))
    lab.check("green", "A separate Kubernetes identity collects actual Job, Pod, image, node, and artifact facts",
              reconciled, {"attestor_evidence_write": collector["evidence_write"],
                           "job_uid_matches_api": observed["job_uid"] == host_observed["job_uid"],
                           "pod_uid_matches_api": observed["pod_uid"] == host_observed["pod_uid"],
                           "image_id_observed": bool(observed["image_id"]), "node_name_observed": bool(observed["node_name"]),
                           "node_platform_observed": bool(observed["node_platform"]),
                           "artifact_sha256": artifact_digest})

    with tempfile.TemporaryDirectory(prefix="saf-observed-build-") as tmp:
        work = Path(tmp)
        policy = {"payload_type": PAYLOAD_TYPE, "subject_name": "observed-artifact.json",
                  "subject_sha256": artifact_digest, "image": PYTHON_IMAGE,
                  "tool_sha256": digest(BUILD_SCRIPT.encode()), "input_sha256": digest(source),
                  "observed_runtime": host_observed,
                  "categories": {}}
        signatures = {}
        for category, statement in (("environment", env_payload), ("process", process_payload)):
            payload = evidence_data[f"{category}.json"].encode()
            payload_path = work / f"{category}.json"
            payload_path.write_bytes(payload)
            private, public, pae, sig = (work / f"{category}.{ext}" for ext in ("key", "pub", "pae", "sig"))
            lab.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private), timeout=20)
            private.chmod(0o600)
            lab.command("openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public))
            payload_type = PAYLOAD_TYPE.encode()
            pae.write_bytes(b"DSSEv1 " + str(len(payload_type)).encode() + b" " + payload_type + b" "
                            + str(len(payload)).encode() + b" " + payload)
            lab.command("openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(sig), str(pae))
            policy["categories"][category] = {"predicate_type": ENV_TYPE if category == "environment" else PROCESS_TYPE,
                                              "public_key_sha256": "sha256:" + digest(public.read_bytes())}
            signatures[category] = {"signature": sig.read_bytes(), "public": public.read_bytes(), "payload": payload}
        policy_path = work / "policy.json"
        policy_path.write_text(canonical(policy))
        consumer = Path(__file__).with_name("observed_consumer.py")
        for category, record in signatures.items():
            (work / f"{category}.json").write_bytes(record["payload"])
            (work / f"{category}.sig").write_bytes(record["signature"])
            (work / f"{category}.pub").write_bytes(record["public"])
        accepted = lab.command("python3", str(consumer), str(work), allow_failure=True)
        decision = json.loads(accepted.stdout) if accepted.stdout.strip() else {}
        # Counterfactual policy changes the required subject without changing either signed statement.
        bad_policy = dict(policy)
        bad_policy["subject_sha256"] = "0" * 64
        bad_path = work / "bad-policy.json"
        bad_path.write_text(canonical(bad_policy))
        rejected = lab.command("python3", str(consumer), str(work), str(bad_path), allow_failure=True)
        bad_decision = json.loads(rejected.stdout) if rejected.stdout.strip() else {}
        decision_ok = accepted.returncode == 0 and decision.get("consumer_accept") is True
        negative_ok = rejected.returncode != 0 and bad_decision.get("consumer_accept") is False
        lab.check("green", "An independent verifier accepts both category signatures only for the observed artifact subject",
                  decision_ok and negative_ok,
                  {"environment_attestation_accepted": decision.get("categories", {}).get("environment", False),
                   "process_attestation_accepted": decision.get("categories", {}).get("process", False),
                   "wrong_subject_rejected": negative_ok, "signing_keys_retained_in_evidence": False})
    (lab.evidence / "observed-build-summary.json").write_text(json.dumps({
        "artifact_sha256": artifact_digest, "builder_evidence_write_denied": builder["evidence_write"] == 403,
        "producer_job_uid": host_observed["job_uid"], "producer_pod_uid": host_observed["pod_uid"],
        "producer_image": host_observed["image"], "producer_image_id": host_observed["image_id"],
        "producer_node": host_observed["node_name"], "collector_reconciled": reconciled,
        "consumer_accepted": decision_ok, "wrong_subject_rejected": negative_ok,
        "public_key_fingerprints": {name: policy["categories"][name]["public_key_sha256"] for name in signatures}}, indent=2) + "\n")
