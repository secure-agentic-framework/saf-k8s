"""Bounded in-cluster recipient-bound ciphertext release reference fixture."""

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAMESPACE = "saf-0804-recipient"
AGENT = "fixture-recipient-release-agent"
ROLE = "fixture-recipient-release-create"
SERVICE_ACCOUNT = "fixture-recipient-release"
SUBJECT = "fixture-enclave-workload"
RESOURCE = "fixture-public-checkpoint"
RECIPIENT_A = "fixture-recipient-a"
RECIPIENT_B = "fixture-recipient-b"
PAYLOAD = b"SAF inert recipient binding marker v1\n"

# The agent only receives public evidence and ciphertext. It validates the exact
# request tuple and freshness, then creates one bounded ciphertext record.
AGENT_SCRIPT = r'''import base64, hashlib, json, os, pathlib, ssl, time, urllib.request
root = pathlib.Path('/input')
item = json.loads((root / 'input.json').read_text())
policy = item['policy']; evidence = item['evidence']; request = item['request']
ciphertext = base64.b64decode(item['ciphertext_b64'], validate=True)
now = int(time.time())
checks = {
  'approved_evidence': evidence.get('appraisal') == policy['appraisal'],
  'subject': evidence.get('subject') == policy['subject'] == request.get('subject'),
  'resource': evidence.get('resource') == policy['resource'] == request.get('resource'),
  'recipient': evidence.get('recipient') == policy['recipient'] == request.get('recipient'),
  'key_binding': evidence.get('recipient_public_sha256') == policy['recipient_public_sha256'] == request.get('recipient_public_sha256'),
  'fresh': evidence.get('issued_at', 0) <= now < evidence.get('expires_at', 0),
  'ciphertext_binding': hashlib.sha256(ciphertext).hexdigest() == evidence.get('ciphertext_sha256'),
}
if not all(checks.values()):
  print(json.dumps({'decision':'DENIED','failed_checks':sorted(key for key,value in checks.items() if not value)},separators=(',',':')))
  raise SystemExit(0)
record = {
  'decision_id': evidence['decision_id'], 'subject': evidence['subject'],
  'resource': evidence['resource'], 'recipient': evidence['recipient'],
  'recipient_public_sha256': evidence['recipient_public_sha256'],
  'ciphertext_sha256': evidence['ciphertext_sha256'],
  'ciphertext_b64': item['ciphertext_b64'],
}
token = pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount/token').read_text()
ca = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
ctx = ssl.create_default_context(cafile=ca)
body = json.dumps({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':item['output_name'],'namespace':os.environ['POD_NAMESPACE'],'labels':{'fixture.example/purpose':'recipient-release-record'}},'immutable':True,'data':{'record.json':json.dumps(record,separators=(',',':'))}}).encode()
url = 'https://' + os.environ['KUBERNETES_SERVICE_HOST'] + ':' + os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS','443') + '/api/v1/namespaces/' + os.environ['POD_NAMESPACE'] + '/configmaps'
req = urllib.request.Request(url, data=body, method='POST', headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
with urllib.request.urlopen(req, context=ctx, timeout=8) as response:
  if response.status != 201: raise RuntimeError('release record API create failed')
print('RELEASED')
'''


def _run(lab, *args, timeout=30, allow_failure=False):
    return lab.kubectl(*args, timeout=timeout, allow_failure=allow_failure)


def _create(lab, obj):
    namespace = obj.get("metadata", {}).get("namespace", NAMESPACE)
    result = lab.kubectl("-n", namespace, "create", "-f", "-", "-o", "json",
                         payload=json.dumps(obj), timeout=35)
    return json.loads(result.stdout)


def _keypair(directory, stem):
    private = directory / f"{stem}.pem"
    public = directory / f"{stem}.pub.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(private)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=True, timeout=15)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=10)
    os.chmod(private, 0o600)
    modulus = subprocess.run(["openssl", "rsa", "-pubin", "-in", str(public),
                              "-noout", "-modulus"], capture_output=True, text=True,
                             check=True, timeout=10).stdout.strip()
    label, separator, digits = modulus.partition("=")
    if label != "Modulus" or not separator:
        raise ValueError("fixture RSA modulus could not be read")
    return private, public.read_bytes(), int(digits, 16)


def _ciphertext(directory, public_bytes):
    public_path = directory / "recipient.pub.pem"
    plain_path = directory / "inert-marker.bin"
    cipher_path = directory / "cipher.bin"
    public_path.write_bytes(public_bytes)
    plain_path.write_bytes(PAYLOAD)
    subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", str(public_path),
                    "-in", str(plain_path), "-out", str(cipher_path), "-pkeyopt", "rsa_padding_mode:oaep",
                    "-pkeyopt", "rsa_oaep_md:sha256"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True, timeout=10)
    return cipher_path.read_bytes()


def _decrypt(private_path, ciphertext, directory, suffix):
    cipher_path = directory / f"cipher-{suffix}.bin"
    plain_path = directory / f"plain-{suffix}.bin"
    cipher_path.write_bytes(ciphertext)
    result = subprocess.run(["openssl", "pkeyutl", "-decrypt", "-inkey", str(private_path),
                             "-in", str(cipher_path), "-out", str(plain_path),
                             "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                            check=False, timeout=10)
    if result.returncode:
        diagnostic = (result.stderr or "").lower()
        recognized_oaep_rejection = "oaep decoding error" in diagnostic
        return False, recognized_oaep_rejection
    return plain_path.read_bytes() == PAYLOAD, False


def _input(policy, evidence, request, ciphertext, output_name):
    return {"policy": policy, "evidence": evidence, "request": request,
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"), "output_name": output_name}


def _job(name, input_name):
    return {"apiVersion":"batch/v1","kind":"Job","metadata":{"name":name,"namespace":NAMESPACE},
            "spec":{"backoffLimit":0,"activeDeadlineSeconds":45,"ttlSecondsAfterFinished":30,
                    "template":{"metadata":{"labels":{"fixture.example/component":"recipient-release-agent"}},
                      "spec":{"restartPolicy":"Never","serviceAccountName":SERVICE_ACCOUNT,
                        "automountServiceAccountToken":True,
                        "securityContext":{"runAsNonRoot":True,"runAsUser":65534,"seccompProfile":{"type":"RuntimeDefault"}},
                        "containers":[{"name":"agent","image":IMAGE,"imagePullPolicy":"IfNotPresent",
                          "command":["python","/input/agent.py"],"securityContext":{"allowPrivilegeEscalation":False,
                            "readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]}},
                          "resources":{"requests":{"cpu":"5m","memory":"24Mi"},"limits":{"cpu":"100m","memory":"96Mi"}},
                          "env":[{"name":"POD_NAMESPACE","valueFrom":{"fieldRef":{"fieldPath":"metadata.namespace"}}},
                                 {"name":"PYTHONDONTWRITEBYTECODE","value":"1"}],
                          "volumeMounts":[{"name":"input","mountPath":"/input","readOnly":True}]}],
                        "volumes":[{"name":"input","configMap":{"name":input_name,"defaultMode":292}}]}}}}


def _wait_job(lab, name):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = _run(lab, "-n", NAMESPACE, "get", "job", name, "-o", "json")
        status = json.loads(result.stdout).get("status", {})
        if status.get("succeeded") == 1:
            return True
        if status.get("failed", 0):
            return False
        time.sleep(0.5)
    return False


def _has_record(lab, name):
    result = _run(lab, "-n", NAMESPACE, "get", "configmap", name, "-o", "json", allow_failure=True)
    if result.returncode:
        diagnostic = result.stderr or ""
        expected = f'configmaps "{name}" not found'
        if "(NotFound)" in diagnostic and expected in diagnostic:
            return False, None
        lab.block("Recipient release record lookup failed for a reason other than exact NotFound: "
                  + diagnostic.strip()[:500])
    obj = json.loads(result.stdout)
    return True, obj


def _job_logs(lab, name):
    return _run(lab, "-n", NAMESPACE, "logs", "job/" + name, timeout=20).stdout.strip()


def run(lab):
    _create(lab, {"apiVersion":"v1","kind":"Namespace","metadata":{"name":NAMESPACE,
             "labels":{"pod-security.kubernetes.io/enforce":"restricted"}}})
    _create(lab, {"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":SERVICE_ACCOUNT,"namespace":NAMESPACE}})
    _create(lab, {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":ROLE,"namespace":NAMESPACE},
                  "rules":[{"apiGroups":[""],"resources":["configmaps"],"verbs":["create"]}]})
    _create(lab, {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":ROLE,"namespace":NAMESPACE},
                  "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":ROLE},
                  "subjects":[{"kind":"ServiceAccount","name":SERVICE_ACCOUNT,"namespace":NAMESPACE}]})

    with tempfile.TemporaryDirectory(prefix="saf-0804-recipient-") as temp:
        directory = Path(temp)
        first = _keypair(directory, "first")
        second = _keypair(directory, "second")
        # Keep the ciphertext in range for both keys so the negative test
        # reaches OAEP padding verification on either OpenSSL implementation.
        (private_a, public_a, modulus_a), (private_b, _public_b, modulus_b) = sorted(
            (first, second), key=lambda pair: pair[2])
        ciphertext = _ciphertext(directory, public_a)
        if not 0 < int.from_bytes(ciphertext, "big") < modulus_a < modulus_b:
            lab.block("The fixed recipient fixture does not satisfy its OAEP comparison precondition")
        public_digest = hashlib.sha256(public_a).hexdigest()
        ciphertext_digest = hashlib.sha256(ciphertext).hexdigest()
        now = int(time.time())
        policy = {"appraisal":"fixture-approved","subject":SUBJECT,"resource":RESOURCE,
                  "recipient":RECIPIENT_A,"recipient_public_sha256":public_digest}
        base_evidence = {"appraisal":"fixture-approved","subject":SUBJECT,"resource":RESOURCE,
                         "recipient":RECIPIENT_A,"recipient_public_sha256":public_digest,
                         "issued_at":now-5,"expires_at":now+240,"decision_id":"fixture-decision-01",
                         "ciphertext_sha256":ciphertext_digest}
        request = {"subject":SUBJECT,"resource":RESOURCE,"recipient":RECIPIENT_A,
                   "recipient_public_sha256":public_digest}
        cases = [
            ("wrong-receipt-recipient", dict(base_evidence, recipient=RECIPIENT_B), request, "fixture-release-wrong-receipt"),
            ("wrong-request-recipient", base_evidence, dict(request, recipient=RECIPIENT_B), "fixture-release-wrong-request"),
        ]
        negatives = {}
        for name, evidence, req, output_name in cases:
            input_name = name + "-input"
            _create(lab, {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":input_name,"namespace":NAMESPACE},
                          "immutable":True,"data":{"agent.py":AGENT_SCRIPT,"input.json":json.dumps(_input(policy,evidence,req,ciphertext,output_name),separators=(",",":"))}})
            _create(lab, _job(name, input_name))
            completed = _wait_job(lab, name)
            decision = json.loads(_job_logs(lab, name)) if completed else {}
            exists, _ = _has_record(lab, output_name)
            negatives[name] = {"job_completed": completed, "decision": decision,
                               "release_record_exists": exists}
        denied = all(row == {"job_completed": True,
                             "decision": {"decision": "DENIED", "failed_checks": ["recipient"]},
                             "release_record_exists": False}
                     for row in negatives.values())
        input_name = "matching-recipient-input"
        output_name = "fixture-release-matching-recipient"
        _create(lab, {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":input_name,"namespace":NAMESPACE},
                      "immutable":True,"data":{"agent.py":AGENT_SCRIPT,"input.json":json.dumps(_input(policy,base_evidence,request,ciphertext,output_name),separators=(",",":"))}})
        _create(lab, _job("matching-recipient", input_name))
        completed = _wait_job(lab, "matching-recipient")
        positive_log = _job_logs(lab, "matching-recipient") if completed else ""
        exists, release_obj = _has_record(lab, output_name)
        record = json.loads(release_obj["data"]["record.json"]) if release_obj else {}
        expected_record_fields = {"decision_id","subject","resource","recipient","recipient_public_sha256",
                                  "ciphertext_sha256","ciphertext_b64"}
        metadata = release_obj.get("metadata", {}) if release_obj else {}
        record_bytes = base64.b64decode(record["ciphertext_b64"], validate=True) if record else b""
        observed_ciphertext_digest = hashlib.sha256(record_bytes).hexdigest() if record else ""
        tuple_bound = bool(release_obj and release_obj.get("immutable") is True
                           and metadata.get("name") == output_name and metadata.get("namespace") == NAMESPACE
                           and bool(metadata.get("uid"))
                           and set(release_obj.get("data", {})) == {"record.json"}
                           and set(record) == expected_record_fields
                           and record.get("decision_id") == "fixture-decision-01"
                           and record.get("subject") == SUBJECT and record.get("resource") == RESOURCE
                           and record.get("recipient") == RECIPIENT_A
                           and record.get("recipient_public_sha256") == public_digest
                           and record.get("ciphertext_sha256") == ciphertext_digest
                           and observed_ciphertext_digest == ciphertext_digest)
        same_key, _same_error = _decrypt(private_a, record_bytes, directory, "a") if record else (False, False)
        _wrong_plain, wrong_key_oaep_error = _decrypt(private_b, record_bytes, directory, "b") if record else (False, False)
        passed = completed and positive_log == "RELEASED" and exists and tuple_bound and same_key and wrong_key_oaep_error and denied
        (lab.evidence / "recipient-release-observations.json").write_text(json.dumps({
            "image":IMAGE,"namespace":NAMESPACE,"subject":SUBJECT,"resource":RESOURCE,"recipient":RECIPIENT_A,
            "recipient_public_sha256":public_digest,"ciphertext_sha256":ciphertext_digest,
            "marker_sha256":hashlib.sha256(PAYLOAD).hexdigest(),"matching_decision_record_created":bool(completed and exists),
            "tuple_bound":tuple_bound,"matching_recipient_recovers_exact_marker":same_key,
            "negative_decisions": negatives, "ciphertext_in_range_for_both_keys": True,
            "second_fixture_key_oaep_rejected":wrong_key_oaep_error,
            "wrong_receipt_or_request_recipient_denied_without_record":denied,
            "private_keys_retained":False,"plaintext_retained":False,
            "provider_tee_or_kms_tested":False},indent=2)+"\n")
        lab.check("recipient", "Fresh approval releases only ciphertext bound to the intended recipient, and mismatched recipients produce no release record",
                  passed, {"matching_decision_record_created":bool(completed and exists),"tuple_bound":tuple_bound,
                           "matching_recipient_recovers_exact_marker":same_key,"second_fixture_key_oaep_rejected":wrong_key_oaep_error,
                           "wrong_receipt_or_request_recipient_denied_without_record":denied})
