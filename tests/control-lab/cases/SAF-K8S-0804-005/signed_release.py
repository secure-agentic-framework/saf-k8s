"""Synthetic signed-result recipient release witness for SAF-K8S-0804-005.

The verifier signing key exists only in a temporary host directory. The relying
party Job receives only the pinned fixture trust root, an immutable RP policy,
a signed claims document, and ciphertext for the public inert marker.
"""

import base64
import hashlib
import importlib.util
import json
import secrets
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The RP checks a detached OpenSSL signature before evaluating claims or creating
# any release record. It never receives a private signing or recipient key.
RP_SCRIPT = r'''import base64,hashlib,json,os,pathlib,shutil,ssl,subprocess,time,urllib.error,urllib.request
from urllib.request import ProxyHandler,HTTPSHandler,build_opener
root=pathlib.Path('/input'); trust=pathlib.Path('/trust'); policy_root=pathlib.Path('/policy')
item=json.loads((root/'input.json').read_text()); request=item['request']; output_name=item['output_name']
try:
    if shutil.which('openssl') is None: raise FileNotFoundError('openssl')
    sig=base64.b64decode((root/'signature.b64').read_text(),validate=True)
    sigpath=pathlib.Path('/work/result.sig'); sigpath.write_bytes(sig)
    verified=subprocess.run(['openssl','dgst','-sha256','-verify',str(trust/'verifier-public.pem'),'-signature',str(sigpath),str(root/'result.json')],capture_output=True,text=True,timeout=8)
except FileNotFoundError:
    print(json.dumps({'decision':'SETUP_ERROR','reason':'openssl_verifier_unavailable'},separators=(',',':'))); raise SystemExit(0)
except Exception:
    print(json.dumps({'decision':'SETUP_ERROR','reason':'signature_verifier_setup_failed'},separators=(',',':'))); raise SystemExit(0)
try:
    policy=json.loads((policy_root/'policy.json').read_text())
    claims=json.loads((root/'result.json').read_bytes())
    ciphertext=base64.b64decode(item['ciphertext_b64'],validate=True)
except Exception:
    print(json.dumps({'decision':'SETUP_ERROR','reason':'fixture_input_parse_failed'},separators=(',',':'))); raise SystemExit(0)
signature_valid=verified.returncode==0 and verified.stdout.strip()=='Verified OK'
now=int(time.time()); issued=claims.get('issued_at'); expires=claims.get('expires_at')
checks={
  'signature':signature_valid,
  'verifier_identity':claims.get('verifier_id')==policy.get('verifier_id') and claims.get('issuer')==policy.get('issuer'),
  'appraisal':claims.get('appraisal_status')==policy.get('appraisal_status')=='approved',
  'subject':claims.get('subject')==policy.get('subject')==request.get('subject'),
  'request_reference':claims.get('request_reference')==policy.get('request_reference')==request.get('request_reference'),
  'resource':claims.get('resource')==policy.get('resource')==request.get('resource'),
  'recipient':claims.get('recipient')==policy.get('recipient')==request.get('recipient'),
  'recipient_key_digest':claims.get('recipient_public_sha256')==policy.get('recipient_public_sha256')==request.get('recipient_public_sha256'),
  'challenge':claims.get('challenge')==policy.get('challenge')==request.get('challenge'),
  'freshness':isinstance(issued,int) and isinstance(expires,int) and issued<=now<expires and 0<expires-issued<=policy.get('max_validity_seconds',0),
  'ciphertext_binding':hashlib.sha256(ciphertext).hexdigest()==claims.get('ciphertext_sha256')==request.get('ciphertext_sha256'),
}
if not all(checks.values()):
    print(json.dumps({'decision':'DENIED','signature_valid':signature_valid,'failed_checks':sorted(k for k,v in checks.items() if not v)},separators=(',',':')))
    raise SystemExit(0)
record={'decision_id':claims['decision_id'],'verifier_id':claims['verifier_id'],'subject':claims['subject'],
        'request_reference':claims['request_reference'],'resource':claims['resource'],'recipient':claims['recipient'],
        'recipient_public_sha256':claims['recipient_public_sha256'],'challenge_sha256':hashlib.sha256(claims['challenge'].encode()).hexdigest(),
        'result_sha256':hashlib.sha256((root/'result.json').read_bytes()).hexdigest(),
        'signature_sha256':hashlib.sha256(sig).hexdigest(),'ciphertext_sha256':claims['ciphertext_sha256'],
        'ciphertext_b64':item['ciphertext_b64']}
try:
    ident=pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount'); token=ident.joinpath('token').read_text().strip(); ca=ident/'ca.crt'
    ctx=ssl.create_default_context(cafile=str(ca)); host=os.environ['KUBERNETES_SERVICE_HOST']; port=os.environ.get('KUBERNETES_SERVICE_PORT_HTTPS','443'); ns=os.environ['POD_NAMESPACE']
    body=json.dumps({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':output_name,'namespace':ns,'labels':{'fixture.example/purpose':'signed-recipient-release'}},'immutable':True,'data':{'record.json':json.dumps(record,separators=(',',':'))}}).encode()
    url=f'https://{host}:{port}/api/v1/namespaces/{ns}/configmaps'; req=urllib.request.Request(url,data=body,method='POST',headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    with urllib.request.build_opener(ProxyHandler({}),HTTPSHandler(context=ctx)).open(req,timeout=8) as response:
        if response.status!=201: raise RuntimeError('unexpected API create status')
except Exception:
    print(json.dumps({'decision':'SETUP_ERROR','reason':'release_record_create_failed'},separators=(',',':'))); raise SystemExit(0)
print(json.dumps({'decision':'RELEASED','verifier_id':claims['verifier_id'],'result_sha256':record['result_sha256']},separators=(',',':')))
'''


def _recipient_module():
    path = HERE / "recipient_release.py"
    spec = importlib.util.spec_from_file_location("saf_0804_005_recipient_release", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("recipient release companion could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _job(name, input_name, trust_name, policy_name):
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": "saf-0804-recipient"},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 45,
                 "ttlSecondsAfterFinished": 30,
                 "template": {"metadata": {"labels": {"fixture.example/component": "signed-release-rp"}},
                    "spec": {"restartPolicy": "Never",
                      "serviceAccountName": "fixture-recipient-release",
                      "automountServiceAccountToken": True,
                      "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                          "runAsGroup": 65534, "fsGroup": 65534,
                                          "seccompProfile": {"type": "RuntimeDefault"}},
                      "containers": [{"name": "rp", "image": "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
                          "imagePullPolicy": "IfNotPresent", "command": ["python", "/input/agent.py"],
                          "securityContext": {"allowPrivilegeEscalation": False,
                              "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                          "resources": {"requests": {"cpu": "5m", "memory": "24Mi"},
                                        "limits": {"cpu": "100m", "memory": "96Mi"}},
                          "env": [{"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
                                  {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
                          "volumeMounts": [{"name": "input", "mountPath": "/input", "readOnly": True},
                                           {"name": "trust", "mountPath": "/trust", "readOnly": True},
                                           {"name": "policy", "mountPath": "/policy", "readOnly": True},
                                           {"name": "work", "mountPath": "/work"}]}],
                      "volumes": [{"name": "input", "configMap": {"name": input_name, "defaultMode": 292}},
                                 {"name": "trust", "configMap": {"name": trust_name, "defaultMode": 292}},
                                 {"name": "policy", "configMap": {"name": policy_name, "defaultMode": 292}},
                                 {"name": "work", "emptyDir": {"sizeLimit": "1Mi"}}]}}}}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(private_key, payload, directory, stem):
    input_path = Path(directory) / f"{stem}.json"
    signature_path = Path(directory) / f"{stem}.sig"
    input_path.write_bytes(payload)
    import subprocess
    result = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private_key),
                             "-out", str(signature_path), str(input_path)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            check=False, timeout=10)
    if result.returncode != 0 or not signature_path.exists():
        raise RuntimeError("fixture signing failed")
    return signature_path.read_bytes()


def _write_raw(lab, raw):
    (lab.evidence / "signed-release-observations.json").write_text(
        json.dumps(raw, sort_keys=True, indent=2) + "\n")


def run(lab):
    base = _recipient_module()
    from tempfile import TemporaryDirectory
    raw = {"fixture": "synthetic-verifier-result-recipient-release-v1",
           "provider_tee_or_kms_tested": False, "private_keys_retained": False,
           "plaintext_retained": False, "cases": {}, "setup_errors": []}
    outcomes = {}
    with TemporaryDirectory(prefix="saf-0804-signed-release-") as temp:
        directory = Path(temp)
        try:
            trusted_private, trusted_public, _ = base._keypair(directory, "verifier-trusted")
            untrusted_private, _untrusted_public, _ = base._keypair(directory, "verifier-untrusted")
            recipient_pair = base._keypair(directory, "recipient-one")
            unrelated_pair = base._keypair(directory, "recipient-two")
            (recipient_private, recipient_public, recipient_modulus), (other_recipient_private, _other_recipient_public, other_modulus) = sorted(
                (recipient_pair, unrelated_pair), key=lambda pair: pair[2])
            ciphertext = base._ciphertext(directory, recipient_public)
            ciphertext_integer = int.from_bytes(ciphertext, "big")
            if not 0 < ciphertext_integer < recipient_modulus < other_modulus:
                raise RuntimeError("recipient ciphertext comparison precondition failed")
        except Exception as exc:
            raw["setup_errors"].append("host_crypto_setup_" + type(exc).__name__)
            _write_raw(lab, raw)
            lab.block("Synthetic signed-release host crypto setup failed")
        recipient_digest = hashlib.sha256(recipient_public).hexdigest()
        ciphertext_digest = hashlib.sha256(ciphertext).hexdigest()
        verifier_id = "fixture-verifier-root-v1"
        issuer = "fixture-verifier"
        appraise = "approved"
        subject = base.SUBJECT
        resource = base.RESOURCE
        request_reference = "fixture-request-0804-005-01"
        trust_name = "signed-release-trust-root"
        trust_obj = base._create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": trust_name, "namespace": base.NAMESPACE}, "immutable": True,
            "data": {"verifier-public.pem": trusted_public.decode("ascii")}})
        public_digest = hashlib.sha256(trusted_public).hexdigest()
        challenge_per_case = {name: secrets.token_hex(16) for name in
                              ("positive", "wrong-request-reference", "wrong-challenge", "expired", "untrusted-verifier")}
        outcomes = {}
        scenarios = [
            {"name": "wrong-request-reference", "claim_overrides": {"request_reference": "fixture-request-other"},
             "signer": "trusted", "expected_failed": ["request_reference"]},
            {"name": "wrong-challenge", "claim_overrides": {"challenge": "fixture-challenge-other"},
             "signer": "trusted", "expected_failed": ["challenge"]},
            {"name": "expired", "time_mode": "expired", "signer": "trusted", "expected_failed": ["freshness"]},
            {"name": "untrusted-verifier", "claim_overrides": {}, "signer": "untrusted",
             "expected_failed": ["signature"]},
            {"name": "positive", "claim_overrides": {}, "signer": "trusted", "expected_failed": []},
        ]
        for scenario in scenarios:
            name = scenario["name"]
            now = int(time.time())
            challenge = challenge_per_case[name]
            policy = {"verifier_id": verifier_id, "issuer": issuer, "appraisal_status": appraise,
                      "subject": subject, "request_reference": request_reference,
                      "resource": resource, "recipient": base.RECIPIENT_A,
                      "recipient_public_sha256": recipient_digest, "challenge": challenge,
                      "max_validity_seconds": 1200}
            request = {"subject": subject, "request_reference": request_reference,
                       "resource": resource, "recipient": base.RECIPIENT_A,
                       "recipient_public_sha256": recipient_digest, "challenge": challenge,
                       "ciphertext_sha256": ciphertext_digest}
            claims = {"verifier_id": verifier_id, "issuer": issuer, "appraisal_status": appraise,
                      "decision_id": "fixture-signed-decision-" + name,
                      "subject": subject, "request_reference": request_reference,
                      "resource": resource, "recipient": base.RECIPIENT_A,
                      "recipient_public_sha256": recipient_digest, "challenge": challenge,
                      "issued_at": now - 5, "expires_at": now + 900,
                      "ciphertext_sha256": ciphertext_digest}
            claims.update(scenario.get("claim_overrides", {}))
            if scenario.get("time_mode") == "expired":
                claims["issued_at"] = now - 120
                claims["expires_at"] = now - 60
            payload = _canonical(claims)
            signer_key = trusted_private if scenario["signer"] == "trusted" else untrusted_private
            try:
                signature = _sign(signer_key, payload, directory, name)
            except Exception as exc:
                raw["setup_errors"].append("fixture_signature_setup_" + type(exc).__name__)
                raw["cases"][name] = {"setup_error": "fixture_signature_setup_failed"}
                _write_raw(lab, raw)
                lab.block("Synthetic verifier signature setup failed")
            input_name = "signed-release-" + name + "-input"
            policy_name = "signed-release-" + name + "-policy"
            output_name = "signed-release-" + name + "-record"
            policy_obj = base._create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": policy_name, "namespace": base.NAMESPACE}, "immutable": True,
                "data": {"policy.json": _canonical(policy).decode("utf-8")}})
            input_obj = base._create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": input_name, "namespace": base.NAMESPACE}, "immutable": True,
                "data": {"agent.py": RP_SCRIPT, "input.json": json.dumps({
                    "request": request, "output_name": output_name,
                    "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii")},
                    sort_keys=True, separators=(",", ":")),
                    "result.json": payload.decode("utf-8"),
                    "signature.b64": base64.b64encode(signature).decode("ascii")}})
            job_name = "signed-release-" + name
            base._create(lab, _job(job_name, input_name, trust_name, policy_name))
            completed = base._wait_job(lab, job_name)
            log_text = base._job_logs(lab, job_name) if completed else ""
            try:
                decision = json.loads(log_text) if log_text else {}
            except json.JSONDecodeError:
                decision = {"decision": "INVALID_LOG_SHAPE"}
            exists, record_obj = base._has_record(lab, output_name)
            record = {}
            record_json_valid = False
            if record_obj:
                try:
                    record = json.loads(record_obj.get("data", {}).get("record.json", ""))
                    record_json_valid = isinstance(record, dict)
                except (json.JSONDecodeError, TypeError, AttributeError):
                    record = {}
            outcomes[name] = {"job_completed": completed,
                "record_json_valid": record_json_valid,
                "decision": decision, "release_record_exists": exists,
                "result_sha256": hashlib.sha256(payload).hexdigest(),
                "signature_sha256": hashlib.sha256(signature).hexdigest(),
                "trust_root_sha256": public_digest,
                "trust_root_config_uid": trust_obj.get("metadata", {}).get("uid"),
                "policy_config_uid": policy_obj.get("metadata", {}).get("uid"),
                "input_config_uid": input_obj.get("metadata", {}).get("uid"),
                "challenge_sha256": hashlib.sha256(challenge.encode()).hexdigest(),
                "record_metadata": ({"name": record_obj.get("metadata", {}).get("name"),
                    "namespace": record_obj.get("metadata", {}).get("namespace"),
                    "uid_present": bool(record_obj.get("metadata", {}).get("uid")),
                    "immutable": record_obj.get("immutable") is True} if record_obj else None)}
            if not completed:
                outcomes[name]["setup_error"] = "rp_job_failed_or_timed_out"
            elif decision.get("decision") == "SETUP_ERROR":
                outcomes[name]["setup_error"] = decision.get("reason", "unclassified_setup_error")
            if exists and record_json_valid:
                try:
                    record_bytes = base64.b64decode(record.get("ciphertext_b64", ""), validate=True)
                    record_digest = hashlib.sha256(record_bytes).hexdigest()
                    record_bytes_valid = True
                except (ValueError, TypeError):
                    record_bytes = b""
                    record_digest = ""
                    record_bytes_valid = False
                record_metadata = record_obj.get("metadata", {})
                outcomes[name]["record_binding"] = {
                    "record_name_matches": record_metadata.get("name") == output_name,
                    "record_namespace_matches": record_metadata.get("namespace") == base.NAMESPACE,
                    "record_uid_present": bool(record_metadata.get("uid")),
                    "record_immutable": record_obj.get("immutable") is True,
                    "record_data_fields_exact": set(record_obj.get("data", {})) == {"record.json"},
                    "decision_id_matches": record.get("decision_id") == claims["decision_id"],
                    "ciphertext_base64_valid": record_bytes_valid,
                    "verifier_id_matches": record.get("verifier_id") == verifier_id,
                    "subject_matches": record.get("subject") == subject,
                    "request_reference_matches": record.get("request_reference") == request_reference,
                    "resource_matches": record.get("resource") == resource,
                    "recipient_matches": record.get("recipient") == base.RECIPIENT_A,
                    "recipient_public_digest_matches": record.get("recipient_public_sha256") == recipient_digest,
                    "challenge_digest_matches": record.get("challenge_sha256") == hashlib.sha256(challenge.encode()).hexdigest(),
                    "result_digest_matches": record.get("result_sha256") == hashlib.sha256(payload).hexdigest(),
                    "signature_digest_matches": record.get("signature_sha256") == hashlib.sha256(signature).hexdigest(),
                    "ciphertext_digest_matches": record.get("ciphertext_sha256") == ciphertext_digest == record_digest,
                    "record_fields_exact": set(record) == {"decision_id", "verifier_id", "subject", "request_reference", "resource", "recipient", "recipient_public_sha256", "challenge_sha256", "result_sha256", "signature_sha256", "ciphertext_sha256", "ciphertext_b64"},
                }
                if name == "positive" and record_bytes_valid:
                    recovered, authorized_key_error = base._decrypt(recipient_private, record_bytes, directory, "signed-positive")
                    _other_plaintext, unrelated_key_oaep_error = base._decrypt(
                        other_recipient_private, record_bytes, directory, "signed-unrelated")
                    outcomes[name]["matching_recipient_decrypts_exact_marker"] = recovered
                    outcomes[name]["authorized_key_oaep_error"] = authorized_key_error
                    outcomes[name]["unrelated_recipient_oaep_rejection"] = unrelated_key_oaep_error
            else:
                outcomes[name]["record_binding"] = None
            outcomes[name]["expected_denial"] = scenario["expected_failed"]
        raw.update({"image": base.IMAGE, "namespace": base.NAMESPACE,
            "verifier_id": verifier_id, "issuer": issuer,
            "trust_root_sha256": public_digest,
            "recipient": base.RECIPIENT_A, "recipient_public_sha256": recipient_digest,
            "resource": base.RESOURCE, "ciphertext_sha256": ciphertext_digest,
            "marker_sha256": hashlib.sha256(base.PAYLOAD).hexdigest(),
            "authorized_recipient_recovers_exact_inert_marker": outcomes.get("positive", {}).get("matching_recipient_decrypts_exact_marker") is True,
            "cases": outcomes})
    _write_raw(lab, raw)
    if raw["setup_errors"]:
        lab.block("Synthetic signed-release setup failed: " + ",".join(raw["setup_errors"]))
    setup_failure = [name for name, row in outcomes.items() if row.get("setup_error")]
    if setup_failure:
        lab.block("Signed-release relying-party setup failed for: " + ",".join(setup_failure))
    expected_denials = {
        "wrong-request-reference": ["request_reference"],
        "wrong-challenge": ["challenge"],
        "expired": ["freshness"],
        "untrusted-verifier": ["signature"],
    }
    denial_ok = True
    for name, failed in expected_denials.items():
        row = outcomes.get(name, {})
        denial_ok = denial_ok and row.get("job_completed") is True and row.get("decision") == {
            "decision": "DENIED", "signature_valid": name != "untrusted-verifier",
            "failed_checks": failed} and row.get("release_record_exists") is False
    positive = outcomes.get("positive", {})
    binding = positive.get("record_binding") or {}
    binding_ok = bool(binding) and all(binding.values())
    positive_ok = (positive.get("job_completed") is True
                   and positive.get("decision", {}).get("decision") == "RELEASED"
                   and positive.get("decision", {}).get("verifier_id") == verifier_id
                   and positive.get("decision", {}).get("result_sha256") == positive.get("result_sha256")
                   and positive.get("release_record_exists") is True
                   and positive.get("matching_recipient_decrypts_exact_marker") is True
                   and positive.get("authorized_key_oaep_error") is False
                   and positive.get("unrelated_recipient_oaep_rejection") is True
                   and binding_ok)
    passed = denial_ok and positive_ok
    lab.check("signed-recipient", "Only a trusted fresh verifier result bound to the exact request can release recipient-encrypted inert data",
              passed, {"trusted_positive_result_released": positive_ok,
                       "request_or_challenge_mismatch_denied_without_record": denial_ok,
                       "expired_signed_result_denied_without_record": outcomes.get("expired", {}).get("release_record_exists") is False,
                       "untrusted_signer_denied_without_record": outcomes.get("untrusted-verifier", {}).get("release_record_exists") is False,
                       "authorized_recipient_recovers_exact_inert_marker": outcomes.get("positive", {}).get("matching_recipient_decrypts_exact_marker") is True,
                       "all_claims_and_artifact_digests_match": binding_ok})
