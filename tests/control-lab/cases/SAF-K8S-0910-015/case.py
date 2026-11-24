"""Destination-side re-verification after replication, before a Kubernetes consumer Job."""
import base64
from datetime import datetime, timezone
from hashlib import sha256
import importlib.util
import ipaddress
import json
from pathlib import Path
import tempfile
import time

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
NS = "saf-test"
SOURCE_REGISTRY = "fixture-destination-source"
DEST_REGISTRY = "fixture-destination-registry"
SOURCE_CLIENT = "fixture-destination-source-client"
TRANSFER_CLIENT = "fixture-destination-transfer"
VALIDATOR = "fixture-destination-validator"
CODE = "fixture-destination-check-code"
NS_CODE = "fixture-destination-transfer-code"
SOURCE_REPO = "fixtures/model"
REGISTRY_IMAGE = ("docker.io/library/registry:3.0.0@sha256:"
                  "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e")
POLICY = "fixture-destination-model-readback"
RECEIPT = "fixture-destination-model-receipt"
LABEL = "saf.fixture/destination-model"
DENIAL = "SAF-K8S-0910-015 requires an exact verified destination manifest"
ADMISSION = "admissionregistration.k8s.io/v1"
SCOPE = (
    "A disposable source Kind cluster and separately owned peer Kind cluster host pinned local "
    "Distribution registries. The source signs the SAF-K8S-0910-024 inert model metadata using a "
    "per-run key; a transfer client copies bytes and reports success. The destination then substitutes "
    "only inert metadata while retaining the signed statement. With enforcement off, a named Kubernetes "
    "Job consumes the substituted bytes. With enforcement on, a separate peer pod re-fetches the actual "
    "destination manifest and blob, checks the reference, Distribution digest headers, descriptor, "
    "source digest and RSA signature against a locally mounted trusted public key, and blocks the Job. "
    "A clean readback is also consumed by an independent named Job. No external registry, production "
    "credential, model payload, or inference execution is involved."
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load fixture {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create(lab, obj):
    obj.setdefault("metadata", {})["namespace"] = NS
    if callable(lab):
        lab("apply", "-f", "-", payload=json.dumps(obj, sort_keys=True), timeout=20)
    else:
        lab.create(obj)


def registry(lab, name, node_port=False):
    unit = container("registry", image=REGISTRY_IMAGE, ports=[{"containerPort": 5000}],
                     env=[{"name": "REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY", "value": "/tmp/saf-registry"}])
    unit.pop("command", None)
    unit["readinessProbe"] = {"httpGet": {"port": 5000, "path": "/v2/"}, "periodSeconds": 1}
    workload = pod(name, [unit], automountServiceAccountToken=False)
    workload["metadata"]["labels"] = {"app": name}
    create(lab, workload)
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
               "spec": {"type": "NodePort" if node_port else "ClusterIP",
                        "selector": {"app": name}, "ports": [{"port": 5000, "targetPort": 5000}]}}
    if node_port:
        service = lab.create({**service, "metadata": {**service["metadata"], "namespace": NS}})
        return service["spec"]["ports"][0]["nodePort"]
    create(lab, service)


def code_map(lab, name, files):
    create(lab, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                 "immutable": True, "data": files})


def client(lab, name, image, code_name):
    unit = container("fixture", image=image, imagePullPolicy="Never",
                     command=["sleep", "360"],
                     volumeMounts=[{"name": "fixture", "mountPath": "/fixture", "readOnly": True}])
    create(lab, pod(name, [unit], automountServiceAccountToken=False,
                    volumes=[{"name": "fixture", "configMap": {"name": code_name}}]))


def wait(lab, name):
    if callable(lab):
        lab("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=95s", timeout=105)
    else:
        lab.kubectl("-n", NS, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=95s", timeout=105)


def k(lab, *args, **kwargs):
    if callable(lab):
        return lab(*args, **kwargs)
    return lab.kubectl("-n", NS, *args, **kwargs)


def exec_json(lab, pod_name, script, operation, payload, tag=None):
    args = ["exec", "-i", pod_name, "--", "python", "/fixture/" + script, operation]
    if tag:
        args.append(tag)
    result = k(lab, *args, payload=json.dumps(payload, sort_keys=True), timeout=35)
    return json.loads(result.stdout)


def private_source_address(lab):
    fmt = '{{json (index .NetworkSettings.Networks "kind")}}'
    raw = lab.command("docker", "inspect", "--format", fmt, lab.cluster + "-control-plane").stdout
    address = ipaddress.ip_address(json.loads(raw)["IPAddress"])
    if address.version != 4 or address.is_global or address.is_loopback or address.is_link_local:
        lab.block("Source cluster bridge address is not private and owned")
    return str(address)


def wait_registry(kube, pod_name, host, port):
    program = """import sys, time
from http.client import HTTPConnection
deadline = time.monotonic() + 25
while True:
    try:
        connection = HTTPConnection(sys.argv[1], int(sys.argv[2]), timeout=2)
        try:
            connection.request("GET", "/v2/")
            if connection.getresponse().status == 200:
                break
        finally:
            connection.close()
    except OSError:
        pass
    if time.monotonic() >= deadline:
        raise RuntimeError("private fixture registry did not respond")
    time.sleep(0.5)
"""
    k(kube, "exec", pod_name, "--", "python", "-c", program, host, str(port), timeout=38)


def receipt(peer, state, manifest):
    create(peer, {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": RECEIPT}, "data": {"state": state, "manifest": manifest}})


def configure_admission(peer):
    receipt(peer, "pending", "unverified")
    expression = (
        "params != null && params.data['state'] == 'verified' && "
        "has(object.spec.template.metadata.annotations) && "
        "object.spec.template.metadata.annotations['saf.fixture/manifest'] == params.data['manifest']"
    )
    policy = {"apiVersion": ADMISSION, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
              "spec": {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                       "matchConstraints": {"objectSelector": {"matchLabels": {LABEL: "true"}},
                                            "resourceRules": [{"apiGroups": ["batch"], "apiVersions": ["v1"],
                                                               "operations": ["CREATE"], "resources": ["jobs"]}]},
                       "validations": [{"expression": expression, "message": DENIAL}]}}
    binding = {"apiVersion": ADMISSION, "kind": "ValidatingAdmissionPolicyBinding",
               "metadata": {"name": POLICY},
               "spec": {"policyName": POLICY, "validationActions": ["Deny"], "paramRef": {
                   "name": RECEIPT, "namespace": NS, "parameterNotFoundAction": "Deny"}}}
    for resource in (policy, binding):
        peer("create", "-f", "-", payload=json.dumps(resource), timeout=20)


def consumer(image, name, tag, manifest, expected_blob, governed=False):
    data = {"action": name, "expected_blob_digest": expected_blob, "expected_manifest_digest": manifest}
    unit = container("consumer", image=image, imagePullPolicy="Never",
                     command=["python", "/fixture/destination_check.py", "consume", tag, json.dumps(data)],
                     volumeMounts=[{"name": "fixture", "mountPath": "/fixture", "readOnly": True}])
    workload = pod(name + "-pod", [unit], automountServiceAccountToken=False,
                   volumes=[{"name": "fixture", "configMap": {"name": CODE}}])
    template = {"spec": workload["spec"], "metadata": {"annotations": {"saf.fixture/manifest": manifest}}}
    return {"apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": name, "namespace": NS, "labels": {LABEL: "true"} if governed else {}},
            "spec": {"backoffLimit": 0, "template": template}}


def job(peer, manifest):
    name = manifest["metadata"]["name"]
    peer("create", "-f", "-", payload=json.dumps(manifest), timeout=20)
    peer("wait", "--for=condition=complete", "job/" + name, "--timeout=45s", timeout=55)
    pod_name = peer("get", "pods", "-l", "job-name=" + name,
                    "-o", "jsonpath={.items[0].metadata.name}").stdout.strip()
    return json.loads(peer("logs", "pod/" + pod_name).stdout)


def admission_projection(peer, candidate, permitted):
    deadline = time.monotonic() + 25
    while True:
        response = peer("create", "--dry-run=server", "-f", "-", payload=json.dumps(candidate),
                        allow_failure=True, timeout=12)
        if (permitted and response.returncode == 0) or (not permitted and DENIAL in response.stderr):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


def all_true(checks):
    return bool(checks) and all(value is True for value in checks.values())


def run(lab):
    peer_module = load(HERE.parent / "SAF-K8S-0910-020" / "owned_peer.py", "saf_0910_015_peer")
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_0910_015_runtime")
    image = runtime.load_runtime(lab)
    with tempfile.TemporaryDirectory(prefix="saf-0910-015-") as key_dir:
        key, pub = Path(key_dir) / "run-signing-key.pem", Path(key_dir) / "run-approved-public.pem"
        lab.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(key), timeout=30)
        lab.command("openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub), timeout=20)
        public_pem = pub.read_bytes()
        blob = json.dumps({"executable": False, "name": "fixture-linear-model", "version": "1.0.0",
                           "weights": "synthetic-placeholder"}, sort_keys=True, separators=(",", ":")).encode()
        statement = json.dumps({"_type": "https://in-toto.io/Statement/v1",
                                "subject": [{"name": SOURCE_REPO, "digest": {"sha256": sha256(blob).hexdigest()}}],
                                "predicateType": "https://slsa.dev/provenance/v1",
                                "predicate": {"saf_created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                                              "saf_origin_cluster": "fixture-training-cluster",
                                              "saf_signing_identity": "fixture://model-release-signer",
                                              "saf_promotion_workflow": "fixture-model-approved"}},
                               sort_keys=True, separators=(",", ":")).encode()
        payload_path, signature_path = Path(key_dir) / "statement.json", Path(key_dir) / "statement.sig"
        payload_path.write_bytes(statement)
        lab.command("openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(signature_path), str(payload_path))
        statement_b64 = base64.b64encode(statement).decode()
        signature_b64 = base64.b64encode(signature_path.read_bytes()).decode()
        with peer_module.owned_peer(lab, image) as (peer, _peer_addr):
            src_port = registry(lab, SOURCE_REGISTRY, node_port=True)
            registry(peer, DEST_REGISTRY)
            k(lab, "wait", "--for=condition=Ready", f"pod/{SOURCE_REGISTRY}", "--timeout=95s", timeout=105)
            peer("wait", "--for=condition=Ready", f"pod/{DEST_REGISTRY}", "--timeout=95s", timeout=105)
            code_map(lab, CODE, {"destination_check.py": (HERE / "destination_check.py").read_text(),
                                 "verify_signature.py": (HERE / "verify_signature.py").read_text(),
                                 "approved-public.pem": public_pem.decode("ascii")})
            code_map(lab, NS_CODE, {"registry_fixture.py": (HERE / "registry_fixture.py").read_text()})
            code_map(peer, CODE, {"destination_check.py": (HERE / "destination_check.py").read_text(),
                                  "verify_signature.py": (HERE / "verify_signature.py").read_text(),
                                  "approved-public.pem": public_pem.decode("ascii")})
            code_map(peer, NS_CODE, {"registry_fixture.py": (HERE / "registry_fixture.py").read_text()})
            client(lab, SOURCE_CLIENT, image, NS_CODE)
            client(peer, TRANSFER_CLIENT, image, NS_CODE)
            client(peer, VALIDATOR, image, CODE)
            for api, name in ((lab, SOURCE_CLIENT), (peer, TRANSFER_CLIENT), (peer, VALIDATOR)):
                wait(api, name)
            source_addr = private_source_address(lab)
            wait_registry(lab, SOURCE_CLIENT, SOURCE_REGISTRY + "." + NS + ".svc", 5000)
            wait_registry(peer, TRANSFER_CLIENT, source_addr, src_port)
            wait_registry(peer, VALIDATOR, DEST_REGISTRY + "." + NS + ".svc", 5000)
            kube_apis = {name: k(kube, "get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout
                         for name, kube in (("source", lab), ("peer", peer))}
            if len(set(kube_apis.values())) != 2 or not all(kube_apis.values()):
                lab.block("Distinct fixture Kubernetes APIs are required")
            seeded = exec_json(lab, SOURCE_CLIENT, "registry_fixture.py", "seed", {
                "host": SOURCE_REGISTRY + "." + NS + ".svc", "port": 5000,
                "statement_b64": statement_b64, "signature_b64": signature_b64})
            copied = exec_json(peer, TRANSFER_CLIENT, "registry_fixture.py", "copy", {
                "source_host": source_addr, "source_port": src_port,
                "destination_host": DEST_REGISTRY + "." + NS + ".svc"})
            if not copied.get("source_claimed_success") or copied.get("manifest_digest") != seeded.get("source_manifest_digest"):
                lab.block("Source transfer success claim failed independent source digest comparison")
            tampered = exec_json(peer, TRANSFER_CLIENT, "registry_fixture.py", "substitute", {
                "destination_host": DEST_REGISTRY + "." + NS + ".svc"})

            base_expect = {"reference": "copied", "manifest_digest": copied["manifest_digest"],
                           "blob_b64": copied["blob_b64"], "statement_b64": statement_b64,
                           "signature_b64": signature_b64}
            raw_baseline = exec_json(peer, VALIDATOR, "destination_check.py", "inspect", base_expect, "copied")
            baseline_checks = raw_baseline["checks"]
            baseline = {"source_claimed_success": copied["source_claimed_success"],
                        "destination_manifest_differs_from_source_digest": baseline_checks["manifest_digest_matches_source_claim"] is False,
                        "destination_blob_differs_from_signed_source_subject": baseline_checks["blob_digest_matches_signed_subject"] is False,
                        "destination_signature_fails_or_binds_other_bytes": baseline_checks["signature_valid_over_readback_statement"] is True
                        and baseline_checks["blob_digest_matches_signed_subject"] is False}
            consumed = job(peer, consumer(image, "fixture-model-consumer-baseline", "copied",
                                          tampered["manifest_digest"], tampered["blob_digest"]))
            baseline["unchecked_named_job_consumed_actual_substituted_bytes"] = consumed.get("consumed") is True \
                and consumed.get("blob_digest") == tampered["blob_digest"] and consumed.get("action") == "fixture-model-consumer-baseline"
            lab.check("red", "Without destination enforcement, a success claim permits substituted bytes to be consumed",
                      all_true(baseline), baseline)

            enforced = {"independent_readback_rejects_before_use": not all_true(baseline_checks),
                        "destination_reference_is_explicit": raw_baseline.get("reference") == "copied",
                        "actual_manifest_and_blob_digests_are_recorded": bool(raw_baseline.get("manifest_digest"))
                        and bool(raw_baseline.get("blob_digest"))}
            configure_admission(peer)
            refused_job = consumer(image, "fixture-model-consumer-enforced", "copied",
                                   tampered["manifest_digest"], tampered["blob_digest"], governed=True)
            enforced["named_consumer_job_create_is_denied"] = admission_projection(peer, refused_job, False)
            absent = peer("get", "job", "fixture-model-consumer-enforced", allow_failure=True)
            enforced["denied_job_has_no_api_object"] = absent.returncode != 0 and "NotFound" in absent.stderr
            lab.check("green", "Destination readback policy blocks use despite source success",
                      all_true(enforced), enforced)

            # Restore the exact source transfer at the same intended destination reference.
            restored = exec_json(peer, TRANSFER_CLIENT, "registry_fixture.py", "copy", {
                "source_host": source_addr, "source_port": src_port,
                "destination_host": DEST_REGISTRY + "." + NS + ".svc"})
            clean_expected = {"reference": "copied", "manifest_digest": restored["manifest_digest"],
                              "blob_b64": copied["blob_b64"], "statement_b64": statement_b64,
                              "signature_b64": signature_b64}
            clean = exec_json(peer, VALIDATOR, "destination_check.py", "inspect", clean_expected, "copied")
            clean_ok = all_true(clean.get("checks", {}))
            accepted = {"consumed": False}
            approved_job = consumer(image, "fixture-model-consumer-approved", "copied",
                                    restored["manifest_digest"], restored["blob_digest"], governed=True)
            if clean_ok:
                receipt(peer, "verified", clean["manifest_digest"])
                if admission_projection(peer, approved_job, True):
                    accepted = job(peer, approved_job)
            positive = {"clean_destination_bytes_pass_reference_digest_and_signature_checks": clean_ok,
                        "approved_named_job_consumed_exact_destination_blob": accepted.get("consumed") is True
                        and accepted.get("blob_digest") == restored["blob_digest"]
                        and accepted.get("action") == "fixture-model-consumer-approved",
                        "receipt_for_clean_manifest_still_excludes_the_altered_manifest":
                        admission_projection(peer, refused_job, False)}
            lab.check("positive", "A clean independently verified destination artifact remains usable",
                      all_true(positive), positive)
            normalized = {"control": "SAF-K8S-0910-015", "red": baseline, "green": enforced,
                          "positive": positive, "altered_readback_checks": baseline_checks,
                          "clean_readback_checks": clean["checks"]}
            raw = {"outcomes": normalized, "api_uids": kube_apis,
                   "source": {"manifest_digest": copied["manifest_digest"], "blob_digest": copied["blob_digest"]},
                   "observed_altered": raw_baseline, "observed_clean": clean,
                   "consumer_before": consumed, "consumer_after": accepted}
            for filename, data in (("destination-model-verification.json", raw),
                                   ("destination-model-normalized.json", normalized)):
                (lab.evidence / filename).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
