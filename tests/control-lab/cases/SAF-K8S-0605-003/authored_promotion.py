"""Promote the exact sandboxed WASM via a disposable, signature-aware PolicyServer."""
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import time
from urllib.error import URLError
from urllib.request import HTTPSHandler, ProxyHandler, build_opener
import ssl


HERE = Path(__file__).resolve().parent
CONTROLLER_NS = "kubewarden"
TEST_NS = "saf-authored-policy"
SERVER = "saf-authored-policy-server"
CONFIG = "saf-authored-signature"
POLICY = "saf-authored-model-label"
REPOSITORY = "fixture/authored-policy"
GROUP = "ai.saf-k8s.example"
SIGNATURE_REFUSAL = "required label saf-k8s.example/approved must equal yes"


def _registry_service(lab, registry, address):
    name = registry.registry_container
    service = {"apiVersion": "v1", "kind": "Service",
               "metadata": {"name": name, "namespace": CONTROLLER_NS},
               "spec": {"ports": [{"name": "registry", "port": 5000, "protocol": "TCP"}]}}
    endpoints = {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
                 "metadata": {"name": name + "-owned", "namespace": CONTROLLER_NS,
                              "labels": {"kubernetes.io/service-name": name,
                                         "endpointslice.kubernetes.io/managed-by": "saf-k8s.example"}},
                 "addressType": "IPv4",
                 "ports": [{"name": "registry", "port": 5000, "protocol": "TCP"}],
                 "endpoints": [{"addresses": [address], "conditions": {"ready": True}}]}
    for resource in (service, endpoints):
        registry.kube("-n", CONTROLLER_NS, "create", "-f", "-", input_text=json.dumps(resource))


def _wait_registry(registry, host):
    opener = build_opener(ProxyHandler({}), HTTPSHandler(
        context=ssl.create_default_context(cafile=registry.registry_ca)))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with opener.open(f"https://{host}/v2/", timeout=3) as response:
                if response.status == 200:
                    return
        except (URLError, TimeoutError):
            time.sleep(.5)
    registry.lab.block("The case-owned TLS registry did not become ready")


def _push_verify(lab, module, library, registry, port):
    host = "127.0.0.1:" + port
    _wait_registry(registry, host)
    kwctl = lab.kubeconfig.parent / "kwctl"
    authorities = registry.work / "sources.json"
    authorities.write_text(json.dumps({"source_authorities": {host: [
        {"type": "Data", "data": registry.registry_ca.read_text()}]}}))
    auth_args = ("--sources-path", str(authorities))
    lab.command(str(kwctl), "push", str(module), f"registry://{host}/{REPOSITORY}:case",
                *auth_args, timeout=60)
    digest = library["_registry_digest"](port, REPOSITORY, registry.registry_ca)
    ref = f"registry://{host}/{REPOSITORY}@{digest}"
    key = registry.work / "signer"
    key.mkdir(mode=0o700)
    registry.cosign(key, "generate-key-pair")
    signature_args = (*auth_args, "--verification-key", str(key / "cosign.pub"))
    unsigned = lab.command(str(kwctl), "verify", *signature_args, ref, allow_failure=True, timeout=60)
    rejected = unsigned.returncode != 0 and "signature" in (unsigned.stdout + unsigned.stderr).lower()
    lab.check("red", "Signature verification rejects the exact authored artifact before signing",
              rejected, {"same_artifact_rejected_without_signature": rejected})
    signature_target = f"{registry.registry}/{REPOSITORY}@{digest}"
    registry.cosign(key, "sign", "--yes", "--key", "/work/cosign.key", "--use-signing-config=false",
                    "--tlog-upload=false", "--new-bundle-format=false", signature_target)
    signed = lab.command(str(kwctl), "verify", *signature_args, ref, timeout=60)
    downloaded = registry.work / "verified-author.wasm"
    lab.command(str(kwctl), "pull", *signature_args, "--output-path", str(downloaded), ref, timeout=60)
    same = module.read_bytes() == downloaded.read_bytes()
    trusted = "Policy successfully verified" in signed.stdout + signed.stderr
    lab.check("green", "The trusted signature verifies and the downloaded policy is the sandboxed WASM",
              trusted and same, {"exact_artifact_signature_valid": trusted, "module_bytes_match": same})
    pubkey = (key / "cosign.pub").read_text()
    return digest, pubkey


def _probe(lab, valid):
    resource = {
        "apiVersion": GROUP + "/v1alpha1", "kind": "ModelDeployment",
        "metadata": {"name": "authored-policy-probe", "namespace": TEST_NS},
        "spec": {"model": "inert-fixture", "replicas": 0},
    }
    if valid:
        resource["metadata"]["labels"] = {"saf-k8s.example/approved": "yes"}
    return lab.kubectl("-n", TEST_NS, "create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(resource), allow_failure=True, timeout=20)


def _apply_policy(lab, registry, digest, key, server_version):
    lab.kubectl("create", "namespace", TEST_NS)
    verification = json.dumps({"apiVersion": "v1", "allOf": [{"kind": "pubKey", "key": key}]})
    lab.kubectl("-n", CONTROLLER_NS, "create", "configmap", CONFIG,
                "--from-literal=verification-config=" + verification)
    lab.create({"apiVersion": "policies.kubewarden.io/v1", "kind": "PolicyServer",
                "metadata": {"name": SERVER}, "spec": {
                    "image": "ghcr.io/kubewarden/adm-controller/policy-server:" + server_version,
                    "replicas": 1, "verificationConfig": CONFIG,
                    "sourceAuthorities": {registry.registry: [registry.registry_ca.read_text()]},
                }})
    reference = f"registry://{registry.registry}/{REPOSITORY}@{digest}"
    policy = {"apiVersion": "policies.kubewarden.io/v1", "kind": "AdmissionPolicy",
              "metadata": {"name": POLICY, "namespace": TEST_NS},
              "spec": {"mode": "protect", "policyServer": SERVER, "module": reference,
                       "mutating": False, "settings": {}, "rules": [{
                           "apiGroups": [GROUP], "apiVersions": ["v1alpha1"],
                           "resources": ["modeldeployments"], "operations": ["CREATE"],
                       }]}}
    lab.kubectl("-n", TEST_NS, "create", "-f", "-", payload=json.dumps(policy))
    deadline = time.monotonic() + 145
    while time.monotonic() < deadline:
        refused = _probe(lab, valid=False)
        if refused.returncode != 0 and POLICY in refused.stderr and SIGNATURE_REFUSAL in refused.stderr:
            break
        time.sleep(1)
    else:
        lab.block("The authored policy did not reach its exact protection decision")
    accepted = _probe(lab, valid=True)
    entry = json.loads(lab.kubectl("-n", TEST_NS, "get", "admissionpolicy", POLICY, "-o", "json").stdout)
    verifier = json.loads(lab.kubectl("get", "policyserver", SERVER, "-o", "json").stdout)
    config = json.loads(lab.kubectl("-n", CONTROLLER_NS, "get", "configmap", CONFIG, "-o", "json").stdout)
    matches = (entry["spec"]["module"] == reference and entry["spec"]["mode"] == "protect"
               and entry["spec"]["policyServer"] == SERVER
               and verifier["spec"]["verificationConfig"] == CONFIG
               and config["data"]["verification-config"] == verification)
    accepted_object = json.loads(accepted.stdout) if accepted.returncode == 0 else {}
    metadata = accepted_object.get("metadata", {})
    accepted_as_expected = (metadata.get("name") == "authored-policy-probe"
                            and metadata.get("namespace") == TEST_NS
                            and metadata.get("labels", {}).get("saf-k8s.example/approved") == "yes")
    observed = {"exact_protect_digest_and_signature_config": matches,
                "approved_label_admitted": accepted_as_expected,
                "missing_label_explicitly_denied": True}
    lab.check("positive", "The signature-aware server protects the namespace with the exact authored digest",
              all(observed.values()), observed)
    return reference, observed


def run(lab, module, server_version):
    target = HERE.parent / "SAF-K8S-0605-002" / "image_admission.py"
    library = runpy.run_path(str(target))
    registry = library["RegistryFixture"](lab)
    registry.registry = f"{registry.registry_container}.{CONTROLLER_NS}.svc.cluster.local:5000"
    try:
        address, port = library["_start_registry"](registry)
        registry.docker("pull", library["COSIGN_IMAGE"], timeout=180)
        _registry_service(lab, registry, address)
        digest, pubkey = _push_verify(lab, module, library, registry, port)
        reference, observed = _apply_policy(lab, registry, digest, pubkey, server_version)
        (lab.evidence / "authored-policy-promotion.json").write_text(json.dumps({
            "annotated_module_sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
            "manifest_digest": digest, "module_reference": reference, "public_verification_key": pubkey,
            **observed,
        }, indent=2) + "\n")
    finally:
        try:
            registry.clean()
        finally:
            signing = registry.work / "signer"
            if signing.exists():
                shutil.rmtree(signing)
