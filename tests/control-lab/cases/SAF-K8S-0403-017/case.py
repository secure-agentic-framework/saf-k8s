"""Exercise real wrapping, persisted ciphertext, distinct signing, and safe key retirement."""

import base64
import json
from pathlib import Path
import runpy
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
vault = SimpleNamespace(**runpy.run_path(str(HERE / "vault_fixture.py")))
TRAIN = "training-fixture"
MODEL = "model-fixture"
SIGN = "signing-fixture"
TRAIN_DATA = b"owned training data marker"
MODEL_DATA = b"owned model artifact marker"
AAD = {"train": "fixture-private-training", "model": "fixture-model-artifact"}
WORKLOAD_ROLES = {
    TRAIN: "fixture-train-domain",
    MODEL: "fixture-model-domain",
    SIGN: "fixture-signing-domain",
}
SCOPE = (
    "Exercise actual Vault Transit key domains and AES-GCM application envelope storage for "
    "owned training and model markers, distinct Ed25519 signing, versioned rewrap and retirement. "
    "An additive check authenticates three owned Kubernetes workload ServiceAccounts to "
    "separate Transit policies using mounted, short-lived audience-bound tokens. The fixture "
    "uses in-memory Vault storage and synthetic application records. Deployed key custody, "
    "HSMs, volumes, backups, product workloads and provider integrations need independent evidence."
)


def b64(value):
    return base64.b64encode(value).decode()


def crypt(lab, helper, mode, key, value, aad=None):
    req = json.dumps({"Mode": mode, "Key": key, "Data": value, "AAD": aad or ""})
    try:
        answer = subprocess.run([str(helper)], input=req, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The private fixture envelope operation did not complete")
    return json.loads(answer.stdout) if not answer.returncode else None


def policy(lab, root, name, key):
    vault.permissions(lab, root, name, {
        "transit/datakey/plaintext/" + key: ["update"], "transit/decrypt/" + key: ["update"]})
    return vault.scoped_token(lab, root, name)


def make(lab, helper, token, domain, key, marker):
    material = vault.required(lab, "transit/datakey/plaintext/" + key, token=token, body={"bits": 256})["data"]
    ciphertext = crypt(lab, helper, "seal", material["plaintext"], b64(marker), AAD[domain])
    if not ciphertext:
        lab.block("The owned envelope could not encrypt a public fixture marker")
    return {"data": ciphertext, "wrapped": material["ciphertext"], "domain": domain, "wrapping_key": key}


def opened(lab, helper, token, box, aad=None, via=vault.PROBE):
    status, reply = vault.request(lab, "transit/decrypt/" + box["wrapping_key"], token=token,
                                  body={"ciphertext": box["wrapped"]}, via=via)
    if status != 200:
        return status, None
    value = crypt(lab, helper, "open", reply["data"]["plaintext"], box["data"], aad or AAD[box["domain"]])
    return status, base64.b64decode(value) if value else None


def persisted(lab, name, box):
    resource = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "data": {"envelope": json.dumps(box)}}
    lab.create(resource)
    raw = lab.kubectl("get", "configmap/" + name, "-o", "jsonpath={.data.envelope}").stdout
    return json.loads(raw), raw


def _workload_token(lab, name):
    login = vault.required(lab, "auth/kubernetes/login", via=name,
                           login=WORKLOAD_ROLES[name])
    token = login.get("auth", {}).get("client_token")
    if not isinstance(token, str) or not token:
        lab.block("A case-owned Kubernetes workload could not authenticate to the local Vault")
    return token


def _mounted_workload_identity(lab, name):
    pod = json.loads(lab.kubectl("get", "pod/" + name, "-o", "json").stdout)
    spec = pod.get("spec", {})
    projected = []
    for volume in spec.get("volumes", []):
        projection = volume.get("projected", {})
        for source in projection.get("sources", []):
            if "serviceAccountToken" in source:
                projected.append(source["serviceAccountToken"])
    return (spec.get("serviceAccountName") == name
            and spec.get("automountServiceAccountToken") is False
            and projected == [{"audience": vault.AUDIENCE, "expirationSeconds": 600, "path": "token"}])


def run(lab):
    root = vault.start(lab, auth=True)
    vault.required(lab, "transit/keys/" + TRAIN, token=root, body={"type": "aes256-gcm96"})
    t = policy(lab, root, "fixture-train-domain", TRAIN)
    with TemporaryDirectory(prefix="saf-envelope-tool-") as directory:
        helper = Path(directory) / "envelope"
        lab.command("go", "build", "-trimpath", "-o", str(helper), str(HERE / "envelope.go"), timeout=90)
        wrong = make(lab, helper, t, "model", TRAIN, MODEL_DATA)
        exposed = opened(lab, helper, t, wrong) == (200, MODEL_DATA)
        lab.check("red", "When both workloads use one wrapping key, the training entitlement reads the model fixture",
                  exposed, {"shared_wrapping_key_cross_use": exposed})

        vault.required(lab, "transit/keys/" + MODEL, token=root, body={"type": "aes256-gcm96"})
        vault.required(lab, "transit/keys/" + SIGN, token=root, body={"type": "ed25519"})
        m = policy(lab, root, "fixture-model-domain", MODEL)
        vault.permissions(lab, root, "fixture-signing-domain", {
            "transit/sign/" + SIGN: ["update"], "transit/verify/" + SIGN: ["update"]})
        signer = vault.scoped_token(lab, root, "fixture-signing-domain")
        for domain in (TRAIN, MODEL, SIGN):
            vault.role(lab, root, WORKLOAD_ROLES[domain], account=domain)
            vault.workload(lab, domain, identity=True)
        for domain in (TRAIN, MODEL, SIGN):
            lab.kubectl("wait", "--for=condition=Ready", "pod/" + domain,
                        "--timeout=90s", timeout=100)
        training, training_raw = persisted(lab, "fixture-training-envelope", make(lab, helper, t, "train", TRAIN, TRAIN_DATA))
        model, model_raw = persisted(lab, "fixture-model-envelope", make(lab, helper, m, "model", MODEL, MODEL_DATA))
        opaque = (all(base64.b64encode(marker).decode() not in raw and marker.decode() not in raw
                      for marker, raw in ((TRAIN_DATA, training_raw), (MODEL_DATA, model_raw)))
                  and set(training) == set(model) == {"data", "wrapped", "domain", "wrapping_key"})
        boundaries = (opened(lab, helper, t, training) == (200, TRAIN_DATA)
                      and opened(lab, helper, m, model) == (200, MODEL_DATA)
                      and opened(lab, helper, t, model)[0] == 403
                      and opened(lab, helper, m, training)[0] == 403
                      and opened(lab, helper, t, training, aad=AAD["model"]) == (200, None))
        sign_route, verify_route = "transit/sign/" + SIGN, "transit/verify/" + SIGN
        signature = vault.required(lab, sign_route, token=signer, body={"input": b64(MODEL_DATA)})["data"]["signature"]
        accepted = vault.required(lab, verify_route, token=signer,
                                  body={"input": b64(MODEL_DATA), "signature": signature})["data"]["valid"]
        modified = vault.required(lab, verify_route, token=signer,
                                  body={"input": b64(TRAIN_DATA), "signature": signature})["data"]["valid"]
        signing_separate = (accepted and not modified
                            and vault.request(lab, sign_route, token=t, body={"input": b64(MODEL_DATA)})[0] == 403
                            and opened(lab, helper, signer, training)[0] == 403)
        lab.check("green", "Distinct wrap keys protect stored ciphertext and the separate signing path rejects cross-domain use",
                  opaque and boundaries and signing_separate,
                  {"ciphertext_only_persisted": opaque, "wrap_and_context_boundaries_enforced": boundaries,
                   "signing_domain_separate": signing_separate})

        workload_tokens = {domain: _workload_token(lab, domain) for domain in (TRAIN, MODEL, SIGN)}
        workload_train = opened(lab, helper, workload_tokens[TRAIN], training, via=TRAIN)
        workload_model = opened(lab, helper, workload_tokens[MODEL], model, via=MODEL)
        workload_cross = {
            "training_reads_model": opened(lab, helper, workload_tokens[TRAIN], model, via=TRAIN)[0],
            "model_reads_training": opened(lab, helper, workload_tokens[MODEL], training, via=MODEL)[0],
            "training_uses_signer": vault.request(
                lab, "transit/sign/" + SIGN, token=workload_tokens[TRAIN], via=TRAIN,
                body={"input": b64(MODEL_DATA)})[0],
            "signer_unwraps_training": opened(
                lab, helper, workload_tokens[SIGN], training, via=SIGN)[0],
        }
        wrong_role_login = vault.request(
            lab, "auth/kubernetes/login", via=TRAIN, login=WORKLOAD_ROLES[MODEL])[0]
        workload_signature = vault.required(
            lab, "transit/sign/" + SIGN, token=workload_tokens[SIGN], via=SIGN,
            body={"input": b64(MODEL_DATA)})["data"]["signature"]
        workload_signature_valid = vault.required(
            lab, "transit/verify/" + SIGN, token=workload_tokens[SIGN], via=SIGN,
            body={"input": b64(MODEL_DATA), "signature": workload_signature})["data"]["valid"]
        workload_signature_modified = vault.required(
            lab, "transit/verify/" + SIGN, token=workload_tokens[SIGN], via=SIGN,
            body={"input": b64(TRAIN_DATA), "signature": workload_signature})["data"]["valid"]
        mounted_scope = all(_mounted_workload_identity(lab, domain) for domain in (TRAIN, MODEL, SIGN))
        workload_domains = (
            mounted_scope and workload_train == (200, TRAIN_DATA)
            and workload_model == (200, MODEL_DATA)
            and set(workload_cross.values()) == {403}
            and wrong_role_login in (400, 403)
            and workload_signature_valid and not workload_signature_modified
        )
        lab.check("positive", "Mounted Kubernetes identities use only their bound Vault data or signing domain",
                  workload_domains,
                  {"mounted_scoped_service_accounts": mounted_scope,
                   "training_workload_reads_only_training_marker": workload_train == (200, TRAIN_DATA),
                   "model_workload_reads_only_model_marker": workload_model == (200, MODEL_DATA),
                   "cross_domain_and_wrong_role_denials": workload_cross,
                   "wrong_role_login_denied": wrong_role_login in (400, 403),
                   "signing_workload_signature_valid": workload_signature_valid,
                   "signing_workload_rejects_modified_marker": not workload_signature_modified,
                   "credential_values_recorded": False})

        vault.required(lab, "transit/keys/" + TRAIN + "/rotate", token=root, body={})
        next_record, _ = persisted(lab, "fixture-training-next", make(lab, helper, t, "train", TRAIN, TRAIN_DATA))
        old_still_works = opened(lab, helper, t, training) == (200, TRAIN_DATA)
        wrapping = vault.required(lab, "transit/rewrap/" + TRAIN, token=root,
                                  body={"ciphertext": training["wrapped"]})["data"]["ciphertext"]
        migrated = dict(training, wrapped=wrapping)
        lab.kubectl("patch", "configmap/fixture-training-envelope", "--type=merge",
                    "-p", json.dumps({"data": {"envelope": json.dumps(migrated)}}), "-o", "name")
        refreshed = json.loads(lab.kubectl("get", "configmap/fixture-training-envelope",
                                          "-o", "jsonpath={.data.envelope}").stdout)
        vault.required(lab, "transit/keys/" + TRAIN + "/config", token=root, body={"min_decryption_version": 2})
        lifecycle = (training["wrapped"].startswith("vault:v1:") and next_record["wrapped"].startswith("vault:v2:")
                     and wrapping.startswith("vault:v2:") and refreshed == migrated and old_still_works
                     and opened(lab, helper, t, training)[0] == 400
                     and opened(lab, helper, t, refreshed) == (200, TRAIN_DATA)
                     and opened(lab, helper, m, model) == (200, MODEL_DATA))
        lab.check("positive", "Training key rotation preserves approved reads until rewrite, then rejects the retired version",
                  lifecycle, {"old_version_works_until_rewrap": old_still_works, "safe_training_version_change": lifecycle})
    (lab.evidence / "key-domain-envelope-observations.json").write_text(json.dumps({
        "shared_key_cross_use": exposed, "only_ciphertext_and_wrapped_key_persisted": opaque,
        "domain_and_context_enforced": boundaries, "model_signing_separate": signing_separate,
        "approved_old_read_until_rewrap": old_still_works, "old_version_retired_after_rewrap": lifecycle,
        "mounted_workload_domain_scope": workload_domains,
        "hardware_key_custody_tested": False,
    }, indent=2) + "\n")
