"""Exercise actual Kubernetes auth, Vault ACL decisions and attributable audit evidence."""

import base64
import json
from pathlib import Path
import runpy
from types import SimpleNamespace

from fixtures import ready

HERE = Path(__file__).resolve().parent
vault = SimpleNamespace(**runpy.run_path(str(HERE / "vault_fixture.py")))
TRAIN = "fixture-training"
SERVE = "fixture-serving"
SIGN = "fixture-signing"
ADMIN = "fixture-governance"
WRONG_AUD = "fixture-wrong-audience"
ENC = "transit/encrypt/"
DEC = "transit/decrypt/"
SIG = "transit/sign/" + SIGN
VER = "transit/verify/" + SIGN
ROTATE = "transit/keys/" + TRAIN + "/rotate"
VALUE = base64.b64encode(b"public fixture data").decode()
SCOPE = (
    "Verify live bound Kubernetes identities, Vault TokenReview auth, role context, actual "
    "cryptographic operation permissions and scoped audit evidence. Provider-specific KMS, "
    "node credential alternatives, HSMs and production audit correlation are separate."
)


def token(lab, subject):
    result = vault.required(lab, "auth/kubernetes/login", via=subject, login=subject)
    return subject, result["auth"]["client_token"]


def post(lab, path, identity, content):
    subject, bearer = identity
    return vault.request(lab, path, token=bearer, body=content, via=subject)


def sealed(lab, key, identity):
    subject, bearer = identity
    return vault.required(lab, ENC + key, token=bearer, body={"plaintext": VALUE}, via=subject)["data"]["ciphertext"]


def audited(entries, path, policy):
    candidates = [e for e in entries if e.get("request", {}).get("path") == path
                  and policy in ((e.get("auth") or {}).get("policies") or [])]
    observed = {}
    for e in candidates:
        observed.setdefault(e["request"].get("id"), set()).add(e.get("type"))
    return any(pair >= {"request", "response"} for pair in observed.values())


def run(lab):
    root = vault.start(lab, auth=True, audit=True)
    for key in (TRAIN, SERVE, SIGN):
        vault.required(lab, "transit/keys/" + key, token=root,
                       body={"type": "ed25519" if key == SIGN else "aes256-gcm96"})
    roles = {
        TRAIN: {ENC + TRAIN: ["update"], DEC + TRAIN: ["update"]},
        SERVE: {ENC + SERVE: ["update"], DEC + SERVE: ["update"]},
        SIGN: {SIG: ["update"], VER: ["update"]},
        ADMIN: {ROTATE: ["update"]},
    }
    for subject, rules in roles.items():
        initial = {**rules, ENC + SERVE: ["update"], SIG: ["update"]} if subject == TRAIN else rules
        vault.permissions(lab, root, subject, initial)
        vault.role(lab, root, subject)
        vault.workload(lab, subject, identity=True)
    vault.workload(lab, WRONG_AUD, identity=True, audience="https://wrong.fixture.invalid", account=TRAIN)
    for subject in (*roles, WRONG_AUD):
        ready(lab, subject)

    tokens = {subject: token(lab, subject) for subject in roles}
    training = tokens[TRAIN]
    serving = tokens[SERVE]
    signer = tokens[SIGN]
    governance = tokens[ADMIN]
    wide = post(lab, ENC + SERVE, training, {"plaintext": VALUE})[0]
    wide_sign = post(lab, SIG, training, {"input": VALUE})[0]
    wrong_subject = vault.request(lab, "auth/kubernetes/login", via=TRAIN, login=SERVE)[0]
    wrong_audience = vault.request(lab, "auth/kubernetes/login", via=WRONG_AUD, login=TRAIN)[0]
    lab.check("red", "The same valid workload identity can use the unrelated fixture keys under the broad policy",
              wide == wide_sign == 200 and wrong_subject in (400, 403) and wrong_audience in (400, 403),
              {"initial_cross_domain_use": wide, "initial_cross_domain_signing": wide_sign,
               "other_role_login_rejected": wrong_subject in (400, 403),
               "different_login_audience_rejected": wrong_audience in (400, 403)})

    vault.permissions(lab, root, TRAIN, roles[TRAIN])
    training_blob = sealed(lab, TRAIN, training)
    serving_blob = sealed(lab, SERVE, serving)
    signatures = vault.required(lab, SIG, token=signer[1], via=signer[0], body={"input": VALUE})["data"]["signature"]
    verifies = vault.required(lab, VER, token=signer[1], via=signer[0], body={"input": VALUE, "signature": signatures})["data"]["valid"]
    positive = (
        post(lab, DEC + TRAIN, training, {"ciphertext": training_blob})[1].get("data", {}).get("plaintext") == VALUE
        and post(lab, DEC + SERVE, serving, {"ciphertext": serving_blob})[1].get("data", {}).get("plaintext") == VALUE
        and verifies and post(lab, ROTATE, governance, {})[0] in (200, 204)
    )
    denied = {
        "training_encrypt_serving": post(lab, ENC + SERVE, training, {"plaintext": VALUE})[0],
        "training_sign": post(lab, SIG, training, {"input": VALUE})[0],
        "serving_decrypt_training": post(lab, DEC + TRAIN, serving, {"ciphertext": training_blob})[0],
        "signer_decrypt_model": post(lab, DEC + SERVE, signer, {"ciphertext": serving_blob})[0],
        "governance_use_data_key": post(lab, DEC + TRAIN, governance, {"ciphertext": training_blob})[0],
        "training_rotate_key": post(lab, ROTATE, training, {})[0],
        "training_change_policy": post(lab, "sys/policies/acl/" + TRAIN, training, {"policy": ""})[0],
    }
    lab.check("green", "Provider ACLs preserve required operations and deny unrelated keys, signing and policy administration",
              positive and set(denied.values()) == {403}, {"required_operations_allowed": positive, "cross_domain_http": denied})

    audit = vault.audit_entries(lab)
    audit_chain = audited(audit, DEC + TRAIN, TRAIN) and audited(audit, DEC + TRAIN, SERVE) and audited(audit, SIG, SIGN)
    vault.permissions(lab, root, TRAIN, {ENC + TRAIN: ["update"]})
    narrowed = post(lab, DEC + TRAIN, training, {"ciphertext": training_blob})[0] == 403
    other = post(lab, DEC + SERVE, serving, {"ciphertext": serving_blob})[0] == 200
    lab.check("positive", "Vault audit correlates actual allowed and denied requests, and narrowing the grant changes the live decision",
              audit_chain and narrowed and other, {"path_and_policy_audit_correlated": audit_chain,
                                                   "removed_permission_denied": narrowed, "serving_permission_preserved": other})
    (lab.evidence / "key-domain-authorization-observations.json").write_text(json.dumps({
        "initial_cross_domain_used": wide == wide_sign == 200, "wrong_role_and_audience_in_login_denied":
            wrong_subject in (400, 403) and wrong_audience in (400, 403), "scoped_http_denials": denied,
        "required_operations_preserved": positive, "auditable_decisions": audit_chain,
        "permission_removal_observed": narrowed, "serving_unaffected": other,
    }, indent=2) + "\n")
