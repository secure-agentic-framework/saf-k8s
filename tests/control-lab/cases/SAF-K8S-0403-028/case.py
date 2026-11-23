"""Verify operator-authorized revocation and continuity at the actual fixture issuer."""
import base64
import json
from pathlib import Path
import runpy
import time
from types import SimpleNamespace

from fixtures import ready

HERE = Path(__file__).resolve().parent
vault = SimpleNamespace(**runpy.run_path(str(HERE / "vault_fixture.py")))
INCIDENT = "fixture-exposure-report"
DECISION = "fixture-credential-disposition"
CONSUMER = "fixture-still-needed-consumer"
KEY = "fixture-verified-response"
PATH = "transit/encrypt/" + KEY
PAYLOAD = base64.b64encode(b"public response continuity marker").decode()
POLICY = "fixture-continuity-only"
RESPONDER = "fixture-revoke-only"
TARGET_SECONDS = 30
SCOPE = (
    "A public test report refers to two case-owned credentials without reporting the "
    "credentials themselves. Live TLS Vault proves issuer-side invalidation, preserves a "
    "separate trusted consumer path, and reissues only the still-needed credential. "
    "External issuers, detection, provider-specific action policies and production timing "
    "need independent evidence."
)


def config(lab, name, data):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "immutable": True, "data": data})


def issue(lab, root, role):
    created = vault.required(lab, "auth/token/create", token=root, body={
        "policies": [POLICY], "token_type": "service", "ttl": "10m",
        "no_default_policy": True, "meta": {"case_owned_usage": role},
    })["auth"]
    return created["accessor"], created["client_token"]


def operate(lab, token, via=CONSUMER):
    code, result = vault.request(lab, PATH, token=token, body={"plaintext": PAYLOAD}, via=via)
    protected = result.get("data", {}).get("ciphertext", "").startswith("vault:v1:")
    return code, protected


def retire(lab, identity, credential):
    return vault.request(lab, "auth/token/revoke-accessor", token=identity,
                         body={"accessor": credential[0]})[0]


def run(lab):
    root = vault.start(lab)
    vault.workload(lab, CONSUMER)
    ready(lab, CONSUMER)
    vault.required(lab, "transit/keys/" + KEY, token=root, body={"type": "aes256-gcm96"})
    vault.permissions(lab, root, POLICY, {PATH: ["update"]})
    vault.permissions(lab, root, RESPONDER, {"auth/token/revoke-accessor": ["update", "sudo"]})
    responder = vault.scoped_token(lab, root, RESPONDER)
    active = issue(lab, root, "continues")
    unused = issue(lab, root, "retired")
    unrelated = issue(lab, root, "unrelated")
    config(lab, INCIDENT, {"signal": "public-fixture-exposure", "continues": "replacement-required",
                           "retired": "invalidate-only"})
    lab.kubectl("delete", "configmap", INCIDENT, "--wait=true")
    red = {
        "active_access_survives_report_cleanup": operate(lab, active[1]) == (200, True),
        "retired_access_survives_report_cleanup": operate(lab, unused[1]) == (200, True),
        "unapproved_revocation_rejected": retire(lab, unrelated[1], unused) == 403,
        "unapproved_action_leaves_access_active": operate(lab, unused[1]) == (200, True),
    }
    lab.check("red", "Removing the fixture report leaves issuer access active and a workload cannot revoke it",
              all(red.values()), red)

    signal_at = time.monotonic()
    config(lab, INCIDENT, {"signal": "public-fixture-exposure", "continues": "replacement-required",
                           "retired": "invalidate-only"})
    statuses = {}
    for role, item in (("continues", active), ("retired", unused)):
        statuses[role] = retire(lab, responder, item)
    retired = {"continues": operate(lab, active[1])[0], "retired": operate(lab, unused[1])[0]}
    delay = round(time.monotonic() - signal_at, 3)
    verified = {
        "authority_confirmed_both_requests": statuses == {"continues": 204, "retired": 204},
        "old_authority_decisions": retired,
        "confirmed_within_fixture_target": delay <= TARGET_SECONDS,
    }
    lab.check("green", "The scoped incident operator verifies actual issuer denial before the fixture deadline",
              all(status == 403 for status in retired.values())
              and verified["authority_confirmed_both_requests"] and verified["confirmed_within_fixture_target"],
              verified)

    replacement = issue(lab, root, "continues-replacement")
    final = {
        "replacement_distinct_and_observed": replacement[0] != active[0]
        and operate(lab, replacement[1]) == (200, True),
        "old_credential_stays_denied": operate(lab, active[1]) == (403, False),
        "unrelated_credential_survives": operate(lab, unrelated[1]) == (200, True),
        "retired_credential_stays_denied": operate(lab, unused[1]) == (403, False),
    }
    config(lab, DECISION, {"source": INCIDENT, "continues": "replaced-and-verified",
                           "retired": "invalidated-without-replacement"})
    retained = json.loads(lab.kubectl("get", "configmap", DECISION, "-o", "json").stdout)["data"]
    final["separate_dispositions_retained"] = retained == {
        "source": INCIDENT, "continues": "replaced-and-verified",
        "retired": "invalidated-without-replacement",
    }
    lab.check("positive", "The affected consumer continues only with its replacement and unrelated access survives",
              all(final.values()), final)
    (lab.evidence / "issuer-revocation-observations.json").write_text(json.dumps({
        "baseline": red, "issuer_rejected_old": verified, "continuity": final,
        "fixture_seconds": delay, "target_seconds": TARGET_SECONDS,
    }, indent=2) + "\n")
