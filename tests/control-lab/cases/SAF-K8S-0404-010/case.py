"""Observe secure service recovery on the actual replacement credential."""
import json
from pathlib import Path
import runpy
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
pki = SimpleNamespace(**runpy.run_path(str(HERE / "pki_fixture.py")))
MAIN = "fixture-pki"
OLD = "fixture-service-original"
NEW = "fixture-service-replacement"
OTHER = "fixture-independent"
RELATED = f"{OTHER}.saf-test.svc"
SCOPE = (
    "A real Kubernetes Service and independent client prove which server certificate is in use. "
    "The test observes a stale endpoint after replacement issuance, confirms the old endpoint "
    "is rejected after CRL publication, switches traffic, and confirms scoped dependent and "
    "unaffected service reads against the intended active credentials."
)


def current(lab, host, *, policy="crl"):
    return pki.call(lab, host, policy=policy)


def waits_for(callback, condition, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = callback()
        if condition(value):
            return True
        time.sleep(2)
    return False


def run(lab):
    ca = pki.CA(lab)
    original = ca.issue("original-leaf", f"DNS:{pki.HOST}", "serverAuth")
    replacement = ca.issue("replacement-leaf", f"DNS:{pki.HOST}", "serverAuth")
    other = ca.issue("independent-leaf", f"DNS:{RELATED}", "serverAuth")
    first, expected, unaffected = map(ca.fingerprint, (original, replacement, other))
    pki.common(lab, ca)
    pki.workload(lab, OLD, ["original-leaf"], server_mode="server")
    pki.workload(lab, NEW, ["replacement-leaf"], server_mode="server")
    pki.workload(lab, OTHER, ["independent-leaf"], server_mode="server")
    pki.workload(lab, pki.CLIENT)
    pki.service(lab, MAIN, OLD)
    pki.service(lab, OTHER, OTHER)
    for fixture in (pki.CLIENT, OLD, NEW, OTHER):
        pki.ready(lab, fixture)
    old = {"allowed": True, "protocol": "TLSv1.3", "leaf": first}
    approved = {"allowed": True, "protocol": "TLSv1.3", "leaf": expected}
    surrounding = {"allowed": True, "protocol": "TLSv1.3", "leaf": unaffected}
    before = waits_for(lambda: current(lab, pki.HOST), lambda r: r == old, 25)
    initial = {"new_credential_not_yet_served": before and first != expected,
               "separate_key_issued": ca.key_hash(original) != ca.key_hash(replacement),
               "independent_endpoint_healthy": current(lab, RELATED) == surrounding}
    lab.check("red", "A staged replacement is present but the dependent client still sees the old active leaf",
              all(initial.values()), initial)

    ca.revoke(original)
    pki.bundle(lab, ca, ca.revocation_list())
    stale_denied = waits_for(lambda: current(lab, pki.HOST),
                            lambda r: r == {"allowed": False, "verify_code": 23}, 115)
    boundaries = {"stale_endpoint_rejected_by_revocation_aware_client": stale_denied,
                  "chain_only_call_still_observes_old_leaf": current(lab, pki.HOST, policy="chain") == old}
    lab.check("green", "Actual dependent health remains failed while traffic still reaches the revoked serving leaf",
              all(boundaries.values()), boundaries)

    pki.route(lab, MAIN, NEW)
    active = waits_for(lambda: current(lab, pki.HOST), lambda r: r == approved, 45)
    recovered = {"expected_replacement_leaf_and_operation_verified": active,
                 "independent_service_continuity": current(lab, RELATED) == surrounding,
                 "replacement_stable_across_fresh_connections": current(lab, pki.HOST) == approved}
    lab.check("positive", "The dependent client verifies the intended replacement on real fresh service connections",
              all(recovered.values()), recovered)
    (lab.evidence / "replacement-recovery-observations.json").write_text(json.dumps({
        "replacement_staged": initial, "stale_service": boundaries, "observed_recovery": recovered,
    }, indent=2) + "\n")
