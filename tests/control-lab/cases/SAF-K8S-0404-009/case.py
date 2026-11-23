"""Verify provider action and reciprocal relying-peer enforcement for one compromised leaf."""
import json
from pathlib import Path
import runpy
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
pki = SimpleNamespace(**runpy.run_path(str(HERE / "pki_fixture.py")))
OLD = "retiring-client"
NEW = "replacement-client"
INDEPENDENT = "independent-client"
SERVER = "fixture-pki"
SCOPE = (
    "A disposable CA explicitly revokes one synthetic client certificate, signs an updated CRL, and "
    "issues a fresh key and replacement leaf with the expected identity. A real TLS service uses "
    "the published CRL; actual prior-peer rejection and unaffected access are observed. Other "
    "issuers, control-plane consumers, propagation objectives and recovery remain separate."
)


def permitted(lab, identity):
    return pki.call(lab, pki.HOST, client=identity).get("allowed") is True


def await_initial(lab):
    end = time.monotonic() + 25
    while time.monotonic() < end:
        if permitted(lab, OLD):
            return
        time.sleep(.5)
    lab.block("The case-owned peer did not reach the initial validating service")


def run(lab):
    ca = pki.CA(lab)
    ca.issue("server-leaf", f"DNS:{pki.HOST}", "serverAuth")
    identity = "URI:spiffe://fixture.invalid/controlled-client"
    old = ca.issue(OLD, identity, "clientAuth")
    new = ca.issue(NEW, identity, "clientAuth")
    ca.issue(INDEPENDENT, "URI:spiffe://fixture.invalid/independent", "clientAuth")
    pki.common(lab, ca)
    pki.workload(lab, SERVER, ["server-leaf"], server_mode="mutual")
    pki.workload(lab, pki.CLIENT, [OLD, NEW, INDEPENDENT])
    pki.service(lab, SERVER, SERVER)
    pki.ready(lab, pki.CLIENT)
    pki.ready(lab, SERVER)
    await_initial(lab)
    red = {"old_peer_still_admitted_after_replacement_issued": permitted(lab, OLD),
           "new_key_differs": ca.key_hash(old) != ca.key_hash(new),
           "replacement_peer_can_use_expected_identity": permitted(lab, NEW)}
    lab.check("red", "Issuance and a distinct key leave both certificates valid before revocation", all(red.values()), red)

    before = lab.kubectl("logs", SERVER).stdout
    ca.revoke(old)
    current = ca.revocation_list()
    inspection = lab.command("openssl", "crl", "-in", str(current), "-text", "-noout").stdout
    serial = lab.command("openssl", "x509", "-in", str(old), "-serial", "-noout").stdout.strip().split("=", 1)[1]
    certified = f"Serial Number: {serial.upper()}" in inspection and "Key Compromise" in inspection
    pki.bundle(lab, ca, current)
    observed_denial = False
    deadline = time.monotonic() + 115
    while time.monotonic() < deadline:
        if not permitted(lab, OLD):
            logs = lab.kubectl("logs", SERVER).stdout
            observed_denial = logs.count("fixture peer certificate revoked") > before.count("fixture peer certificate revoked")
            if observed_denial:
                break
        time.sleep(2)
    defense = {"old_exact_serial_revoked_for_key_compromise": certified,
               "live_service_rejects_revoked_peer": observed_denial}
    lab.check("green", "The issuing authority records compromise and the actual verifier rejects that exact peer",
              all(defense.values()), defense)
    kept = {"replacement_peer_operates": permitted(lab, NEW),
            "unrelated_peer_operates": permitted(lab, INDEPENDENT),
            "retired_peer_remains_denied": not permitted(lab, OLD)}
    lab.check("positive", "Replacement and unrelated live peers remain accepted under the same CRL",
              all(kept.values()), kept)
    (lab.evidence / "certificate-revocation-observations.json").write_text(json.dumps({
        "initial_validity": red, "authority_and_relying_party": defense, "retained_access": kept,
    }, indent=2) + "\n")
