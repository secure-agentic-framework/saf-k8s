"""Observe real cert-manager issuance, trust and configured key replacement."""
import base64
from datetime import datetime
from hashlib import sha256
import json
import re
import time

RELEASE = "v1.21.3"
MANIFEST = f"https://github.com/cert-manager/cert-manager/releases/download/{RELEASE}/cert-manager.yaml"
MANIFEST_SHA = "c04a51295adda2b1a775146751f973e787190778c7f35180861d9678876e5c74"
IMAGES = {
    "cainjector": "083d0e906f8eb44e255fe4ff817ae54e49f9ed82e22f1011bb4e9e4f4b8a641f",
    "controller": "9f4f96a33c7774cef24466fcd85031997531a03a8d117f151126baa8d1290dcc",
    "webhook": "055ac8e9de6a0ba6763794838fe38944acc650f68ebe1b01dd8be079e580f458",
}
API = "cert-manager.io/v1"
BOOTSTRAP = "fixture-bootstrap"
ROOT_CA = "fixture-root-ca"
ISSUER = "fixture-namespaced-issuer"
LEAF = "fixture-leaf"
LEAF_SECRET = f"{LEAF}-tls"
HOST = "fixture-endpoint.saf-test.svc"
UPDATED = "fixture-updated.saf-test.svc"
SCOPE = (
    "Real cert-manager controllers deploy from a reviewed version on fresh Kind. The "
    "case verifies missing issuer behavior, same-namespace CA-backed ECDSA issuance, "
    "the actual validation chain, the recorded renewal schedule, and key replacement "
    "following a Certificate spec update. ACME, other providers, client reload, custody "
    "and issuer-side revocation require separate operational evidence."
)


def managed(lab, kind, name, spec, dry_run=False):
    return lab.create({"apiVersion": API, "kind": kind, "metadata": {"name": name}, "spec": spec},
                      dry_run=dry_run, allow_failure=dry_run)


def document(lab, kind, name):
    out = lab.kubectl("get", kind, name, "-o", "json").stdout
    return json.loads(out)


def wait(lab, kind, name, condition="Ready"):
    lab.kubectl("wait", f"--for=condition={condition}", kind + "/" + name,
                "--timeout=95s", timeout=105)


def install(lab):
    local = lab.kubeconfig.parent / "cert-manager.yaml"
    lab.command("curl", "--fail", "--location", "--silent", "--show-error", "--proto", "=https",
                "--max-time", "45", MANIFEST, "-o", str(local), timeout=50)
    release = local.read_bytes()
    if sha256(release).hexdigest() != MANIFEST_SHA:
        lab.block("The official cert-manager artifact does not match the reviewed manifest")
    adjusted = release.decode()
    for part, digest in IMAGES.items():
        ref = f"quay.io/jetstack/cert-manager-{part}:{RELEASE}"
        if adjusted.count(ref) != 1:
            lab.block("The reviewed cert-manager manifest has a changed image set")
        adjusted = adjusted.replace(ref, f"{ref}@sha256:{digest}")
    local.write_text(adjusted)
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "apply", "-f", str(local), timeout=120)
    for name in ("cert-manager", "cert-manager-cainjector", "cert-manager-webhook"):
        lab.kubectl("-n", "cert-manager", "rollout", "status", "deployment/" + name,
                    "--timeout=145s", timeout=155)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = managed(lab, "Issuer", "fixture-startup-probe", {"selfSigned": {}}, dry_run=True)
        if status.returncode == 0:
            return
        time.sleep(.5)
    lab.block("The pinned certificate admission webhook did not become available")


def issuer_ref(issuer):
    return {"name": issuer, "kind": "Issuer", "group": "cert-manager.io"}


def leaf_spec():
    return {"secretName": LEAF_SECRET, "issuerRef": issuer_ref(ISSUER),
            "dnsNames": [HOST], "duration": "2h", "renewBefore": "40m", "usages": ["server auth"],
            "privateKey": {"algorithm": "ECDSA", "size": 256, "rotationPolicy": "Always"}}


def public_cert(lab, name, filename):
    selected = lab.kubectl("get", "secret", name, "-o", 'go-template={{index .data "tls.crt"}}').stdout.strip()
    local = lab.kubeconfig.parent / filename
    local.write_bytes(base64.b64decode(selected, validate=True))
    return local


def valid_leaf(lab, leaf, root, hostname):
    pins = lab.command("openssl", "x509", "-in", str(leaf), "-text", "-noout").stdout
    verify = lab.command("openssl", "verify", "-CAfile", str(root), "-purpose", "sslserver",
                         str(leaf), allow_failure=True)
    return {
        "approved_trust_and_dns": verify.returncode == 0 and re.findall(r"DNS:([^,\s]+)", pins) == [hostname],
        "ecdsa_p256": "id-ecPublicKey" in pins and ("prime256v1" in pins or "P-256" in pins),
        "server_auth_eku": "TLS Web Server Authentication" in pins,
    }


def run(lab):
    install(lab)
    managed(lab, "Certificate", LEAF, leaf_spec())
    wait(lab, "certificate", LEAF, "Ready=false")
    absent_issuer = lab.kubectl("get", "issuer", ISSUER, "-o", "name", allow_failure=True)
    absent_leaf = lab.kubectl("get", "secret", LEAF_SECRET, "-o", "name", allow_failure=True)
    red = {"issuer_not_found": "(NotFound)" in absent_issuer.stderr,
           "serving_secret_not_issued": "(NotFound)" in absent_leaf.stderr}
    lab.check("red", "The controller cannot issue the fixture leaf without its named issuer", all(red.values()), red)

    managed(lab, "Issuer", BOOTSTRAP, {"selfSigned": {}})
    wait(lab, "issuer", BOOTSTRAP)
    managed(lab, "Certificate", ROOT_CA, {
        "secretName": ROOT_CA, "issuerRef": issuer_ref(BOOTSTRAP),
        "isCA": True, "commonName": "SAF fixture CA", "duration": "24h", "renewBefore": "2h",
        "privateKey": {"algorithm": "ECDSA", "size": 256, "rotationPolicy": "Never"},
    })
    wait(lab, "certificate", ROOT_CA)
    managed(lab, "Issuer", ISSUER, {"ca": {"secretName": ROOT_CA}})
    wait(lab, "issuer", ISSUER)
    wait(lab, "certificate", LEAF)
    root = public_cert(lab, ROOT_CA, "approved-root.pem")
    leaf = public_cert(lab, LEAF_SECRET, "initial-leaf.pem")
    cert_status = document(lab, "certificate", LEAF)["status"]
    times = {key: datetime.fromisoformat(cert_status[key].replace("Z", "+00:00"))
             for key in ("notBefore", "renewalTime", "notAfter")}
    observed = valid_leaf(lab, leaf, root, HOST)
    observed["observed_two_hour_validity"] = (times["notAfter"] - times["notBefore"]).total_seconds() == 7200
    observed["scheduled_forty_minutes_before_expiry"] = (times["notAfter"] - times["renewalTime"]).total_seconds() == 2400
    lab.check("green", "The actual issuer provisions a DNS-verified P-256 server certificate with the configured lifetime",
              all(observed.values()), observed)

    next_spec = json.dumps({"spec": {"dnsNames": [UPDATED]}})
    lab.kubectl("patch", "certificate", LEAF, "--type=merge", "-p", next_spec, "-o", "name")
    deadline = time.monotonic() + 60
    second = None
    while time.monotonic() < deadline:
        status = document(lab, "certificate", LEAF)["status"]
        if status.get("revision", 0) > cert_status["revision"]:
            second = public_cert(lab, LEAF_SECRET, "reissued-leaf.pem")
            break
        time.sleep(.6)
    if second is None:
        lab.block("The controller did not complete spec-triggered reissuance")
    first_key = lab.command("openssl", "x509", "-in", str(leaf), "-pubkey", "-noout").stdout
    next_key = lab.command("openssl", "x509", "-in", str(second), "-pubkey", "-noout").stdout
    positive = valid_leaf(lab, second, root, UPDATED)
    positive["same_trusted_issuer_with_replaced_key"] = bool(first_key and next_key and first_key != next_key)
    old_still_verifies = valid_leaf(lab, leaf, root, HOST)["approved_trust_and_dns"]
    positive["previous_leaf_still_verifies_at_original_identity"] = old_still_verifies
    lab.check("positive", "A specification update reissues under the expected CA and policy while key replacement leaves the original certificate cryptographically valid",
              all(positive.values()), positive)
    (lab.evidence / "certificate-issuer-observations.json").write_text(json.dumps({
        "cert_manager_version": RELEASE, "manifest_sha256": MANIFEST_SHA,
        "missing_issuer": red, "issued_certificate": observed, "reissuance": positive,
    }, indent=2) + "\n")
