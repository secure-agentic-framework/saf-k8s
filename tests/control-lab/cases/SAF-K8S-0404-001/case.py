"""Observe real cert-manager issuance, trust and configured key replacement."""
import base64
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import ssl
import time

from fixtures import container, pod

HERE = Path(__file__).resolve().parent

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
    "following a Certificate spec update. A separate live workload demonstrates scheduled "
    "renewal and mounted leaf reload using the same case CA. Alternate issuers and revocation require their own evidence."
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


def review_issuer_and_reissue(lab):
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

# Add-on: calendar-driven renewal, mounted Secret reload and verified live TLS.
SCHEDULED = "fixture-scheduled-leaf"
SCHEDULED_SECRET = f"{SCHEDULED}-tls"
NORMAL = "fixture-scheduled-control"
NORMAL_SECRET = f"{NORMAL}-tls"
RENEWAL_HOST = "fixture-scheduled-reload.saf-test.svc"
RELOAD_SERVER = "fixture-0404-001-reload-server"
RELOAD_CLIENT = "fixture-0404-001-reload-client"
RELOAD_SERVICE = "fixture-scheduled-reload"
RELOAD_CODE = "fixture-0404-001-reload-code"
RELOAD_CA = "fixture-0404-001-reload-ca"
RELOAD_PYTHON = (
    "docker.io/library/python:3.13.2-alpine@sha256:"
    "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
)


def scheduled_spec(secret, renew_before):
    return {
        "secretName": secret,
        "issuerRef": issuer_ref(ISSUER),
        "dnsNames": [RENEWAL_HOST],
        "duration": "1h",
        "renewBefore": renew_before,
        "usages": ["server auth"],
        "privateKey": {"algorithm": "ECDSA", "size": 256, "rotationPolicy": "Always"},
    }


def scheduled_info(lab, certificate, secret, stem):
    status = document(lab, "certificate", certificate)["status"]
    pem = public_cert(lab, secret, stem + ".pem")
    cert_der = ssl.PEM_cert_to_DER_cert(pem.read_text())
    pubkey = lab.command("openssl", "x509", "-in", str(pem), "-pubkey", "-noout",
                         timeout=15).stdout
    dates = {
        key: datetime.fromisoformat(status[key].replace("Z", "+00:00"))
        for key in ("notBefore", "renewalTime", "notAfter")
    }
    return status["revision"], dates, (
        sha256(cert_der).hexdigest(), sha256(pubkey.encode()).hexdigest()
    ), pem


def reload_workload(lab, root_pem):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": RELOAD_CODE},
                "data": {"tls_service.py": (HERE / "tls_service.py").read_text()}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": RELOAD_CA},
                "data": {"ca.crt": root_pem.read_text()}})
    lab.create({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": RELOAD_SERVICE},
                "spec": {"selector": {"app": RELOAD_SERVER},
                         "ports": [{"port": 8443, "targetPort": 8443}]}})
    mounts = [{"name": "code", "mountPath": "/fixture", "readOnly": True}]
    server_volumes = [
        {"name": "code", "configMap": {"name": RELOAD_CODE}},
        {"name": "signer", "secret": {"secretName": SCHEDULED_SECRET,
                                            "defaultMode": 0o440}},
    ]
    mounts.append({"name": "signer", "mountPath": "/certificate", "readOnly": True})
    server = pod(RELOAD_SERVER, [container(
        "server", image=RELOAD_PYTHON,
        command=["python3", "/fixture/tls_service.py", "server"],
        volumeMounts=mounts,
        readinessProbe={"tcpSocket": {"port": 8443}, "periodSeconds": 1},
    )], volumes=server_volumes, automountServiceAccountToken=False,
       securityContext={"fsGroup": 65534})
    server["metadata"]["labels"] = {"app": RELOAD_SERVER}
    lab.create(server)
    client = pod(RELOAD_CLIENT, [container(
        "client", image=RELOAD_PYTHON, command=["sleep", "420"],
        volumeMounts=[
            {"name": "code", "mountPath": "/fixture", "readOnly": True},
            {"name": "trust", "mountPath": "/trust", "readOnly": True},
        ],
    )], volumes=[
        {"name": "code", "configMap": {"name": RELOAD_CODE}},
        {"name": "trust", "configMap": {"name": RELOAD_CA}},
    ], automountServiceAccountToken=False, securityContext={"fsGroup": 65534})
    lab.create(client)
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{RELOAD_SERVER}",
                "--timeout=95s", timeout=105)
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{RELOAD_CLIENT}",
                "--timeout=95s", timeout=105)


def live_probe(lab):
    result = lab.kubectl("exec", RELOAD_CLIENT, "--", "python3", "/fixture/tls_service.py",
                         "probe", RENEWAL_HOST, timeout=20)
    return json.loads(result.stdout)


def run_scheduled_reload(lab):
    try:
        managed(lab, "Certificate", SCHEDULED, scheduled_spec(
            SCHEDULED_SECRET, "58m30s"))
        managed(lab, "Certificate", NORMAL, scheduled_spec(
            NORMAL_SECRET, "25m"))
        wait(lab, "certificate", SCHEDULED)
        wait(lab, "certificate", NORMAL)

        root_pem = public_cert(lab, ROOT_CA, "scheduled-approved-root.pem")
        early, early_dates, early_hashes, _ = scheduled_info(
            lab, SCHEDULED, SCHEDULED_SECRET, "scheduled-before")
        normal_revision, normal_dates, normal_hashes, _ = scheduled_info(
            lab, NORMAL, NORMAL_SECRET, "scheduled-control-before")
        early_spec = document(lab, "certificate", SCHEDULED)["spec"]
        # Verify the actual public leaf against exactly the original case CA.
        early_cert = public_cert(lab, SCHEDULED_SECRET, "scheduled-initial.crt")
        normal_cert = public_cert(lab, NORMAL_SECRET, "scheduled-control.crt")
        early_validation = valid_leaf(lab, early_cert, root_pem, RENEWAL_HOST)
        normal_validation = valid_leaf(lab, normal_cert, root_pem, RENEWAL_HOST)
        schedule_ok = (early_validation["approved_trust_and_dns"]
                       and normal_validation["approved_trust_and_dns"]
                       and early_dates["renewalTime"] < normal_dates["renewalTime"]
                       and early_dates["notAfter"] - early_dates["renewalTime"]
                           == timedelta(minutes=58, seconds=30))
        lab.check(
            "green", "Early and normal-cycle leaves are valid under the original fixture CA with distinct due times",
            schedule_ok,
            {"same_original_fixture_issuer": schedule_ok,
             "early_due_precedes_control": early_dates["renewalTime"] < normal_dates["renewalTime"],
             "early_cycle_configured_renew_before": "58m30s",
             "normal_cycle_configured_renew_before": "25m"},
        )

        reload_workload(lab, root_pem)
        before_wire = live_probe(lab)
        before_ok = (before_wire.get("healthy") is True
                     and before_wire.get("fingerprint") == early_hashes[0])
        lab.check(
            "positive", "The live workload serves the initial mounted leaf over the approved trust",
            before_ok,
            {"healthy_marker": before_wire.get("healthy") is True,
             "initial_leaf_active": before_wire.get("fingerprint") == early_hashes[0]},
        )

        # Observe the scheduled action at the recorded time; do not force a
        # renewal annotation, mutate the Certificate, or change the host clock.
        due_delay = max(0.0, (early_dates["renewalTime"] - datetime.now(timezone.utc)).total_seconds())
        due_at = time.monotonic() + due_delay
        while time.monotonic() < due_at:
            time.sleep(min(1.0, max(0.0, due_at - time.monotonic())))
        renewal_deadline = time.monotonic() + 180
        renewed = None
        while time.monotonic() < renewal_deadline:
            current = document(lab, "certificate", SCHEDULED)["status"].get("revision", 0)
            if current > early:
                renewed = scheduled_info(lab, SCHEDULED, SCHEDULED_SECRET,
                                         "scheduled-after")
                break
            time.sleep(1)
        if renewed is None:
            lab.block("The scheduled Certificate did not advance within 180 seconds of renewalTime")
        new_revision, new_dates, new_hashes, renewed_pem = renewed
        current_spec = document(lab, "certificate", SCHEDULED)["spec"]
        control_revision, _, control_hashes, _ = scheduled_info(
            lab, NORMAL, NORMAL_SECRET, "scheduled-control-after")
        new_validation = valid_leaf(lab, renewed_pem, root_pem, RENEWAL_HOST)
        renewal_ok = (
            new_revision > early
            and new_dates["notBefore"] >= early_dates["renewalTime"]
            and new_dates["notBefore"] < early_dates["notAfter"]
            and new_hashes[0] != early_hashes[0]
            and new_hashes[1] != early_hashes[1]
            and current_spec == early_spec
            and control_revision == normal_revision
            and control_hashes == normal_hashes
            and new_validation["approved_trust_and_dns"]
            and new_validation["ecdsa_p256"]
            and new_validation["server_auth_eku"]
        )
        lab.check(
            "green", "Cert-manager performs the due renewal with a fresh key before expiry and leaves the later control unchanged",
            renewal_ok,
            {"scheduled_revision_advanced": new_revision > early,
             "renewed_before_prior_expiry": new_dates["notBefore"] < early_dates["notAfter"],
             "leaf_and_key_replaced": new_hashes[0] != early_hashes[0] and new_hashes[1] != early_hashes[1],
             "certificate_spec_unchanged": current_spec == early_spec,
             "normal_control_unchanged": control_revision == normal_revision and control_hashes == normal_hashes,
             "original_trust_and_policy_valid": all(new_validation.values())},
        )

        reload_deadline = time.monotonic() + 150
        active = None
        while time.monotonic() < reload_deadline:
            observation = live_probe(lab)
            if observation.get("healthy") and observation.get("fingerprint") == new_hashes[0]:
                active = observation
                break
            time.sleep(1)
        reloaded = active is not None
        lab.check(
            "positive", "The relying client observes the renewed leaf from the live workload and reads its marker",
            reloaded,
            {"renewed_leaf_active": reloaded,
             "marker_healthy": bool(active and active.get("healthy")),
             "same_approved_trust": reloaded,
             "observation_bound_seconds": 150},
        )
        (lab.evidence / "scheduled-workload-reload.json").write_text(json.dumps({
            "renewal_window": "58m30s",
            "renewal_revision_changed": new_revision > early,
            "key_and_leaf_changed": new_hashes[0] != early_hashes[0] and new_hashes[1] != early_hashes[1],
            "certificate_spec_unchanged": current_spec == early_spec,
            "control_unchanged": control_revision == normal_revision and control_hashes == normal_hashes,
            "live_tls_reload": reloaded,
        }, indent=2) + "\n")
    finally:
        for resource, names in (
            ("pod", [RELOAD_SERVER, RELOAD_CLIENT]),
            ("service", [RELOAD_SERVICE]),
            ("configmap", [RELOAD_CODE, RELOAD_CA]),
            ("certificate", [SCHEDULED, NORMAL]),
            ("secret", [SCHEDULED_SECRET, NORMAL_SECRET]),
        ):
            lab.kubectl("delete", resource, *names, "--ignore-not-found=true",
                        "--wait=false", timeout=25, allow_failure=True)


def run(lab):
    review_issuer_and_reissue(lab)
    run_scheduled_reload(lab)
