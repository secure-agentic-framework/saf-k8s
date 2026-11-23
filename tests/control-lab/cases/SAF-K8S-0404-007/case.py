"""Observe clock-driven renewal and the live leaf used by a relying client."""
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import runpy
import ssl
import time
from types import SimpleNamespace

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
cm = SimpleNamespace(**runpy.run_path(str(HERE / "issuer_fixture.py")))
HOST = "fixture-renewal.saf-test.svc"
SERVER = "fixture-renewal"
CLIENT = "fixture-relying-client"
ROTATING = "fixture-early-cycle"
STATIC = "fixture-normal-cycle"
ROOT = "fixture-renewal-root"
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
SCOPE = (
    "Live cert-manager schedules renewal at distinct points for two case-owned Certificates. "
    "The short-cycle leaf is reissued with a distinct key before expiry without mutation of the "
    "Certificate spec. A real workload reloads its mounted Secret and a verifying client serves a "
    "public probe across the transition. Other Kubernetes certificate fleets and loading behavior "
    "require independent implementation and evidence."
)


def issuer(name):
    return {"name": name, "kind": "Issuer", "group": "cert-manager.io"}


def trust(lab):
    cm.managed(lab, "Issuer", "fixture-bootstrap", {"selfSigned": {}})
    cm.wait(lab, "issuer", "fixture-bootstrap")
    cm.managed(lab, "Certificate", ROOT, {
        "secretName": ROOT, "issuerRef": issuer("fixture-bootstrap"), "commonName": "SAF renewal fixture root",
        "isCA": True, "duration": "24h", "renewBefore": "2h",
        "privateKey": {"algorithm": "ECDSA", "size": 256, "rotationPolicy": "Never"},
        "usages": ["cert sign", "crl sign"],
    })
    cm.wait(lab, "certificate", ROOT)
    cm.managed(lab, "Issuer", "fixture-renewal-issuer", {"ca": {"secretName": ROOT}})
    cm.wait(lab, "issuer", "fixture-renewal-issuer")
    return cm.public_cert(lab, ROOT, "fixture-root.crt").read_text()


def workload(lab, name, server=False):
    mounts = [{"name": "code", "mountPath": "/fixture", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": "fixture-renewal-code"}}]
    if server:
        mounts.append({"name": "signer", "mountPath": "/certificate", "readOnly": True})
        volumes.append({"name": "signer", "secret": {"secretName": ROTATING, "optional": True, "defaultMode": 0o440}})
    else:
        mounts.append({"name": "trust", "mountPath": "/trust", "readOnly": True})
        volumes.append({"name": "trust", "configMap": {"name": "fixture-renewal-ca"}})
    command = ["python3", "/fixture/tls_service.py", "server"] if server else ["sleep", "400"]
    unit = container("guest", image=PYTHON, command=command, volumeMounts=mounts)
    if server:
        unit["readinessProbe"] = {"tcpSocket": {"port": 8443}, "periodSeconds": 1}
    spec = pod(name, [unit], volumes=volumes, automountServiceAccountToken=False,
               securityContext={"fsGroup": 65534})
    if server:
        spec["metadata"]["labels"] = {"app": SERVER}
    lab.create(spec)


def leaf(lab, name, lead):
    cm.managed(lab, "Certificate", name, {"secretName": name, "issuerRef": issuer("fixture-renewal-issuer"),
        "dnsNames": [HOST], "duration": "1h", "renewBefore": lead, "usages": ["server auth"],
        "privateKey": {"algorithm": "ECDSA", "size": 256, "rotationPolicy": "Always"}})
    cm.wait(lab, "certificate", name)


def cert_info(lab, name, label):
    status = cm.document(lab, "certificate", name)["status"]
    pem = cm.public_cert(lab, name, label + ".pem")
    leaf_pem = pem.read_text().split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
    key = lab.command("openssl", "x509", "-in", str(pem), "-pubkey", "-noout").stdout
    hashes = (sha256(ssl.PEM_cert_to_DER_cert(leaf_pem)).hexdigest(), sha256(key.encode()).hexdigest())
    stamps = {k: datetime.fromisoformat(status[k].replace("Z", "+00:00"))
              for k in ("notBefore", "notAfter", "renewalTime")}
    return status["revision"], stamps, hashes


def call(lab):
    output = lab.kubectl("exec", CLIENT, "--", "python3", "/fixture/tls_service.py", "probe", HOST).stdout
    return json.loads(output)


def run(lab):
    cm.install(lab)
    ca = trust(lab)
    for name, data in (
        ("fixture-renewal-code", {"tls_service.py": (HERE / "tls_service.py").read_text()}),
        ("fixture-renewal-ca", {"ca.crt": ca}),
    ):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": data})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": SERVER},
                "spec": {"selector": {"app": SERVER}, "ports": [{"port": 8443, "targetPort": 8443}]}})
    workload(lab, SERVER, server=True)
    workload(lab, CLIENT)
    ready(lab, CLIENT)
    leaf(lab, STATIC, "25m")
    leaf(lab, ROTATING, "58m30s")
    ready(lab, SERVER)
    static_rev, long_dates, static_hashes = cert_info(lab, STATIC, "ordinary")
    first_rev, first_dates, original = cert_info(lab, ROTATING, "before")
    desired = cm.document(lab, "certificate", ROTATING)["spec"]
    response = call(lab)
    baseline = {"old_leaf_in_use": response.get("healthy") is True and response.get("fingerprint") == original[0],
                "short_cycle_due_before_control": first_dates["renewalTime"] < long_dates["renewalTime"],
                "both_initial": static_rev == first_rev == 1}
    lab.check("red", "Both leaves begin valid while the ordinary schedule is outside the lab interval",
              all(baseline.values()), baseline)

    deadline = time.monotonic() + 110
    current = first_rev
    while time.monotonic() < deadline:
        current = cm.document(lab, "certificate", ROTATING)["status"].get("revision", 0)
        if current > first_rev:
            break
        time.sleep(2)
    if current <= first_rev:
        lab.block("The configured calendar-driven renewal did not occur within the lab window")
    _, next_dates, new_hashes = cert_info(lab, ROTATING, "renewed")
    after_static, _, after_hashes = cert_info(lab, STATIC, "ordinary-after")
    observed = {
        "actual_timer_renewed_after_due": next_dates["notBefore"] >= first_dates["renewalTime"],
        "issued_before_expiry": next_dates["notBefore"] < first_dates["notAfter"],
        "distinct_leaf_and_key": all(before != after for before, after in zip(original, new_hashes)),
        "no_certificate_spec_change": cm.document(lab, "certificate", ROTATING)["spec"] == desired,
        "later_scheduled_control_unchanged": after_static == static_rev and after_hashes == static_hashes,
    }
    lab.check("green", "Only the due Certificate is automatically renewed with a fresh key before expiry",
              all(observed.values()), observed)

    deadline = time.monotonic() + 115
    active = False
    successful_samples = 0
    failed_samples = 0
    while time.monotonic() < deadline:
        check = call(lab)
        if check.get("healthy"):
            successful_samples += 1
            if check.get("fingerprint") == new_hashes[0]:
                active = True
                break
        else:
            failed_samples += 1
        time.sleep(2)
    continued = {"verified_live_service_switched_leaf": active,
                 "switch_observed_before_old_expiry": datetime.now(timezone.utc) < first_dates["notAfter"],
                 "service_health_observed": successful_samples > 0}
    lab.check("positive", "The client validates the active replacement leaf and reads the service marker",
              all(continued.values()), continued)
    (lab.evidence / "scheduled-renewal-observations.json").write_text(json.dumps({
        "baseline": baseline, "scheduled_rotation": observed, "effective_reload": continued,
        "observed_probe_samples": {"successful": successful_samples, "failed": failed_samples},
    }, indent=2) + "\n")
