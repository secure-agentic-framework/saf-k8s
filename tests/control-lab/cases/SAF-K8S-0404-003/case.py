"""Observe mutual TLS and separate peer authorization between running fixture Pods."""
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
SCOPE = (
    "Actual TLS 1.3 between owned Kubernetes Pods verifies a server name, server trust, "
    "and client certificate trust. An explicit service decision separate from the TLS "
    "handshake limits the verified client identity. Automatic issuance, service mesh, "
    "all production flows, revocation and authorization surfaces need separate evidence."
)
HOST = "fixture-mtls.saf-test.svc"
OTHER = "fixture-wrong-host.saf-test.svc"
CLIENT = "fixture-mtls-client"
APP = "fixture-mtls-server"
CREDENTIALS = ("training", "neighbor", "untrusted")


def object_of(lab, kind, name, **body):
    return lab.create({"apiVersion": "v1", "kind": kind, "metadata": {"name": name}, **body})


def root_ca(lab, directory, name):
    key = directory / f"{name}.key"
    cert = directory / f"{name}.crt"
    lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", f"/CN={name}", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
                "-keyout", str(key), "-out", str(cert))
    return cert, key


def issue(lab, directory, issuer, name, identity, purpose):
    key, csr, certificate, config = (directory / f"{name}.{suffix}" for suffix in ("key", "csr", "crt", "ext"))
    config.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                      "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
                      f"extendedKeyUsage={purpose}\nsubjectAltName={identity}\n")
    lab.command("openssl", "req", "-new", "-nodes", "-newkey", "rsa:2048", "-subj", f"/CN={name}",
                "-keyout", str(key), "-out", str(csr))
    ca, ca_key = issuer
    lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                "-CAcreateserial", "-days", "1", "-extfile", str(config), "-out", str(certificate))
    lab.kubectl("create", "secret", "tls", f"fixture-key-{name}", "--key=" + str(key),
                "--cert=" + str(certificate), "-o", "name")


def workload(lab, name, mode, identities, server=False):
    mounts = [{"name": "script", "mountPath": "/code", "readOnly": True},
              {"name": "trust", "mountPath": "/trust", "readOnly": True}]
    volumes = [{"name": "script", "configMap": {"name": "fixture-mtls-code"}},
               {"name": "trust", "configMap": {"name": "fixture-mtls-ca"}}]
    for credential in identities:
        mounts.append({"name": credential,
                       "mountPath": "/identity" if server else f"/client/{credential}", "readOnly": True})
        volumes.append({"name": credential, "secret": {"secretName": f"fixture-key-{credential}",
                                                       "defaultMode": 0o440}})
    args = ["python3", "/code/workloads.py", "server", mode] if server else ["sleep", "240"]
    unit = container("guest", image=PYTHON, command=args, volumeMounts=mounts)
    if server:
        unit["readinessProbe"] = {"tcpSocket": {"port": 8443}, "periodSeconds": 1}
    spec = pod(name, [unit], automountServiceAccountToken=False, volumes=volumes,
               securityContext={"fsGroup": 65534})
    if server:
        spec["metadata"]["labels"] = {"app": APP}
    lab.create(spec)


def call(lab, host, credential="none"):
    output = lab.kubectl("exec", CLIENT, "--", "python3", "/code/workloads.py",
                         "request", host, credential).stdout
    return json.loads(output)


def accepted(lab, credential):
    end = time.monotonic() + 20
    while time.monotonic() < end:
        result = call(lab, HOST, credential)
        if result.get("http") == 200:
            return result
        time.sleep(.5)
    lab.block("The intended fixture endpoint did not become usable through Service routing")


def run(lab):
    directory = lab.kubeconfig.parent
    ca = root_ca(lab, directory, "fixture-approved-ca")
    external = root_ca(lab, directory, "fixture-unapproved-ca")
    issue(lab, directory, ca, "server", f"DNS:{HOST}", "serverAuth")
    for role in CREDENTIALS:
        issuer = external if role == "untrusted" else ca
        issue(lab, directory, issuer, role, f"URI:spiffe://fixture.invalid/{role}", "clientAuth")
    object_of(lab, "ConfigMap", "fixture-mtls-code", data={"workloads.py": (HERE / "workloads.py").read_text()})
    object_of(lab, "ConfigMap", "fixture-mtls-ca", data={"ca.crt": ca[0].read_text()})
    for service in (HOST.split(".")[0], OTHER.split(".")[0]):
        object_of(lab, "Service", service, spec={
            "selector": {"app": APP}, "ports": [{"port": 8443, "targetPort": 8443}]})
    workload(lab, CLIENT, "", CREDENTIALS)
    workload(lab, APP, "server-only", ["server"], server=True)
    ready(lab, CLIENT)
    ready(lab, APP)
    baseline = accepted(lab, "none")
    red = {"unidentified_client_reaches_server_only_operation": baseline == {
        "tls": "TLSv1.3", "http": 200, "identity": [], "operation": True}}
    lab.check("red", "Server-only TLS permits an unidentified fixture client to perform the public operation",
              all(red.values()), red)

    lab.kubectl("delete", "pod", APP, "--wait=true")
    workload(lab, APP, "mutual", ["server"], server=True)
    ready(lab, APP)
    permitted = accepted(lab, "training")
    before = lab.kubectl("logs", APP).stdout
    missing = call(lab, HOST)
    untrusted = call(lab, HOST, "untrusted")
    wrong_hostname = call(lab, OTHER, "training")
    after = lab.kubectl("logs", APP).stdout
    no_peer = "fixture server denied missing peer certificate"
    no_issuer = "fixture server denied unknown peer issuer"
    green = {
        "no_certificate_denied": "http" not in missing and after.count(no_peer) == before.count(no_peer) + 1,
        "untrusted_client_denied": "http" not in untrusted and after.count(no_issuer) == before.count(no_issuer) + 1,
        "wrong_server_identity_denied": wrong_hostname == {"error": "server-certificate-verification", "verify_code": 62},
    }
    lab.check("green", "Actual TLS verification rejects missing and untrusted clients and a mismatched server name",
              all(green.values()), green)

    neighbor = call(lab, HOST, "neighbor")
    positive = {
        "approved_identity_completed_operation": permitted == {
            "tls": "TLSv1.3", "http": 200, "identity": ["spiffe://fixture.invalid/training"], "operation": True},
        "authenticated_neighbor_was_not_authorized": neighbor == {
            "tls": "TLSv1.3", "http": 403, "identity": ["spiffe://fixture.invalid/neighbor"], "operation": False},
    }
    lab.check("positive", "An authenticated peer can still be denied by the separate operation policy",
              all(positive.values()), positive)
    (lab.evidence / "mutual-tls-observations.json").write_text(json.dumps({
        "server_only": red, "transport_validation": green, "operation_authorization": positive,
    }, indent=2) + "\n")
