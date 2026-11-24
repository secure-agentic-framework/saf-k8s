"""Contrast intent, temporary session and native mutual TLS on owned loopback markers."""

import json
from pathlib import Path

SCOPE = "A restricted Job compares fixed intent, expiring issued sessions and native TLS client authentication using only loopback markers."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAME = "fixture-metadata-modes"


def fixture_certificates(lab):
    directory = lab.kubeconfig.parent / "local-protocol-pki"
    directory.mkdir(mode=0o700)
    for name in ("ca", "other-ca"):
        lab.command("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", f"/CN={name}-owned-fixture", "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
                    "-keyout", str(directory / f"{name}.key"), "-out", str(directory / f"{name}.crt"))
    for leaf, issuer, subject, usage in (
        ("server", "ca", "fixture-server", "serverAuth"),
        ("client", "ca", "fixture-approved-client", "clientAuth"),
        ("outsider", "other-ca", "fixture-approved-client", "clientAuth"),
    ):
        key, csr, cert = (directory / f"{leaf}.{extension}" for extension in ("key", "csr", "crt"))
        extension_file = directory / f"{leaf}.ext"
        extension_file.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                  "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
                                  f"extendedKeyUsage={usage}\n" +
                                  ("subjectAltName=IP:127.0.0.1\n" if leaf == "server" else ""))
        lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-subj", f"/CN={subject}", "-keyout", str(key), "-out", str(csr))
        lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(directory / f"{issuer}.crt"),
                    "-CAkey", str(directory / f"{issuer}.key"), "-CAcreateserial", "-days", "2",
                    "-sha256", "-extfile", str(extension_file), "-out", str(cert))
    for name, purpose, issuer in (("server", "sslserver", "ca"), ("client", "sslclient", "ca"),
                                  ("outsider", "sslclient", "other-ca")):
        lab.command("openssl", "verify", "-x509_strict", "-purpose", purpose,
                    "-CAfile", str(directory / f"{issuer}.crt"), str(directory / f"{name}.crt"))
    names = ("ca.crt", "server.crt", "server.key", "client.crt", "client.key", "outsider.crt", "outsider.key")
    lab.kubectl("create", "secret", "generic", NAME, *(f"--from-file={directory / name}" for name in names),
                "-o", "name")


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    fixture_certificates(lab)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME}, "immutable": True,
                "data": {"fixture.py": Path(__file__).with_name("protocol-fixture.py").read_text()}})
    container = {"name": "probe", "image": IMAGE, "command": ["python", "/fixture/fixture.py"],
                 "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                                  {"name": "pki", "mountPath": "/fixture-pki", "readOnly": True}],
                 "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "150m", "memory": "64Mi"}},
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME},
                "spec": {"backoffLimit": 0, "template": {"spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "fixture", "configMap": {"name": NAME}},
                                {"name": "pki", "secret": {"secretName": NAME}}], "containers": [container],
                }}}})
    completion = lab.kubectl("wait", "--for=condition=Complete", f"job/{NAME}",
                             "--timeout=85s", timeout=95, allow_failure=True)
    logs = lab.kubectl("logs", f"job/{NAME}", allow_failure=True)
    if completion.returncode or logs.returncode:
        lab.block("The isolated metadata mode fixture did not complete")
    observed = json.loads(logs.stdout)
    lab.check("red", "An HTTP marker accepts the fixed intent header without a fixture-issued session",
              observed["missing_intent"] == 400 and observed["fixed_intent_accepted"],
              {key: observed[key] for key in ("missing_intent", "fixed_intent_accepted")})
    lab.check("green", "The separate session-required route refuses missing or incorrect fixture sessions",
              observed["missing_session"] == observed["incorrect_session"] == 401,
              {key: observed[key] for key in ("missing_session", "incorrect_session")})
    lab.check("positive", "An issued fixture session retains authorized access to the same public marker",
              observed["issued_session_accepted"], {"issued_session_accepted": observed["issued_session_accepted"]})
    lab.check("green", "The same issued marker session stops granting access after its fixture lifetime",
              observed["expired_session"] == 401, {"expired_session": observed["expired_session"]})
    tls_denied = observed["anonymous_tls"] == observed["untrusted_tls"] == "tls-handshake-refused"
    lab.check("green", "Native TLS rejects no certificate and the same claimed subject signed by another CA",
              tls_denied, {"anonymous_and_untrusted_peer_denied": tls_denied})
    tls_allowed = observed["trusted_tls"] == "peer-verified" and observed["trusted_result"] == {
        "marker": "owned-public-marker", "verified_subject": "fixture-approved-client",
    }
    lab.check("positive", "The approved TLS client is verified and can receive the same harmless marker",
              tls_allowed, {"verified_client_received_marker": tls_allowed})
    (lab.evidence / "metadata-access-mode-observations.json").write_text(json.dumps(observed, indent=2) + "\n")
