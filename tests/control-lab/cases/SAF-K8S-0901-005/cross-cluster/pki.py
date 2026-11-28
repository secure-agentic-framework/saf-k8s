"""Create short-lived, role-constrained TLS identities for the fixture."""

from hashlib import sha256
from pathlib import Path
import subprocess


def generate(lab, directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)

    def openssl(*args):
        outcome = subprocess.run(("openssl", *map(str, args)), capture_output=True, timeout=30)
        if outcome.returncode:
            lab.block("Could not generate the ephemeral cross-cluster TLS identities")
        return outcome.stdout

    ca = directory / "ca.crt"
    issuer = directory / "ca.key"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", 1,
            "-subj", "/CN=SAF federated fixture CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
            "-keyout", issuer, "-out", ca)
    issuer.chmod(0o600)
    ca.chmod(0o600)

    roles = (("server", "flower-fleet.saf-fixture.test", "serverAuth"),
             ("participant-a", "participant-a.saf-fixture.test", "clientAuth"),
             ("participant-b", "participant-b.saf-fixture.test", "clientAuth"),
             ("participant-c", "participant-c.saf-fixture.test", "clientAuth"),
             ("unassigned", "unassigned.saf-fixture.test", "clientAuth"))
    credentials = {}
    allowlist = {}
    for name, dns_name, usage in roles:
        key = directory / f"{name}.key"
        csr = directory / f"{name}.csr"
        cert = directory / f"{name}.crt"
        extensions = directory / f"{name}.ext"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid:always\n"
            f"extendedKeyUsage={usage}\n"
            f"subjectAltName=DNS:{dns_name}\n"
        )
        extensions.chmod(0o600)
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}",
                "-keyout", key, "-out", csr)
        openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", issuer,
                "-CAcreateserial", "-days", 1, "-sha256", "-extfile", extensions, "-out", cert)
        key.chmod(0o600)
        cert.chmod(0o600)
        credentials[name] = {"ca.crt": ca, "tls.crt": cert, "tls.key": key}
        if name.startswith("participant-"):
            der = openssl("x509", "-in", cert, "-outform", "DER")
            allowlist[sha256(der).hexdigest()] = name

    return credentials, allowlist
