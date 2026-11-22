"""Generate one isolated test CA and short-lived, role-constrained identities."""
from pathlib import Path
import subprocess


def generate(lab, directory):
    def openssl(*args):
        outcome = subprocess.run(("openssl", *map(str, args)), capture_output=True, timeout=30)
        if outcome.returncode:
            lab.block("Could not generate the ephemeral fixture certificates")

    ca = directory / "ca.crt"
    issuer = directory / "ca.key"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", 1, "-subj", "/CN=SAF isolated route CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash", "-keyout", issuer, "-out", ca)
    leaves = {}
    for name, usage in (("primary", "serverAuth"), ("peer", "serverAuth"), ("router", "serverAuth,clientAuth"),
                        ("eligible-client", "clientAuth"), ("unassigned-client", "clientAuth")):
        key = directory / f"{name}.key"
        csr = directory / f"{name}.csr"
        cert = directory / f"{name}.crt"
        config = directory / f"{name}.ext"
        entries = f"DNS:{name}.saf-inference.test,URI:urn:saf:route:{name}"
        config.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                          "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
                          f"extendedKeyUsage={usage}\nsubjectAltName={entries}\n")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}", "-keyout", key, "-out", csr)
        openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", issuer, "-CAcreateserial",
                "-days", 1, "-sha256", "-extfile", config, "-out", cert)
        key.chmod(0o600)
        leaves[name] = {"ca.crt": ca, "tls.crt": cert, "tls.key": key}
    return leaves
