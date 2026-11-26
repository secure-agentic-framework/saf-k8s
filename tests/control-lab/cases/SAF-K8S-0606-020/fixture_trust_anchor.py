"""Create fixture publisher keys before any release producer is invoked."""
from pathlib import Path
import shutil
import subprocess
import sys


def keypair(openssl, private, public):
    private, public = Path(private), Path(public)
    subprocess.run([openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(private)], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=10)
    private.chmod(0o600)
    subprocess.run([openssl, "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    public.chmod(0o600)


def main(argv):
    if len(argv) != 5:
        raise SystemExit("usage: fixture_trust_anchor.py approved-private approved-public other-private other-public")
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("openssl is required for the fixture")
    keypair(openssl, argv[1], argv[2])
    keypair(openssl, argv[3], argv[4])


if __name__ == "__main__":
    main(sys.argv)
