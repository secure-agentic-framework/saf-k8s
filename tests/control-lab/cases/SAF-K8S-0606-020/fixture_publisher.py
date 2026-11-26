"""Separate disposable fixture signer; it signs canonical Helm chart-tree evidence."""
from pathlib import Path
import shutil
import subprocess
import sys


def main(argv):
    if len(argv) != 4:
        raise SystemExit("usage: fixture_publisher.py private manifest signature")
    private, manifest, signature = map(Path, argv[1:])
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("openssl is required for the fixture signer")
    subprocess.run([openssl, "dgst", "-sha256", "-sign", str(private), "-out",
                    str(signature), str(manifest)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    manifest.chmod(0o600)
    signature.chmod(0o600)


if __name__ == "__main__":
    main(sys.argv)
