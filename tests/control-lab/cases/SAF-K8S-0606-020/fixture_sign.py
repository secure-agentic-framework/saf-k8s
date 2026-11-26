"""Make and verify a second valid fixture signature for the trust-policy negative case."""
from pathlib import Path
import shutil
import subprocess
import sys


def main(argv):
    if len(argv) != 5:
        raise SystemExit("usage: fixture_sign.py private manifest signature public")
    private, manifest, signature, public = map(Path, argv[1:])
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("openssl is required for the fixture signer")
    subprocess.run([openssl, "dgst", "-sha256", "-sign", str(private), "-out",
                    str(signature), str(manifest)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    check = subprocess.run([openssl, "dgst", "-sha256", "-verify", str(public), "-signature",
                            str(signature), str(manifest)], capture_output=True, text=True, timeout=10)
    signature.chmod(0o600)
    if check.returncode != 0:
        raise SystemExit("alternate fixture signature did not verify")


if __name__ == "__main__":
    main(sys.argv)
