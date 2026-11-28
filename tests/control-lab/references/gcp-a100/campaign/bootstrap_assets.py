"""Stage and verify the exact public artifacts used by the disposable A100 guest."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import NamedTemporaryFile, TemporaryDirectory

K3S_RELEASE = "https://github.com/k3s-io/k3s/releases/download/v1.36.6%2Bk3s1"
ASSETS = {
    "k3s": (
        f"{K3S_RELEASE}/k3s",
        "66ceb8e67edfa547195135d74783bfadc2ecc04a91059e90ae5f70a3dbc98c15",
        85000000,
    ),
    "install-k3s.sh": (
        "https://raw.githubusercontent.com/k3s-io/k3s/v1.36.6%2Bk3s1/install.sh",
        "46177d4c99440b4c0311b67233823a8e8a2fc09693f6c89af1a7161e152fbfad",
        65536,
    ),
    "nvidia-device-plugin.yaml": (
        "https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.20.2/deployments/static/nvidia-device-plugin.yml",
        "f59a63d1936eef7005e9982d6cf3539a2005680dd8a782b807b7a6ab3b5d0fff",
        8192,
    ),
}


def verify_one(path, name):
    _, expected, limit = ASSETS[name]
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError(f"Unexpected type or size for bootstrap artifact {name}")
    digest = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected:
        raise ValueError(f"Bootstrap artifact differs from the pinned SHA-256: {name}")
    return actual


def verify_assets(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Expected the staged bootstrap asset directory")
    if {item.name for item in directory.iterdir()} != set(ASSETS):
        raise ValueError("The staged bootstrap asset inventory differs from the pin")
    return {name: verify_one(directory / name, name) for name in ASSETS}


def stage_assets(destination, source=None):
    if destination.exists() or destination.is_symlink():
        raise ValueError("Bootstrap staging destination must be new")
    if source is not None and (source.is_symlink() or not source.is_dir()):
        raise ValueError("Offline bootstrap source must be a directory")
    with TemporaryDirectory(prefix="bootstrap-assets-", dir=destination.parent) as temporary:
        pending = Path(temporary)
        for name, (url, _, limit) in ASSETS.items():
            target = pending / name
            if source is None:
                subprocess.run([
                    "curl", "--proto", "=https", "--proto-redir", "=https", "--fail", "--silent",
                    "--show-error", "--location", "--connect-timeout", "8", "--max-time", "120",
                    "--max-filesize", str(limit), "--output", str(target), url,
                ], check=True, timeout=125)
            else:
                verify_one(source / name, name)
                shutil.copyfile(source / name, target)
            verify_one(target, name)
        destination.mkdir(mode=0o700)
        try:
            for name in ASSETS:
                os.link(pending / name, destination / name)
        except OSError:
            shutil.rmtree(destination)
            raise


def prepare_k3s(directory, target, *, active):
    verify_assets(directory)

    def verify_installed():
        verify_one(target, "k3s")
        if not target.stat().st_mode & 0o111:
            raise ValueError("The existing K3s binary is not executable")
        return "reused"

    if target.exists() or target.is_symlink():
        return verify_installed()
    if active:
        raise ValueError("K3s reports active with no installed binary at the staged path")
    with NamedTemporaryFile(prefix=".saf-k3s-", dir=target.parent) as pending:
        with (directory / "k3s").open("rb") as original:
            shutil.copyfileobj(original, pending)
        pending.flush()
        os.fchmod(pending.fileno(), 0o755)
        os.fsync(pending.fileno())
        verify_one(Path(pending.name), "k3s")
        try:
            os.link(pending.name, target)
        except FileExistsError:
            return verify_installed()
    return "installed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify", "prepare-k3s"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--active", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "verify":
            print(json.dumps(verify_assets(args.directory), sort_keys=True))
        else:
            print(prepare_k3s(args.directory, Path("/usr/local/bin/k3s"), active=args.active))
    except (ValueError, OSError) as error:
        parser.exit(1, f"Bootstrap assets: {error}\n")


if __name__ == "__main__":
    main()
