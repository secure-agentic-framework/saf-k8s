"""Read the loaded Ubuntu modules and their installed detached-signature provenance."""

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys

MODULES = {"nvidia": "nvidia.ko", "nvidia_uvm": "nvidia-uvm.ko"}
SIGNER = "Canonical Ltd. Kernel Module Signing"


def read_cmd(*args):
    return subprocess.check_output(args, text=True, timeout=12).strip()


def checksum(path):
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_one(name, filename, module_root, signatures_package):
    module_path = Path(read_cmd("modinfo", "-F", "filename", name))
    assert module_path == module_root / filename and module_path.is_file()
    signature = module_root / "bits" / f"{filename}.sig"
    ownership = read_cmd("dpkg-query", "-S", str(signature))
    assert ownership.split(": ", 1)[0] == signatures_package
    signature_bytes = signature.read_bytes()
    assert signature_bytes and signature_bytes.endswith(b"~Module signature appended~\n")
    with module_path.open("rb") as stream:
        stream.seek(-len(signature_bytes), os.SEEK_END)
        assert stream.read() == signature_bytes, "Installed module signature differs from the distribution signature artifact"
    signer = read_cmd("modinfo", "-F", "signer", name)
    key_id = read_cmd("modinfo", "-F", "sig_key", name)
    version = read_cmd("modinfo", "-F", "version", name)
    live = Path("/sys/module") / name
    assert signer == SIGNER and (live / "version").read_text().strip() == version
    assert re.fullmatch(r"(?:[A-F0-9]{2}:)*[A-F0-9]{2}", key_id)
    module_taint = (live / "taint").read_text().strip()
    assert "E" not in module_taint, "Loaded module is marked unsigned"
    return {"module": name, "driver_version": version, "signer": signer, "signing_key_id": key_id,
            "module_sha256": checksum(module_path), "distribution_signature_sha256": sha256(signature_bytes).hexdigest(),
            "detached_signature_exact_match": True, "loaded_version_matches": True, "unsigned_module_taint_present": False}


def main(out):
    if os.geteuid() != 0 or not re.fullmatch(r"saf-a100-[0-9]{10}", socket.gethostname()):
        raise SystemExit("Run on the disposable A100 fixture guest")
    os.umask(0o077)
    assert not out.exists()
    kernel = read_cmd("uname", "-r")
    module_root = Path("/lib/modules") / kernel / "kernel/nvidia-580srv"
    package = f"linux-signatures-nvidia-{kernel}"
    efi = Path("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
    assert efi.read_bytes()[-1] == 1
    assert "SecureBoot enabled" in read_cmd("mokutil", "--sb-state")
    lockdown = Path("/sys/kernel/security/lockdown").read_text()
    assert "[integrity]" in lockdown or "[confidentiality]" in lockdown
    keys = read_cmd("keyctl", "list", "%:.builtin_trusted_keys")
    assert SIGNER + ":" in keys
    gpu = read_cmd("nvidia-smi", "--query-gpu=name,driver_version", "--format=csv,noheader")
    assert "A100" in gpu and "\n" not in gpu
    modules = [check_one(name, filename, module_root, package) for name, filename in MODULES.items()]
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    doc = {"schema": "saf-a100-loaded-signed-modules-v1", "captured_at_utc": datetime.now(timezone.utc).isoformat(),
           "boot_ref_sha256": sha256(boot_id.encode()).hexdigest(), "kernel": kernel, "gpu_and_driver": gpu,
           "secure_boot_efi_variable": True, "mokutil_secure_boot": True, "kernel_lockdown": lockdown.strip(),
           "canonical_signer_label_in_builtin_trust": True, "modules": modules,
           "distributor_package": read_cmd("dpkg-query", "-W", package).split(),
           "provider_attestation": "Reviewed separately through the bound provider measured-boot events."}
    with out.open("x") as stream:
        json.dump(doc, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({"status": "passed", "loaded_signed_modules": len(modules), "kernel": kernel}))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
