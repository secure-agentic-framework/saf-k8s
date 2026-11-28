"""Assemble the reviewed A100 guest inputs ahead of an approved rental."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory

from bootstrap_assets import stage_assets

ROOT = Path(__file__).resolve().parent
PUBLIC_SHA = "88da468f56b5f88821614207a3c1f16866cbac07"
PUBLIC_CASES = "tests/control-lab/cases"
VISIBILITY_REVISION = "aca448b3aa788b9a6331248217675f6111c3799e"
VISIBILITY = f"{PUBLIC_CASES}/SAF-K8S-0805-001"
MIG_REVISION = "ce8204c8b386a0862ad04b914886b94dd655d952"
MIG = f"{PUBLIC_CASES}/SAF-K8S-0805-004"
HOLD_REVISION = "ab4734d0e726aa6c94c2f3ca78dfbcfa6b285424"
HOLD = f"{PUBLIC_CASES}/SAF-K8S-0805-003"
TELEMETRY = f"{PUBLIC_CASES}/SAF-K8S-1002-003/a100-reference"
SIGNED = f"{PUBLIC_CASES}/SAF-K8S-0802-008/a100-reference"
FILES = {
    **{f"{TELEMETRY}/fixtures/{name}": f"fixtures/{name}" for name in (
        "a100-vector-witness.yaml", "dcgm-exporter-rendered.yaml", "prometheus.yaml", "framebuffer-witness.c")},
    **{f"{TELEMETRY}/podresources-list/{name}": f"source/podresources-list/{name}"
       for name in ("go.mod", "go.sum", "main.go")},
    f"{TELEMETRY}/support-review.json": "support-review.json",
    f"{TELEMETRY}/deploy-and-baseline.sh": "deploy-and-baseline.sh",
    f"{SIGNED}/verify-loaded-signed-modules.py": "verify-loaded-signed-modules.py",
    f"{SIGNED}/bind-shielded-boot.py": "bind-shielded-boot.py",
}
CANDIDATES = (
    "a100_readiness.py", "live_catch_hold.py", "prove-signed-admission.py", "prove-mig.py",
    "request-mig-mode.sh", "configure-mig-slices.sh", "a100_visibility.py", "mig_inventory.py", "mig_setup.py",
)
ALLOCATOR_SHA = "08e6067ff31f82f6ef3285e752a6445fae9abd572f1db14474231fe6fd406bfd"
HELPER_SHA = "ca6c0bad386183b82ec17d5b3b8f5a2344804bc6a5ac2f29f27fe0a6c19d4619"


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def verify_pin(path, expected):
    actual = digest(path)
    if actual != expected:
        raise SystemExit(f"{path.name} differs from the reviewed build: {actual}")
    path.chmod(0o700)


def assemble(args):
    if not args.output.is_absolute() or args.output.exists() or args.output.is_symlink():
        raise SystemExit("Output must be a new absolute directory")
    public = ["git", "-C", str(args.framework)]
    env = {**os.environ, "GOTOOLCHAIN": "local", "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0",
           "GOFLAGS": "", "GOWORK": "off"}
    if subprocess.check_output([args.go, "version"], env=env, text=True).split()[2] != "go1.26.8":
        raise SystemExit("Use the reviewed Go 1.26.8 toolchain")
    if subprocess.check_output([args.zig, "version"], text=True).strip() != "0.14.0":
        raise SystemExit("Use the reviewed Zig 0.14.0 toolchain")
    with TemporaryDirectory(prefix="a100-bundle-", dir=args.output.parent) as tmp:
        workspace = Path(tmp)
        bundle = workspace / "guest"
        bundle.mkdir(mode=0o700)
        for src, dst in FILES.items():
            target = bundle / dst
            target.parent.mkdir(exist_ok=True, parents=True)
            target.write_bytes(subprocess.check_output([*public, "show", f"{PUBLIC_SHA}:{src}"], timeout=20))
        for name in ("visibility_failure.py", "route_receiver.py", "visibility_transition.py"):
            (bundle / name).write_bytes(subprocess.check_output(
                [*public, "show", f"{VISIBILITY_REVISION}:{VISIBILITY}/{name}"], timeout=20))
        (bundle / "mig_admission.py").write_bytes(subprocess.check_output(
            [*public, "show", f"{MIG_REVISION}:{MIG}/mig_admission.py"], timeout=20))
        (bundle / "a100_admission.py").write_bytes(subprocess.check_output(
            [*public, "show", f"{HOLD_REVISION}:{HOLD}/a100_admission.py"], timeout=20))
        for name in CANDIDATES:
            shutil.copyfile(ROOT.parent / "candidate" / name, bundle / name)
        for name in ("run-case.py", "bootstrap.sh", "bootstrap_assets.py"):
            shutil.copyfile(ROOT / name, bundle / name)
        stage_assets(bundle / "bootstrap-assets", args.bootstrap_assets)
        baseline = bundle / "deploy-and-baseline.sh"
        baseline_source = baseline.read_text()
        if baseline_source.count('evidence="$here/evidence"') != 1:
            raise SystemExit("Unexpected checked-in telemetry baseline arguments")
        baseline.write_text(baseline_source.replace('evidence="$here/evidence"', 'evidence="${1:?private evidence directory required}"'))
        capture = bundle / "capture"
        capture.mkdir()
        helper = capture / "podresources-list-linux-amd64"
        subprocess.run([args.go, "build", "-mod=readonly", "-trimpath", "-o", str(helper), "."],
                       cwd=bundle / "source" / "podresources-list", env=env, timeout=240, check=True)
        verify_pin(helper, HELPER_SHA)
        allocator = bundle / "fixtures" / "framebuffer-witness-linux-amd64"
        zig_env = {**os.environ, "ZIG_GLOBAL_CACHE_DIR": str(workspace / "zig-global"),
                   "ZIG_LOCAL_CACHE_DIR": str(workspace / "zig-local")}
        subprocess.run([args.zig, "cc", "-target", "x86_64-linux-gnu.2.17", "-O2", "-g0", "-s",
                        "-Wl,--build-id=none", "-Wall", "-Wextra", "-Werror",
                        str(bundle / "fixtures" / "framebuffer-witness.c"), "-o", str(allocator), "-ldl"],
                       env=zig_env, timeout=180, check=True)
        verify_pin(allocator, ALLOCATOR_SHA)

        artifacts = {v.relative_to(bundle).as_posix(): digest(v) for v in sorted(bundle.rglob("*")) if v.is_file()}
        manifest = bundle / "manifest.json"
        manifest.write_text(json.dumps({"schema": "saf-a100-hardware-bundle-v1",
                                        "framework_revision": PUBLIC_SHA,
                                        "visibility_framework_revision": VISIBILITY_REVISION,
                                        "mig_framework_revision": MIG_REVISION,
                                        "hold_framework_revision": HOLD_REVISION, "files": artifacts},
                                       indent=2, sort_keys=True) + "\n")
        manifest_sha = digest(manifest)
        if args.output.exists() or args.output.is_symlink():
            raise SystemExit("Output appeared while assembling")
        bundle.rename(args.output)
    print(json.dumps({"output": str(args.output), "manifest_sha256": manifest_sha,
                      "files": len(artifacts)}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--framework", type=Path, required=True, help="checkout containing the pinned public commit")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bootstrap-assets", type=Path,
                        help="reuse the three exact release inputs from an already downloaded directory")
    parser.add_argument("--go", default="go")
    parser.add_argument("--zig", default="zig")
    assemble(parser.parse_args())


if __name__ == "__main__":
    os.umask(0o077)
    main()
