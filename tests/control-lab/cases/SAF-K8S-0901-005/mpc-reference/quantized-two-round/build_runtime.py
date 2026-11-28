"""Build the quantized programs with the case's pinned MP-SPDZ v0.4.4 source."""

import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
UPSTREAM = HERE.parent
VERSION = "0.4.4"
ARCHIVE_SHA256 = "73d6473526101b4433999fc4f7521fdfdc53ddf018e5f64480518d6293f62760"
RELEASE = f"https://github.com/data61/MP-SPDZ/releases/download/v{VERSION}/mp-spdz-{VERSION}.tar.xz"
MACHINE = "malicious-rep-bin-party.x"
SOURCE_SHA256 = {
    "quantized_median.mpc": "294cf8b15bcaf18815fa0e3b368decdf12987904e2891d25ae3a38bd59960c50",
    "saf_quantized_median_calibration.mpc": "652186d11cfdcec533356578573491b81895462e545052f334239b7e87b9fd8f",
    "release_bits.py": "0acb3ac0252ba16c355b564983c380854be6b8376f867e8abd1b920e25b30599",
}
ARTIFACTS = {
    MACHINE: "47a025f64d2647bf64dbe483f1278d346123c1470f247ea38fedc32eab32bc82",
    "Programs/Bytecode/quantized_median-0.bc": "7638664c1edbbd41c1de2b97c06e58f3a460d0a620ab1c3a574467f0e1d93f7d",
    "Programs/Schedules/quantized_median.sch": "ea1c784edddc5ce83120f2626da560192f2e36f8687ef38bbf5c8b0e0ba7ea3d",
    "Programs/Bytecode/saf_quantized_median_calibration-0.bc": "a38563750b17fa0f9a6bf0944e6a4677bb8e2911c8685439516c3bba1b3b74f9",
    "Programs/Schedules/saf_quantized_median_calibration.sch": "8e78f589546b57b95b3def3875cbc04e9d83414c628748c36edf22f1c30e23a7",
}
PROGRAMS = ("quantized_median", "saf_quantized_median_calibration")
ASSEMBLY_SHA256 = "7948abb45fda40f5d98d046c8af57bddb618db0225bb9a8d5c1d83c92edf5dd6"


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def copy_compiled_artifacts(lab, source, package):
    source_dir = HERE / "circuit"
    observed_sources = {file.name for file in source_dir.iterdir() if file.is_file()}
    if observed_sources != set(SOURCE_SHA256):
        lab.block("The quantized circuit source inventory changed")
    for file in source_dir.iterdir():
        if file.is_file() and file.name in SOURCE_SHA256:
            if digest(file) != SOURCE_SHA256[file.name]:
                lab.block(f"Quantized circuit source changed: {file.name}")
            shutil.copyfile(file, source / "Programs" / "Source" / file.name)
    # The upstream archive is extracted into a new temporary directory for each
    # build. Remove target outputs as an additional guard against stale compiler
    # products before generating the pinned candidate artifacts.
    for name in PROGRAMS:
        for generated in (source / "Programs" / "Bytecode" / f"{name}-0.bc",
                          source / "Programs" / "Schedules" / f"{name}.sch",
                          source / f"{name}.asm-{name}-0"):
            if generated.exists():
                generated.unlink()
    env = {**lab.env, "PYTHONPATH": str(source / "Programs/Source")}
    for name in PROGRAMS:
        options = ["-a", "quantized_median.asm"] if name == "quantized_median" else []
        subprocess.run([sys.executable, "-B", "compile.py", "-B", "1", *options, name],
                       cwd=source, env=env, check=True, timeout=60, capture_output=True)
    shutil.copy2(source / "bin" / "Linux-adx" / MACHINE, source / MACHINE)
    for relative, sha in ARTIFACTS.items():
        binary = source / relative
        if digest(binary) != sha:
            lab.block(f"The compiled quantized artifact changed: {relative}")
        destination = package / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, destination)
    assembly = source / "quantized_median.asm-quantized_median-0"
    if digest(assembly) != ASSEMBLY_SHA256:
        lab.block("The quantized private circuit assembly differs from compile evidence")
    return assembly.read_text()


def build(lab, image):
    expected = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}
    host = lab.command("docker", "info", "--format", "{{.Architecture}}", timeout=15).stdout.strip()
    architecture = expected.get(host)
    if architecture is None:
        lab.block("The MP-SPDZ reference image supports Docker amd64 or arm64")
    with TemporaryDirectory(prefix="saf-quantized-mpc-") as scratch:
        scratch = Path(scratch)
        archive = scratch / f"mp-spdz-{VERSION}.tar.xz"
        lab.command("curl", "--fail", "--silent", "--show-error", "--location", "--max-time", "95",
                    RELEASE, "-o", str(archive), timeout=105)
        if digest(archive) != ARCHIVE_SHA256:
            lab.block("The official MP-SPDZ archive failed its pinned SHA-256 check")
        lab.command("tar", "-xf", str(archive), "-C", str(scratch), timeout=60)
        source = scratch / f"mp-spdz-{VERSION}"
        package = scratch / "runtime"
        package.mkdir()
        try:
            copy_compiled_artifacts(lab, source, package)
        except (OSError, subprocess.SubprocessError) as error:
            lab.block(f"The pinned MP-SPDZ compiler failed: {type(error).__name__}")
        shutil.copyfile(UPSTREAM / "Dockerfile", package / "Dockerfile")
        iid = scratch / "image-id"
        lab.command("docker", "build", "--provenance=false", "--platform", f"linux/{architecture}",
                    "--iidfile", str(iid), "-t", image, str(package), timeout=125)
        observed = lab.command("docker", "image", "inspect", "--format", "{{.Id}}",
                               image, timeout=15).stdout.strip()
        if iid.read_text().strip() != observed:
            lab.block("The local quantized image alias differs from its build result")
    lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=120)
