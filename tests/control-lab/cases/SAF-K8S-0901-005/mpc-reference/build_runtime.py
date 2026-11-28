"""Build the isolated runtime from the checksum-pinned upstream release."""

import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
VERSION = "0.4.4"
ARCHIVE_SHA256 = "73d6473526101b4433999fc4f7521fdfdc53ddf018e5f64480518d6293f62760"
RELEASE = f"https://github.com/data61/MP-SPDZ/releases/download/v{VERSION}/mp-spdz-{VERSION}.tar.xz"
MACHINE = "malicious-rep-bin-party.x"
ARTIFACTS = {
    MACHINE: "47a025f64d2647bf64dbe483f1278d346123c1470f247ea38fedc32eab32bc82",
    "Programs/Bytecode/saf_private_update-0.bc": "ff26113e3e599db3021a2493151167596c62c7e19f9c3f6d91722208849c454d",
    "Programs/Bytecode/saf_private_update_truth_table-0.bc": "93d8517c549c96db0bf551cf02270572ab5636cbf92b22b35003704475b9cb69",
    "Programs/Schedules/saf_private_update.sch": "cb1fb9b42bbc037dbfc32b100fbc4920129b6f4922a2384c25b3714eac53a402",
    "Programs/Schedules/saf_private_update_truth_table.sch": "832d771b01871e0e83e573da67a090d0300b910ebde81a270eeee5f8139cb5fa",
}
PROGRAMS = ("saf_private_update", "saf_private_update_truth_table")
ASSEMBLY_SHA256 = "20abb588c854437622c5d7530b855d35d6b848021f0fdc9cd723b5e8f1296414"



def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def copy_compiled_artifacts(lab, source, package):
    for file in (HERE / "circuit").iterdir():
        shutil.copyfile(file, source / "Programs" / "Source" / file.name)
    env = {**lab.env, "PYTHONPATH": str(source / "Programs/Source")}
    for name in PROGRAMS:
        options = ["-a", "saf-private-update"] if name == PROGRAMS[0] else []
        subprocess.run([sys.executable, "-B", "compile.py", "-B", "1", *options, name],
                       cwd=source, env=env, check=True, timeout=45, capture_output=True)
    shutil.copy2(source / "bin" / "Linux-adx" / MACHINE, source / MACHINE)
    for relative, sha in ARTIFACTS.items():
        binary = source / relative
        if digest(binary) != sha:
            lab.block(f"The compiled reference artifact changed: {relative}")
        destination = package / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, destination)
    assembly = source / "saf-private-update-saf_private_update-0"
    if digest(assembly) != ASSEMBLY_SHA256:
        lab.block("The compiler listing differs from the reviewed private circuit")
    return assembly.read_text()


def build(lab, image):
    expected = {"aarch64": "arm64", "arm64": "arm64",
                "x86_64": "amd64", "amd64": "amd64"}
    host = lab.command("docker", "info", "--format", "{{.Architecture}}", timeout=15).stdout.strip()
    architecture = expected.get(host)
    if architecture is None:
        lab.block("The reference image supports Docker amd64 or arm64")
    with TemporaryDirectory(prefix="saf-private-aggregation-") as scratch:
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
            assembly = copy_compiled_artifacts(lab, source, package)
        except (OSError, subprocess.SubprocessError) as error:
            lab.block(f"The pinned MP-SPDZ compiler failed: {type(error).__name__}")
        shutil.copyfile(HERE / "Dockerfile", package / "Dockerfile")
        iid = scratch / "image-id"
        lab.command("docker", "build", "--provenance=false", "--platform", f"linux/{architecture}",
                    "--iidfile", str(iid), "-t", image, str(package), timeout=125)
        observed = lab.command("docker", "image", "inspect", "--format", "{{.Id}}",
                               image, timeout=15).stdout.strip()
        if iid.read_text().strip() != observed:
            lab.block("The local image alias differs from the reviewed build result")
    lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=120)
    return assembly
