"""Build and import the reviewed CPU collective image with verified wheels."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

HERE = Path(__file__).resolve().parent


def _matches(path, package):
    if not path.is_file() or path.stat().st_size != package["size"]:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest() == package["sha256"]


def _prepare_wheels(lab, lock, output):
    cache_dir = os.environ.get("SAF_GLOO_WHEEL_CACHE")
    cache = Path(cache_dir) if cache_dir else None
    if cache:
        cache.mkdir(parents=True, exist_ok=True)
    for package in lock.values():
        target = output / package["filename"]
        cached = cache / package["filename"] if cache else None
        if cached and _matches(cached, package):
            shutil.copyfile(cached, target)
        else:
            lab.command("curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https",
                        "--max-time", "150", "--max-filesize", str(package["size"]),
                        "--output", str(target), package["url"], timeout=160)
        if not _matches(target, package):
            lab.block("The pinned collective fixture wheel bytes did not match")
        if cached and not _matches(cached, package):
            with tempfile.NamedTemporaryFile(prefix="saf-gloo-", dir=cache, delete=False) as file:
                copy_path = Path(file.name)
            try:
                shutil.copyfile(target, copy_path)
                os.replace(copy_path, cached)
            finally:
                copy_path.unlink(missing_ok=True)


def build_and_import(lab):
    node_list = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)
    architectures = {node["status"]["nodeInfo"]["architecture"] for node in node_list["items"]}
    if len(architectures) != 1:
        lab.block("The collective fixture requires one shared Kind architecture")
    architecture = architectures.pop()
    lock_path = HERE / f"wheel-lock-{architecture}.json"
    if not lock_path.is_file():
        lab.block("The collective fixture does not have an approved wheel set for this architecture")
    lock = json.loads(lock_path.read_text())
    image = f"saf-k8s-fixture-gloo:{lab.cluster}"
    try:
        with tempfile.TemporaryDirectory(prefix="saf-gloo-build-") as directory:
            build = Path(directory)
            output = build / "wheels"
            output.mkdir()
            _prepare_wheels(lab, lock, output)
            shutil.copyfile(HERE / "Dockerfile.gloo", build / "Dockerfile")
            lab.command("docker", "build", "--network=none", "--platform", f"linux/{architecture}",
                        "-t", image, str(build), timeout=180)
            image_id = lab.command("docker", "image", "inspect", "--format={{.Id}}", image,
                                   timeout=20).stdout.strip()
            lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=180)
    finally:
        lab.command("docker", "image", "rm", image, allow_failure=True, timeout=25)
    provenance = {"architecture": architecture, "derived_image_id": image_id,
                  "wheel_sha256": {name: item["sha256"] for name, item in lock.items()}}
    return image, provenance
