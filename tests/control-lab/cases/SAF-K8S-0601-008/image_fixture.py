"""Build inert image archives and a synthetic, reproducible OSV advisory database."""
from hashlib import sha256
import gzip
from io import BytesIO
import json
from pathlib import Path
import tarfile
import zipfile

PACKAGE = "saf-fixture-widget"
ADVISORY = "TEST-SAF-IMAGE-0001"
DISTRIBUTION = "application/vnd.oci.image.manifest.v1+json"
ADVISORY_RECORD = {
    "schema_version": "1.6.0", "id": ADVISORY, "modified": "2026-11-01T00:00:00Z",
    "summary": "Synthetic scanner fixture without executable code",
    "affected": [{"package": {"ecosystem": "PyPI", "name": PACKAGE},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.1"}]}]}],
    "database_specific": {"severity": "HIGH"},
}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return "sha256:" + sha256(value).hexdigest()


def tar(members):
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, contents in members.items():
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = 0o644, len(contents)
            archive.addfile(entry, BytesIO(contents))
    return output.getvalue()


def descriptor(media_type, contents):
    return {"mediaType": media_type, "digest": digest(contents), "size": len(contents)}


def image(version):
    metadata_dir = f"usr/local/lib/python3.12/site-packages/saf_fixture_widget-{version}.dist-info"
    layer = tar({
        metadata_dir + "/METADATA": f"Metadata-Version: 2.1\nName: {PACKAGE}\nVersion: {version}\n".encode(),
        metadata_dir + "/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        metadata_dir + "/RECORD": b"",
    })
    packed = gzip.compress(layer, mtime=0)
    config = encode({
        "architecture": "arm64", "os": "linux", "config": {},
        "history": [{"created_by": "Add inert local metadata"}],
        "rootfs": {"type": "layers", "diff_ids": [digest(layer)]},
    })
    manifest = encode({
        "schemaVersion": 2, "mediaType": DISTRIBUTION,
        "config": descriptor("application/vnd.oci.image.config.v1+json", config),
        "layers": [descriptor("application/vnd.oci.image.layer.v1.tar+gzip", packed)],
    })
    return {"config.json": config, "layer.tar.gz": packed, "manifest.json": manifest}


def docker_archive(contents):
    return tar({"config.json": contents["config.json"], "layer.tar.gz": contents["layer.tar.gz"],
                "manifest.json": encode([{"Config": "config.json", "Layers": ["layer.tar.gz"],
                                         "RepoTags": ["fixture.invalid/ci/image:local"]}])})


def database(path):
    path = Path(path) / "osv-scalibr" / "PyPI"
    path.mkdir(parents=True, exist_ok=True)
    info = zipfile.ZipInfo(ADVISORY + ".json")
    with zipfile.ZipFile(path / "all.zip", "w") as archive:
        archive.writestr(info, encode(ADVISORY_RECORD))
