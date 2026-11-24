"""Generate deterministic OCI layout archives containing one synthetic fixture file."""
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import sys
import tarfile

OCI = "application/vnd.oci.image."


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def descriptor(media_type, content):
    return {"mediaType": media_type, "digest": "sha256:" + sha256(content).hexdigest(), "size": len(content)}


def tar_payload(files):
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = 0o644
            archive.addfile(entry, BytesIO(data))
    return output.getvalue()


def image(payload, arch):
    layer = tar_payload({"pipeline/model-summary.json": payload})
    layer_desc = descriptor(OCI + "layer.v1.tar", layer)
    config = encode({"architecture": arch, "os": "linux", "config": {},
                     "rootfs": {"type": "layers", "diff_ids": [layer_desc["digest"]]}})
    config_desc = descriptor(OCI + "config.v1+json", config)
    manifest = encode({"schemaVersion": 2, "mediaType": OCI + "manifest.v1+json",
                       "config": config_desc, "layers": [layer_desc]})
    manifest_desc = descriptor(OCI + "manifest.v1+json", manifest)
    index = encode({"schemaVersion": 2, "mediaType": OCI + "index.v1+json",
                    "manifests": [{**manifest_desc, "platform": {"os": "linux", "architecture": arch}}]})
    sources = {"oci-layout": encode({"imageLayoutVersion": "1.0.0"}), "index.json": index}
    for item, blob in ((layer_desc, layer), (config_desc, config), (manifest_desc, manifest)):
        sources["blobs/sha256/" + item["digest"].split(":", 1)[1]] = blob
    return tar_payload(sources)


def run(output, arch):
    marker = "_".join(("training", "sample", "synthetic", "only"))
    root = Path(output)
    root.mkdir(parents=True, exist_ok=True)
    for name, value in (("red", marker), ("green", "ordinary-clean-sample")):
        payload = encode({"kind": "public-fixture", "sample": value}) + b"\n"
        (root / f"{name}.json").write_bytes(payload)
        (root / f"{name}.oci.tar").write_bytes(image(payload, arch))


if __name__ == "__main__":
    run(sys.argv[1], sys.argv[2])
