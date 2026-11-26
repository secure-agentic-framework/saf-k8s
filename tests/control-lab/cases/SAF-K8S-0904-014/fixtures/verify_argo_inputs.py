"""Static verifier for staged Argo source, OCI index, and render pins."""
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent


def git_blob_sha1(data):
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def main():
    pins = json.loads((HERE / "argo-pins.json").read_text())
    sources = json.loads((HERE / "argo-source-pins.json").read_text())
    for relpath, expected in sources["files"].items():
        path = HERE / "argo-v3.7.6" / relpath
        actual = git_blob_sha1(path.read_bytes())
        if actual != expected:
            raise SystemExit(f"upstream source blob mismatch: {relpath}")

    for name, index_file, index_digest, platform_field in (
        ("controller", "argo-oci-workflow-controller-v3.7.6.json",
         pins["controller_index_digest"], "controller"),
        ("executor", "argo-oci-argoexec-v3.7.6.json",
         pins["executor_index_digest"], "executor"),
    ):
        raw = (HERE / index_file).read_bytes()
        raw_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if raw_digest != index_digest:
            raise SystemExit(f"OCI index digest mismatch: {name}")
        index = json.loads(raw)
        expected = {
            ("linux", "amd64"): pins[f"{platform_field}_linux_amd64_digest"],
            ("linux", "arm64"): pins[f"{platform_field}_linux_arm64_digest"],
        }
        found = {}
        for descriptor in index.get("manifests", []):
            platform = descriptor.get("platform", {})
            key = (platform.get("os"), platform.get("architecture"))
            if key in expected:
                found[key] = descriptor.get("digest")
        if found != expected:
            raise SystemExit(f"OCI platform descriptor mismatch: {name}")

    manifest = HERE / pins["controller_only_manifest_path"]
    if hashlib.sha256(manifest.read_bytes()).hexdigest() != pins["controller_only_manifest_sha256"]:
        raise SystemExit("controller-only rendered manifest hash mismatch")
    text = manifest.read_text()
    required = (
        f"workflow-controller@{pins['controller_index_digest']}",
        f"argoexec@{pins['executor_index_digest']}",
        "--namespaced",
    )
    if any(item not in text for item in required) or "argo-server" in text or ":latest" in text:
        raise SystemExit("controller-only render scope or immutable images mismatch")
    print("Argo source, OCI index/platform, and controller-only render pins: verified")


if __name__ == "__main__":
    main()
