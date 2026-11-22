"""Compare a leaking single-stage baseline with a minimized multi-stage image."""
import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


HERE = Path(__file__).resolve().parent
PAYLOAD_PATH = "app/payload.txt"
MARKER_PATH = "build-stage-marker.txt"
SCOPE = (
    "Build two case-owned Linux scratch images with a local Docker engine and no network. "
    "The single-stage baseline carries the synthetic build-only marker into its final image. "
    "The multi-stage build copies only the intended static fixture output into its runtime "
    "stage. Inspect docker image save archives and apply their layers to compare the actual "
    "final filesystems, check the intermediate marker never appears in a final layer, and "
    "run the final image without networking to verify its executable can read the allowed "
    "payload. This establishes final-image "
    "minimization for this synthetic fixture only; production package inventories, build "
    "systems, promotion gates, and deployed image scope require separate evidence."
)


def filesystem_from_saved_image(lab, image, archive_path):
    """Return non-directory paths from the merged Docker-save filesystem."""
    lab.command("docker", "image", "save", "--output", str(archive_path), image, timeout=60)
    files = {}
    all_paths = set()

    def safe_path(name):
        normalized = name.removeprefix("./").rstrip("/")
        parts = Path(normalized).parts
        if not normalized or normalized.startswith("/") or ".." in parts:
            lab.block("Saved image contains an unsafe archive path")
        return normalized

    with tarfile.open(archive_path, mode="r:") as bundle:
        manifests = json.load(bundle.extractfile("manifest.json"))
        if len(manifests) != 1 or not manifests[0].get("Layers"):
            lab.block("Expected one saved image with at least one filesystem layer")
        for layer_name in manifests[0]["Layers"]:
            stream = bundle.extractfile(layer_name)
            if stream is None:
                lab.block("Saved image layer is missing")
            with tarfile.open(fileobj=stream, mode="r:*") as layer:
                for entry in layer:
                    path = safe_path(entry.name)
                    all_paths.add(path)
                    parent, _, basename = path.rpartition("/")
                    if basename == ".wh..wh..opq":
                        prefix = parent + "/" if parent else ""
                        files = {key: value for key, value in files.items()
                                 if not key.startswith(prefix)}
                    elif basename.startswith(".wh."):
                        removed = (parent + "/" if parent else "") + basename[4:]
                        files = {key: value for key, value in files.items()
                                 if key != removed and not key.startswith(removed + "/")}
                    elif entry.isdir():
                        continue
                    elif entry.isfile():
                        content = layer.extractfile(entry)
                        if content is None:
                            lab.block("Saved image regular file has no content")
                        files[path] = ("regular", content.read())
                    else:
                        files[path] = ("non-regular", b"")
    return files, all_paths


def run(lab):
    baseline = f"saf-0601-017-{lab.cluster}:baseline"
    build_stage = f"saf-0601-017-{lab.cluster}:build-stage"
    candidate = f"saf-0601-017-{lab.cluster}:multistage"
    expected_payload = (HERE / "payload.txt").read_bytes()
    expected_marker = (HERE / "build-stage-marker.txt").read_bytes()
    tags = (baseline, build_stage, candidate)

    with tempfile.TemporaryDirectory(prefix="saf-0601-017-") as temporary:
        try:
            temp = Path(temporary)
            archive = temp / "image.tar"
            context = temp / "context"
            context.mkdir()
            for filename in ("Dockerfile.baseline", "Dockerfile.multistage",
                             "build-stage-marker.txt", "payload.txt"):
                shutil.copyfile(HERE / filename, context / filename)
            node = f"{lab.cluster}-control-plane"
            architecture = lab.kubectl("get", f"node/{node}",
                                       "-o", "jsonpath={.status.nodeInfo.architecture}").stdout.strip()
            if architecture not in ("amd64", "arm64") or not shutil.which("go"):
                lab.block("Building the static fixture needs Go and a Linux amd64 or arm64 node")
            compile_probe = subprocess.run(
                ["go", "build", "-trimpath", "-o", str(context/"probe"), str(HERE/"probe.go")],
                env=dict(lab.env, CGO_ENABLED="0", GOOS="linux", GOARCH=architecture,
                         GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOFLAGS=""),
                capture_output=True, text=True, timeout=180,
            )
            if compile_probe.returncode:
                lab.block("Could not compile the case-owned static Go fixture")
            expected_probe = (context/"probe").read_bytes()
            platform = f"linux/{architecture}"
            lab.command("docker", "build", "--network", "none", "--pull=false", "--platform", platform,
                        "--file", str(context / "Dockerfile.baseline"), "--tag", baseline,
                        str(context), timeout=180)
            baseline_files, _ = filesystem_from_saved_image(lab, baseline, archive)
            baseline_ok = (
                baseline_files.get(PAYLOAD_PATH) == ("regular", expected_payload)
                and baseline_files.get(MARKER_PATH) == ("regular", expected_marker)
            )
            lab.check(
                "red", "single-stage baseline retains the synthetic build-only marker",
                baseline_ok,
                {"regular_paths": sorted(path for path, value in baseline_files.items()
                                          if value[0] == "regular"),
                 "marker_present": baseline_files.get(MARKER_PATH) == ("regular", expected_marker)},
            )

            lab.command("docker", "build", "--network", "none", "--pull=false", "--platform", platform,
                        "--file", str(context / "Dockerfile.multistage"), "--target", "build",
                        "--tag", build_stage, str(context), timeout=180)
            stage_files, _ = filesystem_from_saved_image(lab, build_stage, archive)
            stage_has_inputs = stage_files == {
                "out/payload.txt": ("regular", expected_payload),
                "out/probe": ("regular", expected_probe),
                "out/build-stage-marker.txt": ("regular", expected_marker),
            }
            lab.check(
                "positive", "built intermediate stage actually contains the synthetic marker",
                stage_has_inputs,
                {"paths": sorted(stage_files), "marker_present": stage_has_inputs},
            )

            lab.command("docker", "build", "--network", "none", "--pull=false", "--platform", platform,
                        "--file", str(context / "Dockerfile.multistage"), "--tag", candidate,
                        str(context), timeout=180)
            final_files, final_paths = filesystem_from_saved_image(lab, candidate, archive)
            exact_runtime_inventory = final_files == {
                PAYLOAD_PATH: ("regular", expected_payload),
                "app/probe": ("regular", expected_probe),
            }
            lab.check(
                "green", "multi-stage final image excludes the build marker and contains only runtime output",
                exact_runtime_inventory and all(not path.endswith(MARKER_PATH) for path in final_paths),
                {"paths": sorted(final_files),
                 "marker_absent_from_final_layers": all(not path.endswith(MARKER_PATH) for path in final_paths),
                 "all_entries_regular": all(kind == "regular" for kind, _ in final_files.values())},
            )

            output = lab.command("docker", "run", "--rm", "--network", "none",
                                 "--read-only", candidate, timeout=30).stdout.strip()
            verified = output == "payload-sha256=" + hashlib.sha256(expected_payload).hexdigest()
            lab.check("positive", "The runtime executable reads the intact permitted payload",
                      verified, {"executed_exact_payload": verified, "payload_bytes": len(expected_payload)})
        finally:
            for image in tags:
                lab.command("docker", "image", "rm", image, allow_failure=True)
