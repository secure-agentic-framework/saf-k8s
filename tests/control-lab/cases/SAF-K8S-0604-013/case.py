"""Test an isolated BuildKit RUN step, a pre-resolved lock, and the exact deployed result."""
from contextlib import contextmanager
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import re
import shutil
import time

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
INPUTS = HERE / "inputs"
BUILDKIT = ("docker.io/moby/buildkit:v0.28.0@sha256:"
            "37539dd4d60fc70968d164d3850d903a2c56f6402214a1953fbf9fcb81ada731")
SCOPE = (
    "A pinned BuildKit daemon and offline RUN step assemble pre-resolved fixture bytes. "
    "The connected comparison reads only a marker on an isolated owned Docker network. "
    "The isolated step denies that same path, checks a committed digest lock, rejects "
    "altered and missing inputs, and supplies an exact OCI image run by Kind. "
    "Production builder ingress, cache and source policy and reproducibility need separate evidence."
)


def runtime_tools():
    file = HERE.parent / "SAF-K8S-0604-010" / "case.py"
    spec = importlib.util.spec_from_file_location("offline_runtime_fixture", file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextmanager
def isolated_builder(registry, work):
    docker = registry.docker
    base = registry.lab.cluster + "-offline"
    network, marker, builder = base + "-net", base + "-marker", base + "-builder"
    docker("network", "create", "--internal", network)
    try:
        docker(
            "run", "--detach", "--name", marker, "--network", network, BUSYBOX_IMAGE,
            "sh", "-c", "mkdir /public && printf 'known-owned-marker\\n' > /public/marker "
            "&& exec httpd -f -p 8080 -h /public",
        )
        ip = docker("inspect", marker, "--format", f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}').stdout.strip()
        if not ip:
            registry.lab.block("The owned marker did not receive a private Docker network address")
        docker(
            "run", "--detach", "--name", builder, "--network", network, "--privileged",
            "--volume", f"{work}:/io", BUILDKIT, "--addr", "unix:///run/buildkit/buildkitd.sock",
            "--oci-worker-net=host", timeout=135,
        )
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if docker("exec", builder, "buildctl", "debug", "workers", allow_failure=True).returncode == 0:
                break
            time.sleep(0.5)
        else:
            registry.lab.block("The isolated fixture builder did not start")
        yield builder, f"http://{ip}:8080/marker"
    finally:
        for name in (builder, marker):
            result = docker("rm", "-fv", name, allow_failure=True)
            if result.returncode and "No such container" not in result.stderr:
                registry.lab.block("An owned fixture container could not be removed")
        docker("network", "rm", network)


def stage_inputs(registry, work):
    docker = registry.docker
    name = registry.lab.cluster + "-offline-base"
    docker("pull", BUSYBOX_IMAGE, timeout=150)
    inspected = json.loads(docker("image", "inspect", BUSYBOX_IMAGE).stdout)[0]
    if not any(row.endswith(BUSYBOX_IMAGE.split("@")[1]) for row in inspected["RepoDigests"]):
        registry.lab.block("The pre-resolved BusyBox input was not the pinned source image")
    try:
        docker("create", "--network", "none", "--name", name, BUSYBOX_IMAGE)
        docker("export", "-o", str(work / "busybox-rootfs.tar"), name, timeout=90)
    finally:
        docker("rm", "-v", name, allow_failure=True)
    rootfs_digest = sha256((work / "busybox-rootfs.tar").read_bytes()).hexdigest()
    for label in ("connected", "tampered", "missing", "approved"):
        root = work / label
        (root / "inputs").mkdir(parents=True)
        shutil.copy2(work / "busybox-rootfs.tar", root)
        profile = "connected" if label == "connected" else "locked"
        shutil.copyfile(INPUTS / f"{profile}.Dockerfile", root / "Dockerfile")
        shutil.copyfile(INPUTS / "dependencies.sha256", root / "inputs" / "dependencies.sha256")
        if label != "missing":
            shutil.copyfile(INPUTS / "package.txt", root / "inputs" / "package.txt")
        if label == "tampered":
            (root / "inputs" / "package.txt").write_text("different harmless dependency bytes\n")
    return rootfs_digest


def build(registry, builder, marker, profile):
    archive_name = f"{profile}.tar"
    args = ["exec", builder, "buildctl", "build", "--no-cache", "--progress=plain",
            "--frontend", "dockerfile.v0", "--local", f"context=/io/{profile}",
            "--local", f"dockerfile=/io/{profile}", "--opt", f"build-arg:MARKER_URL={marker}"]
    if profile == "approved":
        args.extend(["--output", f"type=docker,name={registry.lab.cluster}-verified:case,dest=/io/{archive_name}"])
    return registry.docker(*args, allow_failure=True, timeout=135)


def emitted(result, marker):
    return re.search(r"^#\d+\s+\d+(?:\.\d+)?\s+" + re.escape(marker) + r"\s*$",
                     result.stdout + result.stderr, re.M) is not None


def publish(registry, work, runtime):
    (work / "ca.crt").write_bytes(registry.registry_ca.read_bytes())
    target = f"{registry.registry}/fixture/locked-build:case"
    registry.docker(
        "run", "--rm", "--network", "kind", "--cap-drop=ALL", "--volume", f"{work}:/io",
        runtime.SKOPEO, "copy", "--format", "oci", "--dest-cert-dir", "/io", "--digestfile",
        "/io/manifest.digest", "docker-archive:/io/approved.tar", f"docker://{target}",
        timeout=130,
    )
    return target.rsplit(":", 1)[0] + "@" + (work / "manifest.digest").read_text().strip()


def observe(registry, ref, assertion):
    lab = registry.lab
    name = "saf-verified-offline-build"
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "containers": [{"name": "output", "image": ref, "imagePullPolicy": "Always"}],
    }})
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}", "--timeout=70s", timeout=80)
    pod = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    response = lab.kubectl("logs", name).stdout.encode()
    exact = pod["status"]["containerStatuses"][0]["imageID"].endswith(ref.split("@")[1])
    expected_hash = sha256(response).hexdigest() == assertion
    lab.check("positive", "Kind runs the exact approved OCI manifest and emits the locked bytes",
              exact and expected_hash, {"exact_runtime_manifest": exact, "locked_output_digest": expected_hash})


def run(lab):
    runtime = runtime_tools()
    with runtime.load_registry()(lab) as (registry, _, _):
        work = registry.work / "locked-inputs"
        work.mkdir(mode=0o755)
        rootfs_digest = stage_inputs(registry, work)
        with isolated_builder(registry, work) as (builder, marker):
            baseline = build(registry, builder, marker, "connected")
            reached = baseline.returncode == 0 and emitted(baseline, "OWNED_MARKER_REACHED")
            lab.check("red", "The connected build reaches the owned marker from the builder network",
                      reached, {"connected_build_reached_marker": reached})
            reasons = {}
            for name, reason in (("tampered", "LOCKED_FIXTURE_INPUT_MISMATCH"), ("missing", "LOCKED_FIXTURE_INPUT_MISSING")):
                result = build(registry, builder, marker, name)
                reasons[name] = result.returncode != 0 and emitted(result, reason) and emitted(result, "OWNED_MARKER_UNREACHABLE")
            lab.check("green", "The offline build rejects changed or missing locked input bytes for distinct reasons",
                      all(reasons.values()), reasons)
            result = build(registry, builder, marker, "approved")
            offline = result.returncode == 0 and emitted(result, "OWNED_MARKER_UNREACHABLE") and emitted(result, "package.txt: OK")
            lab.check("green", "Matching locked input builds without reaching the same private marker",
                      offline and (work / "approved.tar").is_file(),
                      {"offline_probe_denied": offline, "approved_image_archive": (work / "approved.tar").is_file()})
        ref = publish(registry, work, runtime)
        runtime.trust(registry)
        assertion, _ = (INPUTS / "dependencies.sha256").read_text().split()
        observe(registry, ref, assertion)
        (lab.evidence / "locked-build-receipt.json").write_text(json.dumps({
            "output_manifest": ref.split("@")[1], "dependency_lock_digest": assertion,
            "verified_input_busybox_image": BUSYBOX_IMAGE, "busybox_rootfs_sha256": rootfs_digest,
            "builder": BUILDKIT, "isolated_step": offline,
        }, indent=2, sort_keys=True) + "\n")
