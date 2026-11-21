"""Prove non-root image defaults, shell-free inventory, and runtime rootfs enforcement."""
from io import BytesIO
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import time


HERE = Path(__file__).resolve().parent
NONROOT = 65534
SCOPE = (
    "Two synthetic Linux FROM scratch images built from one static Go probe and a public "
    "marker with distinct USER defaults. One disposable kind v1.36.1 cluster executes each "
    "arm. Compare effective process UID, EROFS from the same root-file operation and a "
    "permitted emptyDir write. Inspect both image archives for the exact final file inventory. "
    "This case exercises image and runtime behavior. Deployed image acceptance policies, "
    "approved production mounts and inspection of third-party images need separate evidence."
)


def inspect_image(lab, image, expected_user):
    saved = subprocess.run(["docker", "image", "save", image], env=lab.env,
                           capture_output=True, timeout=45)
    if saved.returncode != 0:
        lab.block("Could not save the case-owned image for file inventory")
    with tarfile.open(fileobj=BytesIO(saved.stdout)) as bundle:
        manifest = json.load(bundle.extractfile("manifest.json"))
        if len(manifest) != 1:
            lab.block("Expected one local image manifest")
        image_config = json.load(bundle.extractfile(manifest[0]["Config"]))["config"]
        contents = set()
        for entry in manifest[0]["Layers"]:
            stream = bundle.extractfile(entry)
            with tarfile.open(fileobj=BytesIO(stream.read())) as layer:
                for item in layer:
                    if not item.isdir():
                        contents.add((item.name.removeprefix("./"), item.isfile()))
    lab.check("positive", f"Final image with declared UID {expected_user} contains only its probe and marker",
              image_config["User"] == f"{expected_user}:{expected_user}"
              and contents == {("probe", True), ("fixture-marker", True)},
              {"declared_user": image_config["User"],
               "regular_paths": sorted(name for name, regular in contents if regular),
               "all_paths_are_regular": all(regular for _, regular in contents)})


def build_probes(lab, working, tags):
    node = f"{lab.cluster}-control-plane"
    architecture = lab.kubectl("get", f"node/{node}",
                               "-o", "jsonpath={.status.nodeInfo.architecture}").stdout.strip()
    if architecture not in ("amd64", "arm64") or not shutil.which("go"):
        lab.block("Case requires Go and a Linux amd64 or arm64 kind node")
    shutil.copyfile(HERE/"Dockerfile", working/"Dockerfile")
    (working/"fixture-marker").write_text("public case fixture\n")
    result = subprocess.run(
        ["go", "build", "-trimpath", "-o", str(working/"probe"), str(HERE/"probe.go")],
        env=dict(lab.env, CGO_ENABLED="0", GOOS="linux", GOARCH=architecture,
                 GOFLAGS="", GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off"),
        capture_output=True, text=True, timeout=180,
    )
    if result.returncode:
        lab.block("The case-owned static Go probe did not build: " + result.stderr.strip())
    for uid, image in tags.items():
        lab.command("docker", "build", "--network", "none", "--platform", f"linux/{architecture}",
                    "--build-arg", f"PROBE_UID={uid}", "-t", image, str(working), timeout=180)
        inspect_image(lab, image, uid)
        lab.command("kind", "load", "docker-image", "--name", lab.cluster, image, timeout=120)


def run_probe(lab, suffix, image, security):
    name = "saf-0601-014-" + suffix
    lab.create({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "securityContext": {"fsGroup": NONROOT},
            "containers": [{
                "name": "probe", "image": image, "imagePullPolicy": "Never",
                "securityContext": {**security, "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "volumeMounts": [{"name": "scratch", "mountPath": "/scratch"}],
            }],
            "volumes": [{"name": "scratch", "emptyDir": {}}],
        },
    })
    deadline = time.monotonic() + 45
    phase = None
    while time.monotonic() < deadline:
        phase = lab.kubectl("get", f"pod/{name}", "-o", "jsonpath={.status.phase}").stdout.strip()
        if phase in ("Succeeded", "Failed"):
            break
        time.sleep(0.5)
    if phase != "Succeeded":
        lab.block(f"Probe {name} did not complete successfully (phase={phase})")
    output = lab.kubectl("logs", name).stdout.strip()
    match = re.fullmatch(r"uid=(\d+) rootfs=(writable|read-only) scratch=writable", output)
    if not match:
        lab.block("Probe did not report a recognized runtime observation")
    return {"uid": int(match[1]), "rootfs": match[2], "scratch": "writable"}


def run(lab):
    tags = {uid: f"saf-0601-014-{lab.cluster}:uid-{uid}" for uid in (0, NONROOT)}
    with tempfile.TemporaryDirectory(prefix="saf-rootfs-build-") as temp:
        try:
            build_probes(lab, Path(temp), tags)
            images_and_settings = (
                ("default", tags[0], {}, 0, "writable", "red"),
                ("nonroot-default", tags[NONROOT], {}, NONROOT, "writable", "red"),
                ("readonly-only", tags[0], {"readOnlyRootFilesystem": True}, 0, "read-only", "red"),
                ("hardened", tags[NONROOT], {"runAsNonRoot": True, "runAsUser": NONROOT,
                                            "readOnlyRootFilesystem": True}, NONROOT, "read-only", "green"),
            )
            for name, image, security, uid, root, phase in images_and_settings:
                result = run_probe(lab, name, image, security)
                lab.check(phase, f"{name} profile has UID {uid}, {root} rootfs and writable scratch",
                          result == {"uid": uid, "rootfs": root, "scratch": "writable"}, result)
        finally:
            for image in tags.values():
                info = lab.command("docker", "image", "inspect", "--format", "{{.Id}}", image, allow_failure=True)
                if info.returncode == 0:
                    lab.command("docker", "image", "rm", image)
