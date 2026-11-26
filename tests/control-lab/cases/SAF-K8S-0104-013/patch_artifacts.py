"""Stage only the exact release artifacts in the owned Kind node."""
import hashlib
import json
from pathlib import Path
import tempfile
import time


PINS = json.loads(Path(__file__).with_name("upgrade-pins.json").read_text())


def sha256(file):
    digest = hashlib.sha256()
    with file.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stage(lab, node, target, binary_dir):
    platform = node(lab, "uname", "-m").stdout.strip()
    architecture = {"aarch64": "arm64", "x86_64": "amd64"}.get(platform)
    release = PINS[target]
    if architecture not in release["binaries"]:
        lab.block("The owned node architecture has no reviewed official upgrade binaries")
    binaries = release["binaries"][architecture]
    node(lab, "mkdir", "-p", "-m", "0700", binary_dir)
    with tempfile.TemporaryDirectory(dir=lab.kubeconfig.parent, prefix="patch-binaries-") as temporary:
        for name, pin in binaries.items():
            binary = Path(temporary) / name
            lab.command("curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https",
                        "--max-time", "120", "--max-filesize", "180000000",
                        "--retry", "1", "--output", str(binary), pin["url"], timeout=135)
            if sha256(binary) != pin["sha256"]:
                lab.block(f"The official Kubernetes artifact did not match the pin: {name}")
            binary.chmod(0o700)
            lab.command("docker", "cp", str(binary),
                        f"{lab.cluster}-control-plane:{binary_dir}/{name}", timeout=85)
            verify = node(lab, "sha256sum", f"{binary_dir}/{name}").stdout.split()
            if not verify or verify[0] != pin["sha256"]:
                lab.block(f"The staged Kubernetes artifact did not match the pin: {name}")
    kubeadm = node(lab, f"{binary_dir}/kubeadm", "version", "-o", "short").stdout.strip()
    kubelet = node(lab, f"{binary_dir}/kubelet", "--version").stdout.strip()
    if kubeadm != target or kubelet != f"Kubernetes {target}":
        lab.block("The reviewed staged binaries did not declare the exact selected version")

    exact_images = {}
    acceptable_ids = {}
    for name, image in release["images"].items():
        ref = image["ref"]
        digest = image["platforms"][architecture]
        pinned = f"{ref}@{digest}"
        node(lab, "ctr", "-n", "k8s.io", "images", "pull", "--platform",
             f"linux/{architecture}", pinned, timeout=95)
        node(lab, "ctr", "-n", "k8s.io", "images", "tag", "--force",
             pinned, ref, timeout=25)
        exact_images[ref] = digest
        manifest = json.loads(node(lab, "ctr", "-n", "k8s.io", "content", "get",
                                   digest, timeout=20).stdout)
        config_digest = manifest["config"]["digest"]
        acceptable_ids[ref] = sorted({digest, image["index"], config_digest})
    inventory = alias_digests(lab, node, exact_images)
    if inventory != exact_images:
        lab.block("The owned node did not retain the expected pinned image aliases")
    return {"architecture": architecture, "binaries": binaries,
            "platform_image_digests": inventory, "container_image_ids": acceptable_ids,
            "go": release["go"]}


def alias_digests(lab, node, refs):
    inventory = {}
    table = node(lab, "ctr", "-n", "k8s.io", "images", "ls", timeout=20).stdout
    for row in table.splitlines():
        fields = row.split()
        if len(fields) >= 3 and fields[0] in refs:
            inventory[fields[0]] = fields[2]
    return inventory


def observed_component_payloads(lab, expected):
    deadline = time.monotonic() + 75
    observed = {}
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "pods", "-n", "kube-system", "-o", "json",
                             timeout=18, allow_failure=True)
        if result.returncode:
            time.sleep(1)
            continue
        observed = {}
        for pod in json.loads(result.stdout)["items"]:
            declared = {item["name"]: item["image"] for item in pod["spec"]["containers"]}
            for status in pod.get("status", {}).get("containerStatuses", []):
                image = declared.get(status["name"])
                if image in expected and status.get("ready") is True:
                    identity = status.get("imageID", "").rsplit("@", 1)[-1]
                    observed.setdefault(image, set()).add(identity)
        if set(observed) == set(expected) and all(ids <= set(expected[ref])
                                                  for ref, ids in observed.items()):
            return True, {ref: sorted(ids) for ref, ids in sorted(observed.items())}
        time.sleep(1)
    return False, {ref: sorted(ids) for ref, ids in sorted(observed.items())}


def observe(lab, node, pins):
    pid = node(lab, "systemctl", "show", "-p", "MainPID", "--value", "kubelet").stdout.strip()
    if not pid.isascii() or not pid.isdecimal() or int(pid) <= 1:
        lab.block("The owned node did not report a valid active kubelet PID")
    digest = node(lab, "sha256sum", f"/proc/{pid}/exe").stdout.split()[0]
    installed = node(lab, "sha256sum", "/usr/bin/kubelet").stdout.split()[0]
    api = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]
    images = alias_digests(lab, node, pins["platform_image_digests"])
    matched_payloads, payloads = observed_component_payloads(lab, pins["container_image_ids"])
    return {"pid": int(pid), "live_kubelet_sha256": digest, "installed_kubelet_sha256": installed, "api_server": api,
            "pinned_kubelet_matches": digest == installed == pins["binaries"]["kubelet"]["sha256"],
            "api_go_version_matches": api["goVersion"] == "go" + pins["go"]["version"],
            "component_image_aliases_match": images == pins["platform_image_digests"],
            "component_payloads_match": matched_payloads, "ready_component_image_ids": payloads}
