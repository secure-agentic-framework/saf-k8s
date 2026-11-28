"""Prepare the owned A100 MIG layout with a durable, same-boot retry reservation."""

import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import time

from mig_inventory import MigPrecondition, PROFILE, RESOURCE, read_inventory, require

STATE_DIR = Path("/var/lib/saf-gpu-a100-bootstrap")
SOURCE_NAME = "nvidia-device-plugin-runtimeclass.yaml"
SOURCE_SHA = "7300da357074c72fb79904659cefc26aef784bb03c2302496d439b7b134e547a"
PLUGIN = "nvidia-device-plugin-daemonset"
NAMESPACE = "kube-system"
OWNER_KEY = "fixture.saf.example/mig-setup"
RESERVATION = "mig-setup.json"
SCOPE = "saf-a100-mig-setup-reservation-v1"
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def command(*args, check=True, timeout=15, data=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=timeout,
                            env={**os.environ, "LC_ALL": "C"})
    if check and result.returncode:
        raise MigPrecondition(f"{args[0]} returned {result.returncode}: {result.stderr.strip()[-1500:]}")
    return result


def k(*args, timeout=15, data=None):
    return command("/usr/local/bin/k3s", "kubectl", f"--request-timeout={timeout - 3}s",
                   *args, timeout=timeout, data=data).stdout


def plugin_state():
    result = k("-n", NAMESPACE, "get", "daemonset", PLUGIN, "--ignore-not-found", "-o", "json")
    return json.loads(result) if result.strip() else None


def candidate(source, owner):
    raw = source.read_bytes()
    require(not source.is_symlink() and sha256(raw).hexdigest() == SOURCE_SHA,
            "The retained device-plugin manifest differs from the exact pinned bootstrap bytes")
    manifest = json.loads(k("-n", NAMESPACE, "set", "env", "--local", "-f", "-", "MIG_STRATEGY=mixed",
                            "-o", "json", data=raw.decode("utf-8")))
    metadata = manifest["metadata"]
    require(manifest["kind"] == "DaemonSet" and (metadata["namespace"], metadata["name"]) == (NAMESPACE, PLUGIN),
            "Unexpected rendered device-plugin target")
    metadata.setdefault("annotations", {})[OWNER_KEY] = owner
    return manifest


def write_json(path, record, *, exclusive=False):
    location = path.with_name(path.name + "." + secrets.token_hex(6))
    try:
        with location.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(location, path)
        else:
            location.replace(path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        location.unlink(missing_ok=True)


def device_plugin_matches(plugin, intent):
    return bool(plugin and plugin["metadata"].get("uid")
                and plugin["metadata"].get("annotations", {}).get(OWNER_KEY) == intent["owner"]
                and digest(plugin["spec"]) == intent["plugin_spec_sha256"])


def expected_resources(node):
    for field in ("capacity", "allocatable"):
        values = node["status"][field]
        nvidia = {key: value for key, value in values.items() if key.startswith("nvidia.com/") and value != "0"}
        if nvidia != {RESOURCE: "2"}:
            return False
    return True


def prepare(state_dir, output, hostname, boot):
    nodes = json.loads(k("get", "nodes", "-o", "json"))["items"]
    require(len(nodes) == 1, "Expected exactly one node in the owned K3s fixture")
    node = nodes[0]
    require(node["metadata"]["name"] == hostname and node["status"]["nodeInfo"]["bootID"] == boot,
            "Kubernetes node identity differs from this guest boot")
    require(not k("-n", "saf-gpu-a100", "get", "pods", "-o", "name").strip(),
            "The reviewed fixture namespace must be empty before MIG preparation")
    current = read_inventory(command)
    live = plugin_state()
    plugin_was_present = live is not None
    reservation = state_dir / RESERVATION
    scope = {"schema": SCOPE, "node_ref": digest(node["metadata"]["uid"]),
             "boot_ref": digest(boot), "gpu_ref": digest(current.gpu),
             "manifest_sha256": SOURCE_SHA}
    new_reservation = not reservation.exists()
    if new_reservation:
        require(current.empty and live is None, "Existing GPU or plugin state has no matching reservation")
        owner = secrets.token_hex(16)
        intent = {**scope, "owner": owner, "geometry_ref": None}
    else:
        require(not reservation.is_symlink(), "The MIG reservation must be a regular file")
        intent = json.loads(reservation.read_text())
        require(all(intent.get(key) == value for key, value in scope.items())
                and re.fullmatch(r"[0-9a-f]{32}", intent.get("owner", "")),
                "The MIG reservation belongs to a different guest boot, GPU or manifest")

    manifest = candidate(state_dir / SOURCE_NAME, intent["owner"])
    payload = json.dumps(manifest)
    if live is None:
        normalized = json.loads(k("create", "--dry-run=server", "-f", "-", "-o", "json", data=payload))
        spec_ref = digest(normalized["spec"])
        if new_reservation:
            intent["plugin_spec_sha256"] = spec_ref
            write_json(reservation, intent, exclusive=True)
        require(spec_ref == intent["plugin_spec_sha256"], "The server-defaulted plugin spec changed during retry")
    else:
        require(device_plugin_matches(live, intent), "Existing daemonset differs from the reserved device plugin")
        require(not current.empty, "Reserved daemonset exists without its MIG geometry")

    submitted_creation = current.empty
    if submitted_creation:
        require(intent["geometry_ref"] is None, "Previously confirmed MIG geometry disappeared; review the guest")
        command("nvidia-smi", "mig", "-i", "0", "-cgi", f"{PROFILE},{PROFILE}", "-C", timeout=45)
        current = read_inventory(command)
        require(not current.empty and digest(current.gpu) == intent["gpu_ref"],
                "Creation did not establish both MIG devices on the reserved GPU")
    geometry_ref = digest((current.devices, current.instances))
    require(intent["geometry_ref"] in (None, geometry_ref), "Reserved MIG device UUIDs or instances changed")
    if intent["geometry_ref"] is None:
        intent["geometry_ref"] = geometry_ref
        write_json(reservation, intent)

    if live is None:
        live = json.loads(k("create", "-f", "-", "-o", "json", data=payload))
    require(device_plugin_matches(live, intent), "Kubernetes did not return the exact owned device plugin")
    uid = live["metadata"]["uid"]
    k("-n", NAMESPACE, "rollout", "status", "daemonset/" + PLUGIN, "--timeout=100s", timeout=105)
    deadline = time.monotonic() + 35
    while True:
        observed = json.loads(k("get", "node", hostname, "-o", "json"))
        require(observed["metadata"]["uid"] == node["metadata"]["uid"]
                and observed["status"]["nodeInfo"]["bootID"] == boot, "The node or guest boot changed during rollout")
        if expected_resources(observed):
            break
        require(time.monotonic() < deadline, "Kubelet did not publish exactly two MIG resources")
        time.sleep(1)
    final_plugin = plugin_state()
    require(device_plugin_matches(final_plugin, intent) and final_plugin["metadata"]["uid"] == uid,
            "The device plugin changed during verification")
    require(read_inventory(command) == current, "MIG geometry changed during rollout")
    write_json(output, {"schema": "saf-a100-mig-setup-v2", "status": "prepared", "geometry_verified": True,
                        "profile": PROFILE, "device_count": 2, "node_ref": scope["node_ref"],
                        "boot_ref": scope["boot_ref"], "geometry_ref": geometry_ref,
                        "plugin_uid_ref": digest(uid), "plugin_spec_sha256": intent["plugin_spec_sha256"],
                        "reservation_reused": not new_reservation, "slice_creation_requested": submitted_creation,
                        "existing_plugin_reused": plugin_was_present}, exclusive=True)


def main(output):
    hostname = socket.gethostname()
    require(os.geteuid() == 0 and re.fullmatch(r"saf-a100-[0-9]{10}", hostname),
            "Run as root on the dedicated, already-authorized A100 guest")
    require(output.is_absolute() and not output.exists() and not output.is_symlink(), "Provide a new absolute receipt path")
    owner = STATE_DIR.stat()
    require(owner.st_uid == 0 and stat.S_ISDIR(owner.st_mode) and not (owner.st_mode & 0o022)
            and not STATE_DIR.is_symlink(), "The bootstrap directory must be root-owned and protected")
    boot = BOOT_ID.read_text().strip()
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot), "Invalid kernel boot identity")
    fd = os.open(STATE_DIR / "mig-setup.lock", os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    with os.fdopen(fd, "r+") as lock:
        require(stat.S_ISREG(os.fstat(lock.fileno()).st_mode), "The MIG reservation lock must be a regular file")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MigPrecondition("Another MIG setup is active") from exc
        prepare(STATE_DIR, output, hostname, boot)


if __name__ == "__main__":
    os.umask(0o077)
    try:
        if len(sys.argv) != 2:
            raise MigPrecondition("Usage: mig_setup.py /absolute/new/receipt.json")
        main(Path(sys.argv[1]))
    except (MigPrecondition, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        sys.exit(str(exc))
