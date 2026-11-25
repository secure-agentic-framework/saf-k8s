"""Stream a native etcd snapshot from the case-owned process's verified tmpfs.

No cluster lifecycle is included. Call only from the existing case while its
case-owned Kubernetes v1.36.1 kind cluster is alive. Every runtime assumption is
checked and fails closed. It returns a host-side ciphertext artifact suitable
for the existing age decrypt/digest/revision checks.
"""
import json
import os
from pathlib import Path
import re
import subprocess


SNAPSHOT_NAME = "saf-0102-007-protected.db"


def _node_output(lab, node, *args, timeout=30):
    try:
        result = subprocess.run(["docker", "exec", node, *args], env=lab.env,
                                capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The case-owned node could not verify its etcd tmpfs backing")
    if result.returncode:
        lab.block("A case-owned node tmpfs precondition failed")
    return result.stdout


def _container_pid(lab, node, container_id):
    normalized = container_id.removeprefix("containerd://")
    if not re.fullmatch(r"[0-9a-f]{32,128}", normalized):
        lab.block("The etcd container ID was not a containerd ID")
    raw = _node_output(lab, node, "crictl", "inspect", normalized)
    try:
        inspected = json.loads(raw)
        inspected_id = inspected["status"]["id"]
        pid = int(inspected["info"]["pid"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        lab.block("The pinned node runtime did not expose an inspectable etcd PID")
    if inspected_id != normalized or pid < 2:
        lab.block("Runtime inspection did not match the exact etcd container")
    return pid


def _exists(lab, node, path):
    try:
        result = subprocess.run(["docker", "exec", node, "test", "-e", path], env=lab.env,
                                capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The case-owned node could not verify volatile snapshot cleanup")
    if result.returncode not in (0, 1):
        lab.block("The case-owned node could not inspect the exact volatile snapshot path")
    return result.returncode == 0


def _stream_to_age(lab, node, source_path, age, recipient, encrypted_part):
    processes = []
    try:
        source = subprocess.Popen(["docker", "exec", node, "cat", source_path], env=lab.env,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        processes.append(source)
        with source.stdout as transfer:
            encryptor = subprocess.Popen([age, "--encrypt", "--recipient", recipient,
                                      "--output", str(encrypted_part), "-"], env=lab.env,
                                      stdin=transfer, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(encryptor)
        age_status = encryptor.wait(timeout=90)
        source_status = source.wait(timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("The protected snapshot-to-age stream did not complete")
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
    if (source_status or age_status or not encrypted_part.is_file()
            or encrypted_part.stat().st_size == 0):
        lab.block("The protected snapshot stream failed without retaining tool output")


def _snapshot_revision(lab, node, snapshot_tool, snapshot_path):
    raw = _node_output(lab, node, snapshot_tool, "--write-out=json", "snapshot", "status", snapshot_path)
    try:
        revision = int(json.loads(raw)["revision"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        lab.block("etcdutl did not report an exact source snapshot revision")
    if revision < 1:
        lab.block("The synthetic source snapshot had no valid revision")
    return revision


def capture_protected_snapshot(lab, pod, container_id, tls_args, age, recipient, encrypted):
    """Use bounded noswap tmpfs and write only ciphertext to the host staging directory."""
    node = f"{lab.cluster}-control-plane"
    if pod != f"etcd-{node}" or encrypted.exists() or any(encrypted.parent.iterdir()):
        lab.block("Protected capture requires the exact owned etcd Pod and an empty staging directory")
    pid = _container_pid(lab, node, container_id)
    tools = f"/proc/{pid}/root/usr/local/bin"
    mount = _node_output(lab, node, "mktemp", "-d", "/run/saf-etcd-stage.XXXXXX").strip()
    if not re.fullmatch(r"/run/saf-etcd-stage\.[A-Za-z0-9]{6}", mount):
        lab.block("The isolated node did not create the expected private staging directory")
    mounted = False
    encrypted_part = encrypted.with_suffix(".age.part")
    snapshot = f"{mount}/{SNAPSHOT_NAME}"
    try:
        _node_output(lab, node, "mount", "-t", "tmpfs", "-o", "noswap,size=16m,mode=0700,nosuid,nodev,noexec",
                     "tmpfs", mount)
        mounted = True
        result = _node_output(lab, node, "findmnt", "--noheadings", "--output", "FSTYPE,OPTIONS",
                              "--mountpoint", mount).strip().split()
        if len(result) != 2 or result[0] != "tmpfs" or "noswap" not in result[1].split(","):
            lab.block("The owned snapshot staging mount did not report tmpfs with noswap")
        lab.check("positive", "The owned snapshot staging mount is private bounded tmpfs with noswap",
                  True, {"filesystem": "tmpfs", "noswap": True, "maximum_size_mib": 16})
        _node_output(lab, node, f"{tools}/etcdctl", *tls_args, "snapshot", "save", snapshot, timeout=70)
        part_path = snapshot + ".part"
        if not _exists(lab, node, snapshot) or _exists(lab, node, part_path):
            lab.block("The native snapshot did not complete on the verified tmpfs")
        source_revision = _snapshot_revision(lab, node, f"{tools}/etcdutl", snapshot)
        digest_record = _node_output(lab, node, "sha256sum", snapshot).split()
        if not digest_record or not re.fullmatch(r"[0-9a-f]{64}", digest_record[0]):
            lab.block("The isolated source snapshot digest had an unexpected format")
        source_digest = digest_record[0]
        _stream_to_age(lab, node, snapshot, age, recipient, encrypted_part)
        encrypted_part.chmod(0o600)
        os.replace(encrypted_part, encrypted)
        _node_output(lab, node, "rm", "-f", "--", snapshot, part_path)
        if _exists(lab, node, snapshot) or _exists(lab, node, part_path):
            lab.block("Could not verify removal of both volatile etcd snapshot paths")
    finally:
        encrypted_part.unlink(missing_ok=True)
        if mounted:
            _node_output(lab, node, "umount", "--", mount)
        _node_output(lab, node, "rmdir", "--", mount)
    only_ciphertext = list(encrypted.parent.iterdir()) == [encrypted]
    lab.check("green", "Protected capture writes only the encrypted archive to host staging",
              only_ciphertext, {"staging_only_ciphertext": only_ciphertext,
                                "volatile_snapshot_removed_and_mount_deleted": True})
    return source_digest, source_revision
