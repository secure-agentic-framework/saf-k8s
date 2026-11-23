"""Verify LUKS block-image protection for a snapshot from an isolated etcd member."""

import json
from pathlib import Path
import time

SCOPE = ("An etcd snapshot containing only public lab data is written into an offline ext4 image. "
         "QEMU encrypts the block image as LUKS with a separately mounted memory-only key directory.")
HERE = Path(__file__).resolve().parent
TOOLS = "saf-lab-disk-encryption-fixture:alpine3.22"
ETCD = "gcr.io/etcd-development/etcd:v3.6.8@sha256:397189418d1a00e500c0605ad18d1baf3b541a1004d768448c367e48071622e5"
POD = "fixture-offline-disk"
ENDPOINT = "http://127.0.0.1:12379"
KEY = "/saf-owned/public"
MARKER = "saf owned etcd disk marker v1"


def unit(name, image, argv, mounts):
    return {"name": name, "image": image, "imagePullPolicy": "IfNotPresent", "command": argv,
            "volumeMounts": mounts,
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "15m", "memory": "32Mi"},
                          "limits": {"cpu": "400m", "memory": "192Mi"}}}


def member(lab, *args, allow_failure=False):
    return lab.kubectl("exec", "pod/" + POD, "-c", "etcd", "--", "etcdctl",
                       f"--endpoints={ENDPOINT}", "--dial-timeout=2s", "--command-timeout=10s",
                       *args, allow_failure=allow_failure)


def configure(lab):
    lab.command("docker", "build", "-q", "-t", TOOLS, "-f", str(HERE / "Dockerfile"), str(HERE), timeout=200)
    lab.command("kind", "load", "docker-image", TOOLS, "--name", lab.cluster, timeout=120)
    common = {"name": "work", "mountPath": "/work"}
    et = unit("etcd", ETCD, ["etcd", "--name=saf-owned", "--data-dir=/work/live",
                            "--listen-peer-urls=http://127.0.0.1:12380",
                            "--initial-advertise-peer-urls=http://127.0.0.1:12380",
                            "--initial-cluster=saf-owned=http://127.0.0.1:12380",
                            f"--listen-client-urls={ENDPOINT}", f"--advertise-client-urls={ENDPOINT}"],
              [common])
    disk = unit("disk", TOOLS, ["sleep", "240"], [common, {"name": "keys", "mountPath": "/fixture-keys"}])
    disk["imagePullPolicy"] = "Never"
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [et, disk],
        "volumes": [{"name": "work", "emptyDir": {}}, {"name": "keys", "emptyDir": {"medium": "Memory"}}],
    }})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + POD, "--timeout=80s", timeout=90)


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    configure(lab)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if not member(lab, "endpoint", "health", allow_failure=True).returncode:
            break
        time.sleep(0.45)
    else:
        lab.block("The owned single-member etcd fixture was unavailable")
    member(lab, "put", KEY, MARKER)
    current = member(lab, "get", KEY, "--print-value-only").stdout.strip() == MARKER
    lab.kubectl("exec", "pod/" + POD, "-c", "disk", "--", "mkdir", "/work/fixture-files")
    member(lab, "snapshot", "save", "/work/fixture-files/etcd.db")
    results = lab.kubectl("exec", "-i", "pod/" + POD, "-c", "disk", "--", "sh", "-s",
                          payload=(HERE / "encrypt-fixture.sh").read_text(), timeout=90)
    found = set(results.stdout.splitlines())
    plain = "plain_marker_present" in found
    protected = "luks_image_and_hidden_marker" in found
    wrong = "wrong_key_denied" in found
    restored = "exact_restore_with_separate_key" in found
    lab.check("red", "A plain offline block image exposes its known etcd snapshot marker", plain and current,
              {"owned_live_marker": current, "unprotected_block_marker_visible": plain})
    lab.check("green", "The LUKS image conceals the marker and prevents opening with the unrelated key",
              protected and wrong, {"luks_image_marker_hidden": protected, "unrelated_key_denied": wrong})
    lab.check("positive", "The approved separately stored passphrase restores the entire offline image",
              restored, {"byte_identical_image": restored})
    (lab.evidence / "etcd-media-encryption-observations.json").write_text(json.dumps({
        "unprotected_marker_visible": plain, "encrypted_marker_hidden": protected,
        "wrong_key_denied": wrong, "authorized_roundtrip_identical": restored,
        "production_attached_volume_tested": False,
    }, indent=2) + "\n")
