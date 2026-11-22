"""Verify encrypted checkpoint IO, local permissions, and scoped Kubernetes access."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


HERE = Path(__file__).parent
CHECKPOINT = "saf-0304-009-checkpoint"
OTHER = "saf-0304-009-other"
SCOPE = (
    "Small inert checkpoint in an actual disk-backed emptyDir using a process-local "
    "AES-GCM key. Verify the on-volume record, authentic reuse, alteration rejection, "
    "and read/write denial for a different UID. Separately verify API access to a named "
    "ciphertext ConfigMap by synthetic ServiceAccounts. Real data, provider/filesystem "
    "encryption, reuse across processes, key-management lifecycle and production scope remain separate."
)


def build(lab, image, directory):
    architecture = lab.kubectl("get", f"node/{lab.cluster}-control-plane", "-o",
                               "jsonpath={.status.nodeInfo.architecture}").stdout.strip()
    if architecture not in ("arm64", "amd64") or not shutil.which("go"):
        lab.block("The checkpoint probe requires local Go and a Linux kind amd64 or arm64 node")
    shutil.copyfile(HERE / "Dockerfile", directory / "Dockerfile")
    result = subprocess.run(
        ["go", "build", "-trimpath", "-o", str(directory / "checkpoint"), str(HERE / "checkpoint.go")],
        env=dict(lab.env, CGO_ENABLED="0", GOOS="linux", GOARCH=architecture,
                 GOFLAGS="", GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off"),
        capture_output=True, text=True, timeout=150,
    )
    if result.returncode:
        lab.block("The checkpoint probe did not build: " + result.stderr.strip())
    lab.command("docker", "build", "--network", "none", "--pull=false", "--platform", f"linux/{architecture}",
                "-t", image, str(directory), timeout=120)
    lab.command("kind", "load", "docker-image", "--name", lab.cluster, image, timeout=120)


def on_volume(lab, image, name, *modes):
    containers = []
    for index, mode in enumerate(modes):
        uid = 65534 - index
        containers.append({"name": mode, "image": image, "imagePullPolicy": "Never", "args": [mode],
                           "securityContext": {"runAsNonRoot": True, "runAsUser": uid, "runAsGroup": uid,
                                               "readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                               "capabilities": {"drop": ["ALL"]},
                                               "seccompProfile": {"type": "RuntimeDefault"}},
                           "volumeMounts": [{"name": "checkpoint", "mountPath": "/checkpoint"}]})
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                         "securityContext": {"fsGroup": 65534}, "containers": containers,
                         "volumes": [{"name": "checkpoint", "emptyDir": {}}]}})
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}", "--timeout=60s", timeout=70)
    return [json.loads(lab.kubectl("logs", name, "-c", mode).stdout) for mode in modes]


def as_account(lab, user, *args):
    account = f"system:serviceaccount:saf-test:{user}"
    return lab.kubectl("--as", account, "--as-group", "system:serviceaccounts",
                       "--as-group", "system:serviceaccounts:saf-test", "--as-group", "system:authenticated",
                       *args, allow_failure=True)


def forbidden(response):
    return response.returncode != 0 and "(Forbidden)" in response.stderr


def verify_api_boundary(lab, envelope):
    for name, content in ((CHECKPOINT, json.dumps(envelope, sort_keys=True)), (OTHER, "inert")):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                    "data": {"envelope": content}})
    lab.apply(HERE / "access.yaml")
    training = "checkpoint-training"
    before = as_account(lab, training, "get", "configmap", CHECKPOINT)
    lab.check("red", "The synthetic training identity cannot read the object without a binding",
              forbidden(before), {"unbound_denied": forbidden(before)})
    lab.apply(HERE / "binding.yaml")
    retrieved = as_account(lab, training, "get", "configmap", CHECKPOINT, "-o", "json")
    original = json.loads(retrieved.stdout)["data"]["envelope"] if retrieved.returncode == 0 else "{}"
    lab.check("positive", "The authorized read returns the same encrypted record",
              retrieved.returncode == 0 and json.loads(original) == envelope, {"read_authorized": retrieved.returncode == 0})
    patch = '{"data":{"stage":"synthetic-resumed"}}'
    permitted_write = as_account(lab, training, "patch", "configmap", CHECKPOINT, "--type=merge", "-p", patch)
    live = json.loads(lab.kubectl("get", "configmap", CHECKPOINT, "-o", "json").stdout)
    lab.check("positive", "The authorized checkpoint update persists on the intended object",
              permitted_write.returncode == 0 and live["data"].get("stage") == "synthetic-resumed",
              {"authorized_update": permitted_write.returncode == 0})
    outsider = "checkpoint-outsider"
    denied = {
        "unrelated_read": forbidden(as_account(lab, training, "get", "configmap", OTHER)),
        "collection_read": forbidden(as_account(lab, training, "get", "configmaps")),
        "outsider_read": forbidden(as_account(lab, outsider, "get", "configmap", CHECKPOINT)),
        "outsider_write": forbidden(as_account(lab, outsider, "patch", "configmap", CHECKPOINT, "--type=merge", "-p", patch)),
    }
    lab.check("green", "The role preserves the approved scope and denies unrelated and outsider access",
              all(denied.values()), denied)


def run(lab):
    image = f"saf-0304-009:{lab.cluster}"
    try:
        with tempfile.TemporaryDirectory(prefix="saf-checkpoint-") as temporary:
            build(lab, image, Path(temporary))
        plain, = on_volume(lab, image, "saf-checkpoint-plain", "plain")
        lab.check("red", "The ordinary disk fixture preserves the inert plaintext before encryption",
                  plain["plain_marker_present"], plain)
        protected, observer = on_volume(lab, image, "saf-checkpoint-encrypted", "encrypt", "observe")
        envelope = protected.pop("envelope")
        lab.check("green", "The disk-backed encrypted record has no plaintext and rejects altered reuse",
                  protected == {"plain_marker_absent": True, "disk_backed": True,
                                "valid_accepted": True, "corrupted_rejected": True, "file_mode": 0o600},
                  protected)
        lab.check("green", "The independent unprivileged container cannot read or write the checkpoint file",
                  observer == {"read_denied": True, "write_denied": True}, observer)
        verify_api_boundary(lab, envelope)
    finally:
        lab.command("docker", "image", "rm", image, timeout=45, allow_failure=True)
