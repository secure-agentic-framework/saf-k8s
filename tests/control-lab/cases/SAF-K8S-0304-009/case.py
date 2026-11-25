"""Verify encrypted checkpoint IO, local permissions, and scoped Kubernetes access."""
import json
import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


HERE = Path(__file__).parent
CHECKPOINT = "saf-0304-009-checkpoint"
OTHER = "saf-0304-009-other"
HANDOFF = "saf-0304-009-handoff"
HANDOFF_ALTERED = "saf-0304-009-handoff-altered"
KEY_SECRET = "saf-0304-009-handoff-key"
SCOPE = (
    "Small inert checkpoint in an actual disk-backed emptyDir using a process-local "
    "AES-GCM key. Verify the on-volume record, authentic reuse, alteration rejection, "
    "and read/write denial for a different UID. Separately verify API access to a named "
    "ciphertext ConfigMap by synthetic ServiceAccounts. A fresh process in the same Pod "
    "authenticates a retained record against expected run, step and time using a separate tmpfs key. "
    "A separate fresh process also promotes only the authorized encrypted envelope. "
    "Provider encryption and durable cross-Pod key custody are adopter-specific."
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
    volumes = [{"name": "checkpoint", "emptyDir": {}}]
    for index, mode in enumerate(modes):
        uid = 65534 - index
        containers.append({"name": mode, "image": image, "imagePullPolicy": "Never", "args": [mode],
                           "securityContext": {"runAsNonRoot": True, "runAsUser": uid, "runAsGroup": uid,
                                               "readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                               "capabilities": {"drop": ["ALL"]},
                                               "seccompProfile": {"type": "RuntimeDefault"}},
                           "volumeMounts": [{"name": "checkpoint", "mountPath": "/checkpoint"}]})
        if mode == "lifecycle":
            containers[-1]["volumeMounts"].append({"name": "resume-key", "mountPath": "/resume-key"})
            volumes.append({"name": "resume-key", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}})
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                         "securityContext": {"fsGroup": 65534}, "containers": containers,
                         "volumes": volumes}})
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


def handoff_pod(lab, image, name, mode, secret_name, configmap_name=None, service_account=None, expected_exit=0):
    volumes = [
        {"name": "resume-key", "secret": {"secretName": secret_name, "defaultMode": 0o440}},
        {"name": "handoff", "emptyDir": {}} if mode == "handoff-produce" else
        {"name": "handoff", "configMap": {"name": configmap_name, "defaultMode": 0o440}},
        {"name": "checkpoint", "emptyDir": {"sizeLimit": "1Mi"}},
    ]
    mounts = [
        {"name": "resume-key", "mountPath": "/resume-key", "readOnly": True},
        {"name": "handoff", "mountPath": "/handoff", "readOnly": mode == "handoff-consume"},
        {"name": "checkpoint", "mountPath": "/checkpoint"},
    ]
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": mode == "handoff-produce",
                         **({"serviceAccountName": service_account} if service_account else {}),
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                             "runAsGroup": 65534, "fsGroup": 65534},
                         "containers": [{"name": "probe", "image": image, "imagePullPolicy": "Never",
                                         "args": [mode], "securityContext": {
                                             "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]},
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                                         "volumeMounts": mounts}], "volumes": volumes}})
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        pod = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
        status = pod.get("status", {})
        containers = status.get("containerStatuses", [])
        terminated = containers[0].get("state", {}).get("terminated") if len(containers) == 1 else None
        if terminated and status.get("phase") in {"Succeeded", "Failed"}:
            break
        time.sleep(0.6)
    else:
        lab.block("Checkpoint handoff Pod did not reach a terminal phase")
    if terminated.get("exitCode") != expected_exit:
        lab.block(f"Checkpoint handoff Pod returned exit {terminated.get('exitCode')}, expected {expected_exit}")
    logs = lab.kubectl("logs", name, "-c", "probe").stdout.splitlines()
    # The success path prints the standard promotion marker followed by a
    # summary. Only the summary is returned to check evidence.
    summaries = [line for line in logs if line.startswith("{")]
    return bool(summaries), summaries[-1] if summaries else ""


def verify_cross_pod_handoff(lab, image):
    # The key is generated once in memory and placed only in a disposable
    # Secret. Never echo the key, serialized Secret, or mounted file to output.
    key_bytes = os.urandom(32)
    def create_ephemeral_secret(name, value):
        # Lab.create logs its JSON request body. Keep secret bytes in a private
        # mode-0600 temporary manifest and log only the file path and API result.
        with tempfile.TemporaryDirectory(prefix="saf-0304-009-secret-") as private:
            manifest = Path(private) / "secret.json"
            manifest.write_text(json.dumps({"apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": name}, "type": "Opaque", "immutable": True,
                "data": {"key": base64.b64encode(value).decode("ascii")}}))
            manifest.chmod(0o600)
            lab.kubectl("create", "-f", str(manifest), "-o", "name")

    create_ephemeral_secret(KEY_SECRET, key_bytes)
    wrong_key_bytes = os.urandom(32)
    create_ephemeral_secret("saf-0304-009-outsider-key", wrong_key_bytes)
    for name in ("checkpoint-producer", "checkpoint-consumer"):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name}})
    lab.apply(HERE / "handoff-access.yaml")

    # Both ConfigMaps exist before the producer runs. Its ServiceAccount can
    # patch only HANDOFF; no envelope bytes pass through harness output/logs.
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": HANDOFF},
                "data": {"envelope.json": ""}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": HANDOFF_ALTERED},
                "data": {"envelope.json": ""}})
    producer = "saf-checkpoint-handoff-producer"
    produced, producer_summary = handoff_pod(lab, image, producer, "handoff-produce", KEY_SECRET,
                                              HANDOFF, "checkpoint-producer")
    produced_status = json.loads(producer_summary) if produced else {}
    lab.check("positive", "Producer Pod publishes an encrypted envelope to its exact named handoff",
              produced_status.get("ciphertext_handoff_written") is True,
              {"ciphertext_handoff_written": produced_status.get("ciphertext_handoff_written") is True})
    quiet_get = subprocess.run(["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                                f"kind-{lab.cluster}", "--namespace", "saf-test", "get",
                                "configmap", HANDOFF, "-o", "json"], env=lab.env,
                               capture_output=True, text=True, timeout=20)
    if quiet_get.returncode:
        lab.block("Could not inspect the synthetic handoff object")
    produced_object = json.loads(quiet_get.stdout)
    envelope = json.loads(produced_object["data"]["envelope.json"])
    altered = dict(envelope)
    raw_ciphertext = bytearray(base64.b64decode(altered["ciphertext"]))
    raw_ciphertext[-1] ^= 1
    altered["ciphertext"] = base64.b64encode(raw_ciphertext).decode("ascii")
    with tempfile.TemporaryDirectory(prefix="saf-0304-009-altered-") as private:
        manifest = Path(private) / "altered-handoff.json"
        manifest.write_text(json.dumps({"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": HANDOFF_ALTERED},
            "data": {"envelope.json": json.dumps(altered, sort_keys=True)}}))
        manifest.chmod(0o600)
        lab.kubectl("apply", "-f", str(manifest), "-o", "name")

    authorized = "checkpoint-consumer"
    allowed = as_account(lab, authorized, "get", "configmap", HANDOFF, "-o", "name")
    key_allowed = as_account(lab, authorized, "get", "secret", KEY_SECRET, "-o", "name")
    outsider_read = as_account(lab, "checkpoint-outsider", "get", "configmap", HANDOFF, "-o", "name")
    outsider_key = as_account(lab, "checkpoint-outsider", "get", "secret", KEY_SECRET, "-o", "name")
    lab.check("green", "Only the scoped consumer identity can read the named ciphertext and key objects",
              allowed.returncode == 0 and key_allowed.returncode == 0
              and forbidden(outsider_read) and forbidden(outsider_key),
              {"authorized_named_reads": allowed.returncode == 0 and key_allowed.returncode == 0,
               "outsider_denied": forbidden(outsider_read) and forbidden(outsider_key)})
    collection = as_account(lab, authorized, "get", "configmaps")
    unrelated = as_account(lab, authorized, "get", "configmap", OTHER)
    lab.check("green", "Consumer grants do not allow collection or unrelated reads",
              forbidden(collection) and forbidden(unrelated),
              {"collection_denied": forbidden(collection), "unrelated_denied": forbidden(unrelated)})

    altered_ok, altered_summary = handoff_pod(lab, image, "saf-checkpoint-handoff-altered",
                                              "handoff-consume", KEY_SECRET, HANDOFF_ALTERED, expected_exit=20)
    altered_status = json.loads(altered_summary) if altered_ok else {}
    lab.check("green", "Altered ciphertext is rejected before handoff promotion",
              altered_status.get("accepted") is False and altered_status.get("promotion_absent") is True,
              {"altered_rejected": altered_status.get("accepted") is False,
               "promotion_absent": altered_status.get("promotion_absent") is True})
    unauthorized_ok, unauthorized_summary = handoff_pod(
        lab, image, "saf-checkpoint-handoff-outsider", "handoff-consume",
        "saf-0304-009-outsider-key", HANDOFF, "checkpoint-outsider", expected_exit=20)
    unauthorized_status = json.loads(unauthorized_summary) if unauthorized_ok else {}
    lab.check("green", "A consumer without the handoff key cannot authenticate or promote it",
              unauthorized_status.get("accepted") is False
              and unauthorized_status.get("promotion_absent") is True,
              {"unauthorized_key_rejected": unauthorized_status.get("accepted") is False,
               "promotion_absent": unauthorized_status.get("promotion_absent") is True})
    exact_ok, exact_summary = handoff_pod(lab, image, "saf-checkpoint-handoff-authorized",
                                          "handoff-consume", KEY_SECRET, HANDOFF, "checkpoint-consumer")
    exact_status = json.loads(exact_summary) if exact_ok else {}
    lab.check("positive", "Authorized consumer promotes the exact encrypted handoff",
              exact_status.get("accepted") is True
              and exact_status.get("promotion_preserved_ciphertext") is True,
              {"exact_handoff_accepted": exact_status.get("accepted") is True,
               "ciphertext_preserved": exact_status.get("promotion_preserved_ciphertext") is True})

    lab.kubectl("delete", "secret", KEY_SECRET, "saf-0304-009-outsider-key", "--wait=true")
    key_source = lab.kubectl("get", "secret", KEY_SECRET, "saf-0304-009-outsider-key",
                             "--ignore-not-found", "-o", "name").stdout.strip()
    lab.check("positive", "Both owned temporary key objects are absent after the Pods finish",
              not key_source, {"temporary_key_objects_retired": not key_source})


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
        lifecycle, = on_volume(lab, image, "saf-checkpoint-lifecycle", "lifecycle")
        resume = lifecycle.get("resume", {})
        lab.check("positive", "A fresh process authenticates the retained checkpoint before resume",
                  resume.get("authorized_retained_verified") is True
                  and resume.get("key_tmpfs_mode_0600") is True,
                  {key: resume.get(key) for key in ("authorized_retained_verified", "key_tmpfs_mode_0600")})
        rejected = {key: resume.get(key) for key in ("changed_rejected", "wrong_run_rejected",
                    "wrong_step_rejected", "stale_rejected", "future_rejected")}
        lab.check("green", "Resume rejects altered, wrong-run, wrong-step, expired and future checkpoints",
                  all(value is True for value in rejected.values()), rejected)
        lab.check("green", "The process removes the temporary records and key and confirms absence",
                  resume.get("cleanup_verified") is True,
                  {"cleanup_verified": resume.get("cleanup_verified")})
        promotion = lifecycle.get("promotion", {})
        lab.check("positive", "The approved checkpoint is promoted as the same verified ciphertext",
                  promotion.get("approved_copy_written") is True,
                  {"approved_copy_written": promotion.get("approved_copy_written")})
        blocked_promotions = {key: promotion.get(key) for key in (
            "tampered_no_destination", "wrong_run_no_destination", "wrong_step_no_destination",
            "stale_no_destination", "future_no_destination")}
        lab.check("green", "Rejected checkpoints never create a promotion destination object",
                  all(value is True for value in blocked_promotions.values()), blocked_promotions)
        verify_api_boundary(lab, envelope)
        verify_cross_pod_handoff(lab, image)
    finally:
        lab.command("docker", "image", "rm", image, timeout=45, allow_failure=True)
