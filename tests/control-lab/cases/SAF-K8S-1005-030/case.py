"""Rehearse verified etcd restore and API-visible recovery of one synthetic object."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


HERE = Path(__file__).resolve().parent
FIXTURE_PATH = HERE / "fixtures" / "rehearsal.json"
CONTROL_ID = "SAF-K8S-1005-030"
NAMESPACE = "saf-1005-030-rehearsal"
OBJECT_NAME = "recovery-sentinel"
DATA_DIRECTORY = "/var/lib/etcd"
RESTORED_DIRECTORY = "/var/lib/etcd-saf-1005-030-restored"
ETCD_ENDPOINT = "https://127.0.0.1:2379"
ETCD_IMAGE = (
    "registry.k8s.io/etcd:3.6.8-0@sha256:"
    "397189418d1a00e500c0605ad18d1baf3b541a1004d768448c367e48071622e5"
)
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
REVISION_BUMP = 1_000_000
SCOPE = (
    "One fresh, single-control-plane Kind v1.36.1 cluster. Create one labeled, non-sensitive "
    "ConfigMap sentinel; snapshot the live etcd member; reject a deliberately truncated copy "
    "before any restore action; mutate the sentinel; restore the integrity-checked snapshot into "
    "a new data directory with a revision bump and compaction; switch the disposable kubeadm "
    "static etcd manifest to that directory; and verify the original sentinel state through the "
    "Kubernetes API. The backup contains the cluster's etcd database, but this case never reads, "
    "prints, queries, or exports credential objects or values. This does not prove production "
    "backup custody, encryption, signer trust, control-plane rebuild, multi-member/external etcd, "
    "authorization, business recovery objectives, or organization-wide execution readiness."
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def private_process(lab, args, timeout=60):
    """Run an expected-error helper without retaining raw diagnostics in evidence."""
    try:
        return subprocess.run(args, env=lab.env, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("A bounded local etcd recovery helper could not complete")


def api_object(lab):
    return json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "configmap", OBJECT_NAME, "-o", "json",
    ).stdout)


def object_state(obj, fixture):
    metadata = obj.get("metadata", {})
    return {
        "exists": obj.get("kind") == "ConfigMap",
        "namespace": metadata.get("namespace"),
        "name": metadata.get("name"),
        "uid": metadata.get("uid"),
        "state": obj.get("data", {}).get(fixture["object"]["key"]),
        "fixture_label": metadata.get("labels", {}).get("saf-k8s.example/fixture"),
    }


def native_snapshot_revision(lab, mount, filename):
    result = private_process(lab, [
        "docker", "run", "--rm", "--network=none", "--mount", mount,
        "--entrypoint=etcdutl", ETCD_IMAGE, "--write-out=json", "snapshot", "status",
        f"/backup/{filename}",
    ], timeout=45)
    if result.returncode:
        return None
    try:
        return int(json.loads(result.stdout)["revision"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def snapshot(lab, node, etcd_pod, destination):
    remote = f"{DATA_DIRECTORY}/saf-1005-030-{destination.name}"
    tls = [
        f"--endpoints={ETCD_ENDPOINT}",
        "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
        "--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt",
        "--key=/etc/kubernetes/pki/etcd/healthcheck-client.key",
    ]
    try:
        lab.kubectl(
            "-n", "kube-system", "exec", etcd_pod, "-c", "etcd", "--",
            "etcdctl", *tls, "snapshot", "save", remote, timeout=90,
        )
        lab.command("docker", "cp", f"{node}:{remote}", str(destination), timeout=90)
        destination.chmod(0o600)
    finally:
        lab.command("docker", "exec", node, "rm", "-f", remote, allow_failure=True)


def etcd_profile(lab):
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)
    if version.get("serverVersion", {}).get("gitVersion") != "v1.36.1":
        lab.block("Expected the runner-pinned Kubernetes v1.36.1 profile")
    node = f"{lab.cluster}-control-plane"
    nodes = lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines()
    if nodes != [node]:
        lab.block("Refusing recovery operations outside the one runner-owned Kind node")
    pod_name = f"etcd-{node}"
    pod = json.loads(lab.kubectl("-n", "kube-system", "get", f"pod/{pod_name}", "-o", "json").stdout)
    containers = [item for item in pod.get("spec", {}).get("containers", [])
                  if item.get("name") == "etcd"]
    if len(containers) != 1 or containers[0].get("image") != "registry.k8s.io/etcd:3.6.8-0":
        lab.block("The observed Kind control plane does not match the expected etcd profile")
    mounts = {item.get("name") for item in containers[0].get("volumeMounts", [])
              if item.get("mountPath") == DATA_DIRECTORY}
    host_paths = {item.get("name") for item in pod.get("spec", {}).get("volumes", [])
                  if item.get("hostPath", {}).get("path") == DATA_DIRECTORY}
    if not mounts.intersection(host_paths):
        lab.block("The etcd data directory is not the expected node hostPath")

    args = containers[0].get("command", []) + containers[0].get("args", [])
    def flag(name):
        prefix = f"--{name}="
        values = [value[len(prefix):] for value in args if value.startswith(prefix)]
        if len(values) != 1 or not values[0]:
            lab.block(f"Could not identify the etcd {name} setting from the API mirror")
        return values[0]

    manifest = lab.command("docker", "exec", node, "cat", "/etc/kubernetes/manifests/etcd.yaml").stdout
    if manifest.count("path: /var/lib/etcd") != 1 or "kind: Pod" not in manifest:
        lab.block("The kubeadm etcd manifest is outside the expected single-data-path profile")
    return node, pod_name, flag("name"), flag("initial-cluster"), flag("initial-advertise-peer-urls"), manifest


def restore_api(lab, node, member_name, initial_cluster, peer_urls, manifest_original,
                artifact, staging, mount, trusted_digest, expected_state):
    if sha256(artifact) != trusted_digest:
        lab.block("Verified backup changed before the restore")
    restored = staging / "member"
    if restored.exists():
        lab.block("Restore staging directory already exists")
    result = private_process(lab, [
        "docker", "run", "--rm", "--network=none", "--mount", mount,
        "--entrypoint=etcdutl", ETCD_IMAGE, "snapshot", "restore",
        f"/backup/{artifact.name}", f"--data-dir=/backup/member", f"--name={member_name}",
        f"--initial-cluster={initial_cluster}",
        f"--initial-advertise-peer-urls={peer_urls}",
        f"--bump-revision={REVISION_BUMP}", "--mark-compacted",
    ], timeout=90)
    if result.returncode:
        lab.block("Verified backup restore command failed; the existing data directory remains intact")

    manifest_path = "/etc/kubernetes/manifests/etcd.yaml"
    parked_manifest = "/etc/kubernetes/etcd.yaml.saf-1005-030-original"
    if RESTORED_DIRECTORY in manifest_original or "--name=" + member_name not in manifest_original:
        lab.block("Refusing an unexpected etcd manifest before maintenance")
    path_exists = lab.command("docker", "exec", node, "sh", "-ec",
                              f"test ! -e {RESTORED_DIRECTORY}", allow_failure=True)
    if path_exists.returncode:
        lab.block("Refusing to overwrite a pre-existing etcd recovery directory")
    lab.command("docker", "cp", str(restored), f"{node}:{RESTORED_DIRECTORY}", timeout=90)
    # Keep the original data directory and manifest as the abort/recovery path.
    lab.command("docker", "exec", node, "sh", "-ec",
                f"test ! -e {parked_manifest}; cp {manifest_path} {parked_manifest}")
    lab.command("docker", "exec", node, "systemctl", "stop", "kubelet", timeout=45)
    kubelet_stopped = True
    manifest_switched = False
    try:
        # Stop the API server and all kubeadm control-plane static-pod containers before
        # changing etcd state. The runner owns this one disposable control-plane node.
        lab.command(
            "docker", "exec", node, "sh", "-ec",
            "for component in kube-apiserver etcd kube-controller-manager kube-scheduler; do "
            "for id in $(crictl ps --name \"$component\" -q); do crictl stop \"$id\"; done; done",
            timeout=60,
        )
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            running = []
            for component in ("kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler"):
                running.extend(lab.command(
                    "docker", "exec", node, "crictl", "ps", "--name", component, "-q",
                ).stdout.split())
            if not running:
                break
            time.sleep(1)
        else:
            lab.block("Control-plane static pods did not stop; aborting before data-path switch")

        lab.command("docker", "exec", node, "sh", "-ec",
                    f"test -d {RESTORED_DIRECTORY}; test $(grep -c 'path: /var/lib/etcd$' {manifest_path}) -eq 1; "
                    f"sed -i 's#path: /var/lib/etcd$#path: {RESTORED_DIRECTORY}#' {manifest_path}; "
                    f"test $(grep -c 'path: {RESTORED_DIRECTORY}$' {manifest_path}) -eq 1")
        manifest_switched = True
        lab.command("docker", "exec", node, "systemctl", "start", "kubelet", timeout=45)
        kubelet_stopped = False

        deadline = time.monotonic() + 150
        observed = None
        while time.monotonic() < deadline:
            result = lab.kubectl(
                "-n", NAMESPACE, "get", "configmap", OBJECT_NAME, "-o", "json",
                timeout=15, allow_failure=True,
            )
            if result.returncode == 0:
                observed = json.loads(result.stdout)
                if observed.get("data", {}).get("state") == expected_state:
                    break
            time.sleep(2)
        if not observed or observed.get("data", {}).get("state") != expected_state:
            lab.block("Kubernetes API did not return the snapshot sentinel after etcd restart")

        node_ready = False
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            ready = lab.kubectl("get", "node", node, "-o", "json", timeout=20,
                                allow_failure=True)
            if ready.returncode == 0:
                node_obj = json.loads(ready.stdout)
                node_ready = any(condition.get("type") == "Ready"
                                 and condition.get("status") == "True"
                                 for condition in node_obj.get("status", {}).get("conditions", []))
                if node_ready:
                    break
            time.sleep(2)
        if not node_ready:
            lab.block("The API-visible sentinel returned but the control-plane node is not Ready")
        health = lab.kubectl("get", "--raw=/readyz", timeout=20)
        if health.stdout.strip() != "ok":
            lab.block("Restored API server did not report ready")
        return observed, node_ready
    except Exception:
        # Revert only the case-owned manifest reference; the original etcd data is untouched.
        if kubelet_stopped:
            lab.command("docker", "exec", node, "sh", "-ec",
                        f"cp {parked_manifest} {manifest_path}", allow_failure=True)
            lab.command("docker", "exec", node, "systemctl", "start", "kubelet",
                        timeout=45, allow_failure=True)
        elif manifest_switched:
            lab.command("docker", "exec", node, "systemctl", "stop", "kubelet",
                        timeout=45, allow_failure=True)
            lab.command("docker", "exec", node, "sh", "-ec",
                        f"cp {parked_manifest} {manifest_path}", allow_failure=True)
            lab.command("docker", "exec", node, "systemctl", "start", "kubelet",
                        timeout=45, allow_failure=True)
        raise


def run(lab):
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    if (fixture.get("fixture_only") is not True or fixture.get("credentials") is not False
            or fixture.get("external_targets") != [] or fixture.get("workloads") is not False):
        lab.block("Rehearsal fixture must remain synthetic, credential-free, and offline")
    node, etcd_pod, member_name, initial_cluster, peer_urls, original_manifest = etcd_profile(lab)
    lab.kubectl("create", "namespace", NAMESPACE)
    sentinel = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": OBJECT_NAME, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control": "1005-030",
                                "saf-k8s.example/fixture": "synthetic-etcd-recovery"}},
        "data": {fixture["object"]["key"]: fixture["object"]["before_backup"]},
    }
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(sentinel))
    before = object_state(api_object(lab), fixture)
    if before["state"] != fixture["object"]["before_backup"] or not before["uid"]:
        lab.block("The synthetic baseline was not independently observed through the Kubernetes API")

    with tempfile.TemporaryDirectory(prefix="saf-1005-030-") as temporary:
        root = Path(temporary).resolve()
        staging = root / "backup"
        staging.mkdir(mode=0o700)
        mount = f"type=bind,src={staging},dst=/backup"
        good = staging / "verified.db"
        snapshot(lab, node, etcd_pod, good)
        trusted_digest = sha256(good)
        original_revision = native_snapshot_revision(lab, mount, good.name)
        if original_revision is None or original_revision <= 0:
            lab.block("New etcd snapshot failed native integrity/status inspection")

        damaged = staging / "rejected-truncated.db"
        shutil.copyfile(good, damaged)
        damaged.chmod(0o600)
        with damaged.open("r+b") as stream:
            stream.truncate(max(1, damaged.stat().st_size // 2))
        digest_rejected = sha256(damaged) != trusted_digest
        native_rejected = native_snapshot_revision(lab, mount, damaged.name) is None
        unchanged = object_state(api_object(lab), fixture) == before
        lab.check(
            "red", "A truncated backup is rejected before restore and leaves the API sentinel unchanged",
            digest_rejected and native_rejected and unchanged,
            {"trusted_digest_mismatch": digest_rejected, "native_snapshot_rejected": native_rejected,
             "restore_attempted": False, "sentinel_unchanged": unchanged,
             "sentinel_uid_preserved": bool(before["uid"])},
        )

        lab.kubectl(
            "-n", NAMESPACE, "patch", "configmap", OBJECT_NAME, "--type=merge", "-p",
            json.dumps({"data": {fixture["object"]["key"]: fixture["object"]["after_backup"]}}),
        )
        after_backup = object_state(api_object(lab), fixture)
        if after_backup["state"] != fixture["object"]["after_backup"]:
            lab.block("The post-snapshot API state was not independently observed")

        observed, node_ready = restore_api(
            lab, node, member_name, initial_cluster, peer_urls,
            original_manifest, good, staging, mount, trusted_digest, fixture["object"]["before_backup"],
        )
        restored_state = object_state(observed, fixture)
        locator = f"/api/v1/namespaces/{NAMESPACE}/configmaps?fieldSelector=metadata.name%3D{OBJECT_NAME}"
        listing = json.loads(lab.kubectl("get", "--raw", locator).stdout)
        revision = listing["metadata"].get("resourceVersion", "")
        if listing.get("kind") != "ConfigMapList" or not revision.isdecimal() or len(listing["items"]) != 1:
            lab.block("Raw API list did not identify the restored fixture at a numeric revision")
        if object_state({"kind": "ConfigMap", **listing["items"][0]}, fixture) != restored_state:
            lab.block("Raw API list did not return the same restored fixture")
        restored_revision = int(revision)
        revision_bump_observed = restored_revision >= original_revision + REVISION_BUMP
        lab.check(
            "green", "After rejection, the verified backup restores the pre-change object through the Kubernetes API",
            restored_state["state"] == fixture["object"]["before_backup"]
            and restored_state["uid"] == before["uid"]
            and node_ready and revision_bump_observed,
            {"restored_state": restored_state["state"], "pre_backup_uid_preserved": restored_state["uid"] == before["uid"],
             "control_plane_node_ready": node_ready, "nonzero_snapshot_revision": original_revision > 0,
             "revision_bump_observed": revision_bump_observed, "revision_compaction_requested": True},
        )
        current = object_state(api_object(lab), fixture)
        lab.check(
            "positive", "The API continues serving the restored baseline after control-plane readiness",
            current == restored_state and current["state"] == fixture["object"]["before_backup"]
            and current["fixture_label"] == "synthetic-etcd-recovery",
            {"api_readback_matches_restore": current == restored_state,
             "current_fixture_state": current["state"], "no_workloads_created": True,
             "credential_objects_queried": False},
        )

        evidence = {
            "control_id": CONTROL_ID,
            "cluster_profile": "single-node-disposable-kind-v1.36.1",
            "kind_node_image": NODE_IMAGE,
            "etcd_image": ETCD_IMAGE,
            "recovery_image": ETCD_IMAGE,
            "fixture": {"kind": "ConfigMap", "namespace": NAMESPACE,
                        "name": OBJECT_NAME, "synthetic_only": True},
            "snapshot_sha256": trusted_digest,
            "snapshot_revision": original_revision,
            "restored_list_revision": restored_revision,
            "snapshot_bytes_recorded": False,
            "snapshot_content_exported": False,
            "credentials_read_or_exported": False,
            "external_targets_contacted": False,
            "red_observation": {"truncated_backup_rejected": digest_rejected and native_rejected,
                                "restore_attempted": False, "api_sentinel_unchanged": unchanged},
            "recovery_observation": {"sentinel_before": before, "sentinel_after_mutation": after_backup,
                                     "sentinel_after_restore": restored_state,
                                     "control_plane_node_ready": node_ready},
            "checks": lab.checks,
        }
        (lab.evidence / "etcd-recovery-observations.raw.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )
