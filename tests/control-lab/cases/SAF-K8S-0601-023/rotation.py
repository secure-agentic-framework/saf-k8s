"""Bounded callback for the pinned 0601-022 registry/ESO fixture lifecycle."""
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import time
import tempfile


def _fail(message):
    raise RuntimeError(message)


def _target(helper, lab, secret_name):
    row = helper._quiet_secret(lab, secret_name)
    if not row or row.get("type") != "kubernetes.io/dockerconfigjson":
        return None, None, None
    encoded = row.get("data", {}).get(".dockerconfigjson", "")
    try:
        raw = base64.b64decode(encoded, validate=True)
        config = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None, None, None
    return row, raw, config


def _patch_provider(helper, lab, context, config):
    body = {"stringData": {"registry-config.json": json.dumps(config, sort_keys=True)}}
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="provider-patch-",
                                     suffix=".json", dir=context.htpasswd_path.parent) as patch_file:
        json.dump(body, patch_file)
        patch_file.flush()
        result = helper._quiet_kubectl(
            lab, "patch", "secret", context.provider_data_secret, "--type=merge",
            "--patch-file", patch_file.name, "-o", "name", timeout=20)
        if result.returncode:
            _fail("case-owned provider source update failed")


def _status_for_auth(port, entry):
    username = entry.get("username")
    password = entry.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        _fail("case-owned registry credential shape is unexpected")
    basic = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", "/v2/", headers={"Authorization": "Basic " + basic})
        response = connection.getresponse()
        status = response.status
        response.read(0)
        return status
    except OSError as error:
        raise RuntimeError("owned loopback registry comparison failed") from error
    finally:
        connection.close()


def _replace_registry_password(helper, lab, context, old_entry):
    path = Path(context.htpasswd_path).resolve(strict=True)
    owner = path.parent
    temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
    if (path.name != "htpasswd" or owner.parent != temp_root
            or not owner.name.startswith("saf-0601-022-pull-") or not path.is_file()):
        _fail("registry auth file is outside its exact case-owned temporary directory")
    username = old_entry.get("username")
    if not isinstance(username, str) or not username or ":" in username:
        _fail("case-owned registry principal shape is unexpected")
    new_password = secrets.token_urlsafe(32)
    result = helper._quiet(["htpasswd", "-B", "-n", "-i", username], env=lab.env,
                           input_text=new_password + "\n", timeout=15)
    line = result.stdout.rstrip("\n")
    account, separator, encoded_hash = line.partition(":")
    if not separator or account != username or not encoded_hash.startswith("$2"):
        _fail("case-owned bcrypt credential generation did not match the expected form")

    before = path.stat()
    path.write_text(line + "\n", encoding="utf-8")
    path.chmod(0o600)
    after = path.stat()
    if before.st_ino != after.st_ino or before.st_mtime_ns == after.st_mtime_ns:
        _fail("registry auth file did not change in place with a new mtime")

    encoded = base64.b64encode(f"{username}:{new_password}".encode("utf-8")).decode("ascii")
    new_entry = {"username": username, "password": new_password, "auth": encoded}
    return {"auths": {context.registry_alias + ":5000": new_entry}}, new_entry


def _refresh_status(helper, lab, context, old_fingerprint, new_config, rotated_at,
                    provider_rows_before):
    deadline = time.monotonic() + 150
    accepted_read = {"path": "/fixture-registry-auth", "status": 200}
    previous_reads = provider_rows_before.count(accepted_read)
    while time.monotonic() < deadline:
        row, raw, observed = _target(helper, lab, context.secret_name)
        owner_match = bool(row and any(
            ref.get("kind") == "ExternalSecret" and ref.get("name") == context.external_secret_name
            for ref in row.get("metadata", {}).get("ownerReferences", [])))
        condition = helper._external_secret_condition(lab, context.external_secret_name)
        external = helper._quiet_kubectl(
            lab, "get", "externalsecret", context.external_secret_name, "-o", "json",
            timeout=15, allow_failure=True)
        refresh_advanced = False
        if external.returncode == 0:
            try:
                status = json.loads(external.stdout).get("status", {})
                refresh_time = datetime.fromisoformat(status["refreshTime"].replace("Z", "+00:00"))
                refresh_advanced = refresh_time > rotated_at
            except (KeyError, ValueError, TypeError):
                refresh_advanced = False
        rows = helper._provider_rows(lab)
        provider_ok = rows.count(accepted_read) > previous_reads
        exact_new = observed == new_config
        fingerprint_changed = bool(raw and hashlib.sha256(raw).hexdigest() != old_fingerprint)
        if (condition == "True" and owner_match and refresh_advanced and provider_ok
                and exact_new and fingerprint_changed):
            return True, {"owner_match": owner_match, "ready": True,
                          "provider_200_after_rotation": provider_ok,
                          "refresh_time_after_rotation": refresh_advanced,
                          "target_fingerprint_changed": fingerprint_changed,
                          "target_matches_new_fixture_value": exact_new}
        time.sleep(2)
    return False, {"owner_match": owner_match, "ready": condition == "True",
                   "provider_200_after_rotation": provider_ok,
                   "refresh_time_after_rotation": refresh_advanced,
                   "target_fingerprint_changed": fingerprint_changed,
                   "target_matches_new_fixture_value": exact_new}


def _registry_logs(helper, lab, context):
    result = helper._quiet(["docker", "logs", context.registry_container],
                           env=lab.env, timeout=15)
    return helper._registry_records(result.stdout)


def _remove_exact_cached_pull(helper, lab, context):
    name = "private-pull-correct-credential"
    pod = helper._get_pod_quiet(lab, name)
    if not pod:
        _fail("the initial case-owned successful pull Pod is missing")
    uid = pod.get("metadata", {}).get("uid")
    if not uid:
        _fail("the initial pull Pod has no observed UID")
    deleted = helper._quiet_kubectl(
        lab, "delete", "pod", name, "--wait=true", "--timeout=45s", timeout=55)
    if deleted.returncode:
        _fail("the initial case-owned pull Pod did not delete cleanly")

    listing = helper._quiet(["docker", "exec", context.node_container,
                             "crictl", "ps", "-a", "-o", "json"],
                            env=lab.env, timeout=20)
    try:
        containers = json.loads(listing.stdout).get("containers", [])
    except json.JSONDecodeError as error:
        raise RuntimeError("owned node container inventory was not JSON") from error
    exact = [row for row in containers
             if row.get("labels", {}).get("io.kubernetes.pod.uid") == uid]
    for row in exact:
        if row.get("state") not in {"CONTAINER_EXITED", "CONTAINER_CREATED"}:
            _fail("case-owned pull container is not stopped before cache removal")
        container_id = row.get("id")
        if not isinstance(container_id, str) or not container_id:
            _fail("case-owned pull container has no exact runtime ID")
        removed_container = helper._quiet(
            ["docker", "exec", context.node_container, "crictl", "rm", container_id],
            env=lab.env, timeout=20, allow_failure=True)
        if removed_container.returncode:
            _fail("exact stopped case-owned pull container removal failed")
    removed_image = helper._quiet(
        ["docker", "exec", context.node_container, "crictl", "rmi", context.image_ref],
        env=lab.env, timeout=30, allow_failure=True)
    return (removed_image.returncode == 0
            and not helper._node_has_digest(lab, context.node_container, context.digest))


def _registry_port(helper, lab, context):
    result = helper._quiet(["docker", "port", context.registry_container, "5000/tcp"],
                           env=lab.env, timeout=15)
    rows = result.stdout.strip().splitlines()
    if len(rows) != 1:
        _fail("owned registry port is not a single loopback mapping")
    match = re.fullmatch(r"127\.0\.0\.1:(\d+)", rows[0])
    if not match or int(match.group(1)) != context.host_port:
        _fail("owned registry mapping changed from its case-created loopback port")
    return int(match.group(1))


def rotate_and_verify(lab, helper, context):
    """Rotate only the synthetic fixture credential, then prove refresh and pull."""
    old_secret, old_raw, old_config = _target(helper, lab, context.secret_name)
    if not old_secret or not old_config:
        _fail("existing case-owned pull Secret is not readable as dockerconfigjson")
    auths = old_config.get("auths", {})
    registry_key = context.registry_alias + ":5000"
    if set(auths) != {registry_key}:
        _fail("pull Secret is not scoped to the exact owned registry alias")
    old_entry = auths[registry_key]
    old_fingerprint = hashlib.sha256(old_raw).hexdigest()

    external = helper._quiet_kubectl(
        lab, "get", "externalsecret", context.external_secret_name, "-o", "json", timeout=15)
    old_external = json.loads(external.stdout)
    old_refresh = old_external.get("status", {}).get("refreshTime")
    if not old_refresh:
        _fail("ESO fixture did not publish an initial refreshTime")

    provider_rows_before = helper._provider_rows(lab)
    interval_patch = {"spec": {"refreshInterval": "5s", "refreshPolicy": "Periodic"}}
    patch = helper._quiet_kubectl(
        lab, "patch", "externalsecret", context.external_secret_name,
        "--type=merge", "-p", json.dumps(interval_patch), timeout=20)
    if patch.returncode:
        _fail("bounded Periodic refresh interval could not be configured")

    new_config, new_entry = _replace_registry_password(helper, lab, context, old_entry)
    rotated_at = datetime.now(timezone.utc)
    _patch_provider(helper, lab, context, new_config)

    # Distribution v3.0.0's htpasswd authenticator reloads the file when its
    # modification time changes. Use its bound loopback endpoint, old first to
    # force the re-read, then the new value; retain status only.
    port = _registry_port(helper, lab, context)
    auth_log_before = _registry_logs(helper, lab, context)
    old_status = _status_for_auth(port, old_entry)
    new_status = _status_for_auth(port, new_entry)
    auth_log_delta = helper._record_delta(auth_log_before, _registry_logs(helper, lab, context))
    old_logged = any(method == "GET" and uri == "/v2/" and status == 401
                     for method, uri, status in auth_log_delta)
    new_logged = any(method == "GET" and uri == "/v2/" and status == 200
                     for method, uri, status in auth_log_delta)

    refreshed, refresh_observed = _refresh_status(
        helper, lab, context, old_fingerprint, new_config, rotated_at, provider_rows_before)
    lab.check("green", "Periodic ESO reconciliation refreshes the scoped pull Secret and the registry retires the old fixture credential",
              refreshed and old_status == 401 and new_status == 200 and old_logged and new_logged,
              {**refresh_observed, "retired_credential_http_status": old_status,
               "rotated_credential_http_status": new_status,
               "registry_401_and_200_access_records": old_logged and new_logged})

    # Remove only the exited initial Pod and its exact image from the owned
    # node, forcing kubelet to use the refreshed Secret on the next Pod.
    cache_clear = _remove_exact_cached_pull(helper, lab, context)
    before_pull = _registry_logs(helper, lab, context)
    name = "private-pull-after-rotation"
    lab.create(helper._private_image_pod(name, context.image_ref, context.secret_name))
    pulled = helper._wait_private_pod(lab, name, timeout=90) or {}
    phase = pulled.get("status", {}).get("phase")
    output = helper._quiet_kubectl(lab, "logs", name, timeout=20, allow_failure=True)
    log_delta = helper._record_delta(before_pull, _registry_logs(helper, lab, context))
    manifest_200 = any(method == "GET" and uri == f"/v2/{context.repository}/manifests/{context.digest}"
                       and status == 200 for method, uri, status in log_delta)
    exact_digest = helper._node_has_private_reference(
        lab, context.node_container, context.image_ref, context.digest)
    refreshed_secret, refreshed_raw, refreshed_value = _target(helper, lab, context.secret_name)
    still_rotated = (refreshed_value == new_config and refreshed_raw is not None
                     and hashlib.sha256(refreshed_raw).hexdigest() != old_fingerprint)
    lab.check("positive", "A new Pod pulls the exact image digest after cache removal using the refreshed Kubernetes Secret",
              cache_clear and phase == "Succeeded" and output.returncode == 0
              and output.stdout.strip() == "private-pull-ok" and manifest_200 and exact_digest
              and still_rotated,
              {"exact_fixture_digest_removed_before_pull": cache_clear,
               "new_pod_succeeded": phase == "Succeeded",
               "private_marker_observed": output.returncode == 0 and output.stdout.strip() == "private-pull-ok",
               "registry_manifest_200": manifest_200,
               "exact_registry_digest_observed": exact_digest,
               "refreshed_secret_remains_current": still_rotated})
