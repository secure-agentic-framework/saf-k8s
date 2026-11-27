"""Exercise scoped node-taint scheduling and parse fictional onboarding evidence."""
import base64
import hashlib
import json
import re
import secrets
from pathlib import Path
import tempfile
import time


HERE = Path(__file__).resolve().parent
FIXTURE_PATH = HERE / "fixtures" / "evidence.json"
LABEL = "saf-k8s.example/control-1007-016-candidate"
TAINT = "saf-k8s.example/gpu-candidate"
WORKLOAD_LABEL = "saf-k8s.example/control-1007-016-workload"
OPENSSL = "/usr/bin/openssl"
OPENSSL_MINIMUM = {"OpenSSL": (1, 1, 1), "LibreSSL": (3, 3, 6)}
ATTESTATION_SCHEMA = "urn:example:saf-k8s:attestation-test:v1"
PAUSE_IMAGE = (
    "registry.k8s.io/pause:3.10.1@sha256:"
    "278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
)
SCOPE = (
    "One disposable default-layout Kind v1.36.1 node. The case labels that node as a synthetic candidate, "
    "observes an inert digest-pinned pause Pod schedule before a fixture-scoped NoSchedule taint, then "
    "observes an untolerating Pod remain unscheduled and a tolerating Pod receive a scheduler-assigned "
    "nodeName. It parses local fictional attestation and driver-evidence JSON fixtures and records mock "
    "eligibility decisions. This does not provision or identify GPU hardware, install or inspect a driver, "
    "cryptographically attest hardware, verify a real driver or checksum, integrate production trust roots, "
    "or establish production label/taint authority. A separate test-only exact-byte RSA signature check uses "
    "a per-run ephemeral key and the actual Kind Node UID plus fresh nonce; it does not represent hardware attestation."
)


def read_fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def assess_evidence(attestation, driver, node_alias):
    """Parse fixture fields only; no cryptographic or host verification is performed."""
    attestation_ok = (
        attestation.get("schema") == "urn:example:saf-k8s:attestation-fixture:v1"
        and attestation.get("source_kind") == "synthetic-fixture"
        and attestation.get("subject") == node_alias
        and attestation.get("fixture_result") == "pass"
        and attestation.get("verification_performed") is False
    )
    digest_shape_ok = all(
        isinstance(driver.get(field), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", driver[field]) is not None
        for field in ("observed_digest", "approved_digest")
    )
    driver_ok = (
        driver.get("schema") == "urn:example:saf-k8s:driver-fixture:v1"
        and driver.get("source_kind") == "synthetic-fixture"
        and driver.get("subject") == node_alias
        and driver.get("component") == "mock-gpu-driver"
        and driver.get("fixture_result") == "pass"
        and digest_shape_ok
        and driver.get("observed_digest") == driver.get("approved_digest")
    )
    return {
        "decision": "eligible" if attestation_ok and driver_ok else "hold",
        "evidence_class": "synthetic-fixture-only",
        "attestation_fields_match_fixture_contract": attestation_ok,
        "driver_fields_match_fixture_contract": driver_ok,
        "cryptographic_attestation_verified": False,
        "host_driver_or_checksum_inspected": False,
    }


def pod(name, *, tolerates_candidate_taint, existing_tolerations):
    spec = {
        "automountServiceAccountToken": False,
        "restartPolicy": "Never",
        "nodeSelector": {LABEL: "true"},
        "containers": [{"name": "inert", "image": PAUSE_IMAGE,
                        "imagePullPolicy": "IfNotPresent"}],
    }
    spec["tolerations"] = list(existing_tolerations)
    # Tolerate only the exact taints already present before this case adds its own,
    # so scheduler outcomes isolate the fixture-scoped taint.
    if tolerates_candidate_taint:
        spec["tolerations"].append({
            "key": TAINT, "operator": "Equal", "value": "reserved", "effect": "NoSchedule",
        })
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "labels": {WORKLOAD_LABEL: "synthetic"}},
        "spec": spec,
    }


def as_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def save_raw(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                                     encoding="utf-8")


def pod_record(lab, name):
    return as_json(lab, "get", "pod", name)


def wait_for(lab, name, predicate, seconds=30):
    end = time.monotonic() + seconds
    record = pod_record(lab, name)
    while time.monotonic() < end:
        if predicate(record):
            return record
        time.sleep(0.5)
        record = pod_record(lab, name)
    return record


def scheduled(record):
    return bool(record.get("spec", {}).get("nodeName"))


def unschedulable_for_fixture_taint(record):
    status = record.get("status", {})
    condition = next((item for item in status.get("conditions", [])
                      if item.get("type") == "PodScheduled"), {})
    message = condition.get("message", "").lower()
    return (not scheduled(record) and condition.get("status") == "False"
            and condition.get("reason") == "Unschedulable"
            and "untolerated taint" in message)


def safe_node_observation(node):
    metadata = node.get("metadata", {})
    status = node.get("status", {})
    return {
        "name": metadata.get("name"),
        "uid": metadata.get("uid"),
        "candidate_label": metadata.get("labels", {}).get(LABEL),
        "taints": [taint for taint in node.get("spec", {}).get("taints", [])
                   if taint.get("key") == TAINT],
        "ready": any(condition.get("type") == "Ready" and condition.get("status") == "True"
                     for condition in status.get("conditions", [])),
    }


def safe_pod_observation(record):
    spec = record.get("spec", {})
    status = record.get("status", {})
    condition = next((item for item in status.get("conditions", [])
                      if item.get("type") == "PodScheduled"), {})
    return {
        "name": record.get("metadata", {}).get("name"),
        "node_name": spec.get("nodeName"),
        "phase": status.get("phase"),
        "scheduled_condition": {key: condition.get(key) for key in ("status", "reason", "message")
                                if key in condition},
        "image": spec.get("containers", [{}])[0].get("image"),
        "tolerations": spec.get("tolerations", []),
    }


def openssl_version_supported(version):
    match = re.match(r"^(OpenSSL|LibreSSL)\s+(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        return False
    provider = match.group(1)
    observed = tuple(int(match.group(index)) for index in (2, 3, 4))
    return observed >= OPENSSL_MINIMUM[provider]


def canonical_attestation(subject_uid, nonce):
    record = {
        "schema": ATTESTATION_SCHEMA,
        "purpose": "fixture-only-node-onboarding-authorization",
        "test_only": True,
        "subject_node_uid": subject_uid,
        "nonce": nonce,
    }
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_bytes(lab, private_key, directory, name, message):
    message_path = directory / f"{name}.envelope.json"
    signature_path = directory / f"{name}.sig"
    message_path.write_bytes(message)
    lab.command(OPENSSL, "dgst", "-sha256", "-sign", str(private_key),
                "-out", str(signature_path), str(message_path), timeout=15)
    return message_path, signature_path


def verify_test_attestation(lab, public_key, directory, name, message, signature,
                            expected_uid, expected_nonce, used_nonces):
    message_path = directory / f"verify-{name}.envelope.json"
    signature_path = directory / f"verify-{name}.sig"
    message_path.write_bytes(message)
    signature_path.write_bytes(signature)
    verified = lab.command(OPENSSL, "dgst", "-sha256", "-verify", str(public_key),
                           "-signature", str(signature_path), str(message_path),
                           timeout=15, allow_failure=True)
    cryptographic_valid = verified.returncode == 0 and "Verified OK" in verified.stdout
    output = {"cryptographic_signature_valid": cryptographic_valid,
              "openssl_returncode": verified.returncode}
    if not cryptographic_valid:
        return {**output, "decision": "hold", "reason": "signature-invalid"}
    try:
        record = json.loads(message.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {**output, "decision": "hold", "reason": "envelope-invalid"}
    if not isinstance(record, dict):
        return {**output, "decision": "hold", "reason": "envelope-invalid"}
    if record.get("schema") != ATTESTATION_SCHEMA or record.get("test_only") is not True:
        return {**output, "decision": "hold", "reason": "schema-invalid"}
    if record.get("subject_node_uid") != expected_uid:
        return {**output, "decision": "hold", "reason": "subject-mismatch"}
    if record.get("nonce") != expected_nonce:
        return {**output, "decision": "hold", "reason": "nonce-mismatch"}
    if expected_nonce in used_nonces:
        return {**output, "decision": "hold", "reason": "nonce-replay"}
    used_nonces.add(expected_nonce)
    return {**output, "decision": "authorized-test-fixture", "reason": "signature-subject-nonce-valid"}


def held_observation(lab, node_name, pod_name, pod_uid):
    node = as_json(lab, "get", "node", node_name)
    pod_state = pod_record(lab, pod_name)
    taints = safe_node_observation(node)["taints"]
    taint_present = taints == [{"key": TAINT, "value": "reserved", "effect": "NoSchedule"}]
    pending_same_pod = (pod_state.get("metadata", {}).get("uid") == pod_uid
                        and not scheduled(pod_state)
                        and pod_state.get("status", {}).get("phase") == "Pending")
    scheduler_reports_taint = unschedulable_for_fixture_taint(pod_state)
    return {"taint_present": taint_present, "same_pod_uid_pending": pending_same_pod,
            "scheduler_reports_case_taint": scheduler_reports_taint}


def run_signed_authorization(lab, node_name, node_uid, existing_tolerations):
    """Verify a test-only envelope, then release only this case's scheduler hold."""
    version = lab.command(OPENSSL, "version", timeout=10).stdout.strip()
    if not openssl_version_supported(version):
        lab.block(f"OpenSSL-compatible CLI must be OpenSSL >=1.1.1 or LibreSSL >=3.3.6; observed {version!r}")
    probe_name = "saf-1007-016-signed-authorization-probe"
    created = lab.create(pod(probe_name, tolerates_candidate_taint=False,
                             existing_tolerations=existing_tolerations))
    probe_uid = created["metadata"]["uid"]
    pending = wait_for(lab, probe_name, unschedulable_for_fixture_taint)
    if (pending.get("metadata", {}).get("uid") != probe_uid or scheduled(pending)
            or not unschedulable_for_fixture_taint(pending)):
        lab.block("Signed authorization probe did not remain Pending under the case taint")

    primary_nonce = secrets.token_hex(16)
    wrong_nonce = secrets.token_hex(16)
    replay_nonce = secrets.token_hex(16)
    wrong_node = "urn:fixture:wrong-node-subject"
    with tempfile.TemporaryDirectory(prefix="saf-1007-016-test-key-") as temp:
        directory = Path(temp)
        directory.chmod(0o700)
        private_key = directory / "test-private.pem"
        public_key = directory / "test-trust-root.pem"
        lab.command(OPENSSL, "genrsa", "-out", str(private_key), "2048", timeout=30)
        private_key.chmod(0o600)
        lab.command(OPENSSL, "rsa", "-in", str(private_key), "-pubout", "-out", str(public_key), timeout=15)
        public_pem = public_key.read_bytes()

        valid_message = canonical_attestation(node_uid, primary_nonce)
        valid_message_path, valid_signature_path = sign_bytes(lab, private_key, directory, "valid", valid_message)
        valid_signature = valid_signature_path.read_bytes()
        untrusted_private_key = directory / "untrusted-private.pem"
        untrusted_public_key = directory / "untrusted-public.pem"
        lab.command(OPENSSL, "genrsa", "-out", str(untrusted_private_key), "2048", timeout=30)
        untrusted_private_key.chmod(0o600)
        lab.command(OPENSSL, "rsa", "-in", str(untrusted_private_key), "-pubout",
                    "-out", str(untrusted_public_key), timeout=15)
        untrusted_signature_path = directory / "untrusted-root.sig"
        lab.command(OPENSSL, "dgst", "-sha256", "-sign", str(untrusted_private_key),
                    "-out", str(untrusted_signature_path), str(valid_message_path), timeout=15)
        untrusted_signature = untrusted_signature_path.read_bytes()
        untrusted_self_verify = lab.command(
            OPENSSL, "dgst", "-sha256", "-verify", str(untrusted_public_key),
            "-signature", str(untrusted_signature_path), str(valid_message_path),
            timeout=15, allow_failure=True)
        untrusted_signature_valid = (untrusted_self_verify.returncode == 0
                                     and "Verified OK" in untrusted_self_verify.stdout)

        bad_signature = bytearray(valid_signature)
        bad_signature[-1] ^= 1
        wrong_nonce_message = canonical_attestation(node_uid, wrong_nonce)
        _, wrong_nonce_signature_path = sign_bytes(lab, private_key, directory, "wrong-nonce", wrong_nonce_message)
        wrong_node_message = canonical_attestation(wrong_node, primary_nonce)
        _, wrong_node_signature_path = sign_bytes(lab, private_key, directory, "wrong-node", wrong_node_message)
        wrong_shape_message = b"[]"
        _, wrong_shape_signature_path = sign_bytes(lab, private_key, directory, "wrong-shape", wrong_shape_message)
        replay_message = canonical_attestation(node_uid, replay_nonce)
        _, replay_signature_path = sign_bytes(lab, private_key, directory, "replay", replay_message)

        primary_seen = set()
        replay_seen = set()
        cases = {}
        cases["bad_signature"] = verify_test_attestation(
            lab, public_key, directory, "bad-signature", valid_message, bytes(bad_signature),
            node_uid, primary_nonce, primary_seen)
        held_after_bad_sig = held_observation(lab, node_name, probe_name, probe_uid)
        cases["wrong_nonce"] = verify_test_attestation(
            lab, public_key, directory, "wrong-nonce", wrong_nonce_message,
            wrong_nonce_signature_path.read_bytes(), node_uid, primary_nonce, primary_seen)
        held_after_wrong_nonce = held_observation(lab, node_name, probe_name, probe_uid)
        cases["wrong_node"] = verify_test_attestation(
            lab, public_key, directory, "wrong-node", wrong_node_message,
            wrong_node_signature_path.read_bytes(), node_uid, primary_nonce, primary_seen)
        held_after_wrong_node = held_observation(lab, node_name, probe_name, probe_uid)
        cases["wrong_trust_root"] = verify_test_attestation(
            lab, public_key, directory, "wrong-trust-root", valid_message,
            untrusted_signature, node_uid, primary_nonce, primary_seen)
        held_after_wrong_root = held_observation(lab, node_name, probe_name, probe_uid)
        cases["wrong_shape"] = verify_test_attestation(
            lab, public_key, directory, "wrong-shape", wrong_shape_message,
            wrong_shape_signature_path.read_bytes(), node_uid, primary_nonce, primary_seen)
        held_after_wrong_shape = held_observation(lab, node_name, probe_name, probe_uid)
        replay_first = verify_test_attestation(
            lab, public_key, directory, "replay-first", replay_message,
            replay_signature_path.read_bytes(), node_uid, replay_nonce, replay_seen)
        cases["replay"] = verify_test_attestation(
            lab, public_key, directory, "replay-repeat", replay_message,
            replay_signature_path.read_bytes(), node_uid, replay_nonce, replay_seen)
        held_after_replay = held_observation(lab, node_name, probe_name, probe_uid)
        valid = verify_test_attestation(
            lab, public_key, directory, "valid", valid_message, valid_signature,
            node_uid, primary_nonce, primary_seen)

        raw_cases = {
            "valid": {"envelope_utf8": valid_message.decode("utf-8"),
                      "envelope_sha256": hashlib.sha256(valid_message).hexdigest(),
                      "signature_base64": base64.b64encode(valid_signature).decode("ascii"),
                      "verification": valid},
            "bad_signature": {"envelope_utf8": valid_message.decode("utf-8"),
                              "envelope_sha256": hashlib.sha256(valid_message).hexdigest(),
                              "signature_base64": base64.b64encode(bytes(bad_signature)).decode("ascii"),
                              "verification": cases["bad_signature"], "held_state": held_after_bad_sig},
            "wrong_nonce": {"envelope_utf8": wrong_nonce_message.decode("utf-8"),
                            "envelope_sha256": hashlib.sha256(wrong_nonce_message).hexdigest(),
                            "signature_base64": base64.b64encode(wrong_nonce_signature_path.read_bytes()).decode("ascii"),
                            "verification": cases["wrong_nonce"], "held_state": held_after_wrong_nonce},
            "wrong_node": {"envelope_utf8": wrong_node_message.decode("utf-8"),
                           "envelope_sha256": hashlib.sha256(wrong_node_message).hexdigest(),
                           "signature_base64": base64.b64encode(wrong_node_signature_path.read_bytes()).decode("ascii"),
                           "verification": cases["wrong_node"], "held_state": held_after_wrong_node},
            "wrong_trust_root": {"envelope_utf8": valid_message.decode("utf-8"),
                                 "envelope_sha256": hashlib.sha256(valid_message).hexdigest(),
                                 "signature_base64": base64.b64encode(untrusted_signature).decode("ascii"),
                                 "untrusted_public_key_sha256": hashlib.sha256(untrusted_public_key.read_bytes()).hexdigest(),
                                 "signature_valid_under_untrusted_key": untrusted_signature_valid,
                                 "verification_under_approved_root": cases["wrong_trust_root"],
                                 "held_state": held_after_wrong_root},
            "wrong_shape": {"envelope_utf8": wrong_shape_message.decode("utf-8"),
                            "envelope_sha256": hashlib.sha256(wrong_shape_message).hexdigest(),
                            "signature_base64": base64.b64encode(wrong_shape_signature_path.read_bytes()).decode("ascii"),
                            "verification": cases["wrong_shape"], "held_state": held_after_wrong_shape},
            "replay_first": {"envelope_utf8": replay_message.decode("utf-8"),
                             "envelope_sha256": hashlib.sha256(replay_message).hexdigest(),
                             "signature_base64": base64.b64encode(replay_signature_path.read_bytes()).decode("ascii"),
                             "verification": replay_first},
            "replay_repeat": {"envelope_utf8": replay_message.decode("utf-8"),
                              "envelope_sha256": hashlib.sha256(replay_message).hexdigest(),
                              "signature_base64": base64.b64encode(replay_signature_path.read_bytes()).decode("ascii"),
                              "verification": cases["replay"], "held_state": held_after_replay},
        }
        raw = {"evidence_class": "test-only ephemeral RSA trust root; not hardware attestation",
               "openssl_version": version, "trust_root_pem": public_pem.decode("ascii"),
               "trust_root_sha256": hashlib.sha256(public_pem).hexdigest(),
               "node_uid": node_uid, "primary_nonce": primary_nonce,
               "probe_uid": probe_uid, "probe_name": probe_name,
               "cases": raw_cases,
               "untrusted_public_key_sha256": hashlib.sha256(untrusted_public_key.read_bytes()).hexdigest(),
               "untrusted_signature_valid_under_its_key": untrusted_signature_valid}
        negative_holds = all(
            cases[name]["decision"] == "hold" and held_state == {
                "taint_present": True, "same_pod_uid_pending": True,
                "scheduler_reports_case_taint": True}
            for name, held_state in (("bad_signature", held_after_bad_sig),
                                     ("wrong_nonce", held_after_wrong_nonce),
                                     ("wrong_node", held_after_wrong_node),
                                     ("wrong_trust_root", held_after_wrong_root),
                                     ("wrong_shape", held_after_wrong_shape),
                                     ("replay", held_after_replay)))
        lab.check("green", "Invalid signed attestations keep the scoped node tainted and the same probe Pending",
                  negative_holds and replay_first["decision"] == "authorized-test-fixture"
                  and cases["bad_signature"]["reason"] == "signature-invalid"
                  and cases["wrong_nonce"]["reason"] == "nonce-mismatch"
                  and cases["wrong_node"]["reason"] == "subject-mismatch"
                  and cases["wrong_trust_root"]["reason"] == "signature-invalid"
                  and cases["wrong_shape"]["reason"] == "envelope-invalid"
                  and untrusted_signature_valid
                  and cases["replay"]["reason"] == "nonce-replay",
                  {"bad_signature_held": negative_holds,
                   "wrong_nonce_signature_valid": cases["wrong_nonce"]["cryptographic_signature_valid"],
                   "wrong_node_signature_valid": cases["wrong_node"]["cryptographic_signature_valid"],
                   "wrong_root_signature_valid_under_untrusted_key": untrusted_signature_valid,
                   "wrong_root_rejected_under_approved_key": cases["wrong_trust_root"]["reason"] == "signature-invalid",
                   "valid_nonobject_json_held": cases["wrong_shape"]["reason"] == "envelope-invalid",
                   "replay_first_accepted_then_repeat_rejected": replay_first["decision"] == "authorized-test-fixture"
                   and cases["replay"]["decision"] == "hold"})
        pre_release_node = as_json(lab, "get", "node", node_name)
        pre_release_observation = safe_node_observation(pre_release_node)
        node_uid_matches_before_release = pre_release_node.get("metadata", {}).get("uid") == node_uid
        held_before_release = (pre_release_observation["candidate_label"] == "true"
                               and pre_release_observation["taints"] == [
                                   {"key": TAINT, "value": "reserved", "effect": "NoSchedule"}])
        raw.update({"node_observation_before_release": pre_release_observation,
                    "node_uid_matches_before_release": node_uid_matches_before_release,
                    "held_before_release": held_before_release})
        save_raw(lab, "signed-test-authorization.raw.json", raw)
        authorization_valid = (valid["decision"] == "authorized-test-fixture"
                               and valid["cryptographic_signature_valid"]
                               and node_uid_matches_before_release and held_before_release)
        lab.check("positive", "Exact-byte signature authorizes only the current Node UID and fresh nonce",
                  authorization_valid,
                  {"signature_valid": valid["cryptographic_signature_valid"],
                   "subject_and_nonce_bound": valid["reason"] == "signature-subject-nonce-valid",
                   "node_uid_matches_before_release": node_uid_matches_before_release,
                   "case_hold_present_before_release": held_before_release,
                   "ephemeral_test_root": True})
        if not authorization_valid:
            lab.block("Valid fixture signature did not authorize the scoped test decision")

    # The short-lived private key is deleted before the authorization affects scheduling.
    lab.kubectl("taint", "node", node_name, f"{TAINT}-")
    cleared_node = as_json(lab, "get", "node", node_name)
    cleared_observation = safe_node_observation(cleared_node)
    case_taint_absent = not cleared_observation["taints"]
    node_uid_matches_after_release = cleared_node.get("metadata", {}).get("uid") == node_uid
    authorized_probe = wait_for(lab, probe_name, scheduled)
    same_probe = (authorized_probe.get("metadata", {}).get("uid") == probe_uid
                  and authorized_probe.get("spec", {}).get("nodeName") == node_name)
    post_schedule_node = as_json(lab, "get", "node", node_name)
    node_uid_matches_after_scheduling = post_schedule_node.get("metadata", {}).get("uid") == node_uid
    lab.check("positive", "Valid signed test authorization clears only the case taint and schedules the same probe",
              case_taint_absent and same_probe and node_uid_matches_after_release and node_uid_matches_after_scheduling,
              {"case_taint_absent": case_taint_absent, "same_probe_uid_scheduled_to_candidate": same_probe,
               "node_uid_matches_after_release": node_uid_matches_after_release,
               "node_uid_matches_after_scheduling": node_uid_matches_after_scheduling})
    lab.kubectl("delete", "pod", probe_name, "--wait=true", timeout=20)
    lab.kubectl("label", "node", node_name, f"{LABEL}-", timeout=15)
    cleanup_node = as_json(lab, "get", "node", node_name)
    cleanup_observation = safe_node_observation(cleanup_node)
    missing_pod = lab.kubectl("get", "pod", probe_name, timeout=10, allow_failure=True)
    probe_absent = missing_pod.returncode != 0 and "notfound" in (missing_pod.stderr + missing_pod.stdout).lower()
    cleanup_ok = (cleanup_node.get("metadata", {}).get("uid") == node_uid
                  and cleanup_observation["candidate_label"] is None
                  and not cleanup_observation["taints"] and probe_absent)
    raw.update({"node_observation_after_scheduling": safe_node_observation(post_schedule_node),
                "signed_probe_after_scheduling": safe_pod_observation(authorized_probe),
                "node_uid_matches_after_release": node_uid_matches_after_release,
                "node_uid_matches_after_scheduling": node_uid_matches_after_scheduling,
                "node_observation_after_cleanup": cleanup_observation,
                "probe_absent_after_cleanup": probe_absent,
                "cleanup_succeeded": cleanup_ok})
    save_raw(lab, "signed-test-authorization.raw.json", raw)
    lab.check("positive", "Scoped taint, candidate label and signed probe are cleaned up",
              cleanup_ok,
              {"case_taint_absent": not cleanup_observation["taints"],
               "candidate_label_absent": cleanup_observation["candidate_label"] is None,
               "probe_absent": probe_absent})


def run(lab):
    fixture = read_fixture()
    nodes = as_json(lab, "get", "nodes").get("items", [])
    if len(nodes) != 1:
        lab.block(f"Expected exactly one node in the default Kind profile; observed {len(nodes)}")
    node = nodes[0]
    node_name = node.get("metadata", {}).get("name")
    if not node_name:
        lab.block("Kind node has no API-observed name")
    existing_tolerations = []
    for taint in node.get("spec", {}).get("taints", []):
        if taint.get("key") == TAINT or taint.get("effect") not in ("NoSchedule", "NoExecute"):
            continue
        item = {"key": taint["key"], "operator": "Exists", "effect": taint["effect"]}
        if taint.get("value"):
            item.update(operator="Equal", value=taint["value"])
        existing_tolerations.append(item)
    lab.kubectl("label", "node", node_name, f"{LABEL}=true", "--overwrite")
    before_name = "saf-1007-016-before-taint"
    lab.create(pod(before_name, tolerates_candidate_taint=False,
                   existing_tolerations=existing_tolerations))
    before = wait_for(lab, before_name, scheduled)
    before_node = before.get("spec", {}).get("nodeName")
    lab.check("red", "Before the candidate taint, an inert Pod can schedule to the candidate node",
              before_node == node_name,
              {"scheduler_assigned_candidate_node": before_node == node_name,
               "fixture_taint_present": False})

    lab.kubectl("taint", "node", node_name, f"{TAINT}=reserved:NoSchedule")
    held_node = as_json(lab, "get", "node", node_name)
    case_taints = safe_node_observation(held_node)["taints"]
    held = case_taints == [{"key": TAINT, "value": "reserved", "effect": "NoSchedule"}]
    if not held:
        lab.block("The case-owned NoSchedule taint did not persist")
    denied_name = "saf-1007-016-no-toleration"
    lab.create(pod(denied_name, tolerates_candidate_taint=False,
                   existing_tolerations=existing_tolerations))
    denied = wait_for(lab, denied_name, unschedulable_for_fixture_taint)
    taint_denial = unschedulable_for_fixture_taint(denied)
    lab.check("green", "The scheduler leaves an untolerating candidate Pod unscheduled for the scoped taint",
              taint_denial and held,
              {"scheduler_reported_untolerated_taint": taint_denial,
               "scoped_taint_read_back": held, "node_name_empty": not scheduled(denied)})

    rejected_attestation = assess_evidence(fixture["negative_attestation"],
                                           fixture["driver_evidence"], fixture["node_alias"])
    rejected_driver = assess_evidence(fixture["attestation"],
                                      fixture["negative_driver_evidence"], fixture["node_alias"])
    allowed = assess_evidence(fixture["attestation"], fixture["driver_evidence"],
                              fixture["node_alias"])
    save_raw(lab, "synthetic-evidence-assessment.raw.json", {
        "fixture_notice": fixture["fixture_notice"],
        "node_alias": fixture["node_alias"],
        "negative_attestation_assessment": rejected_attestation,
        "negative_driver_assessment": rejected_driver,
        "positive_fixture_assessment": allowed,
    })
    negative_evidence_held = (
        rejected_attestation["decision"] == "hold"
        and not rejected_attestation["attestation_fields_match_fixture_contract"]
        and rejected_attestation["driver_fields_match_fixture_contract"]
        and rejected_driver["decision"] == "hold"
        and rejected_driver["attestation_fields_match_fixture_contract"]
        and not rejected_driver["driver_fields_match_fixture_contract"]
    )
    lab.check("green", "Synthetic attestation failure and driver digest mismatch each independently yield hold",
              negative_evidence_held,
              {"attestation_failure": rejected_attestation,
               "driver_digest_mismatch": rejected_driver})

    allowed_name = "saf-1007-016-mock-approved"
    if allowed["decision"] == "eligible":
        lab.create(pod(allowed_name, tolerates_candidate_taint=True,
                       existing_tolerations=existing_tolerations))
        approved = wait_for(lab, allowed_name, scheduled)
        approved_node = approved.get("spec", {}).get("nodeName")
    else:
        approved = {}
        approved_node = None
    lab.check("positive", "Matching synthetic fixture records permit an inert Pod that tolerates the taint to schedule",
              allowed["decision"] == "eligible" and approved_node == node_name,
              {"mock_decision": allowed["decision"], "scheduler_assigned_candidate_node": approved_node == node_name,
               "cryptographic_attestation_verified": False,
               "host_driver_or_checksum_inspected": False})

    current_node = as_json(lab, "get", "node", node_name)
    save_raw(lab, "scheduling-observations.raw.json", {
        "node": safe_node_observation(current_node),
        "before_taint": safe_pod_observation(before),
        "without_toleration": safe_pod_observation(denied),
        "mock_eligible_with_toleration": safe_pod_observation(approved) if approved else None,
        "scope_notice": "Only API-visible scheduling and fixture-scoped taint fields are recorded.",
    })
    # Preserve the original unschedulable comparator in its raw evidence, then remove it
    # so clearing the hold can schedule only the signed-phase probe.
    lab.kubectl("delete", "pod", denied_name, "--wait=true", timeout=20)
    run_signed_authorization(lab, node_name, node["metadata"]["uid"], existing_tolerations)
