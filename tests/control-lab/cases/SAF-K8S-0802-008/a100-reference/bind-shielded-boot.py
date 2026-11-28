"""Bind one reviewed signed-module capture to early and late Shielded VM boot results."""

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

SOURCE = "compute.googleapis.com%2Fshielded_vm_integrity"
EVENTS = ("startupEvent", "earlyBootReportEvent", "lateBootReportEvent")
SIGNER = "Canonical Ltd. Kernel Module Signing"
KEY_ID = "E9:DF:13:0F:92:92:A9:B7"


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def parse_time(value):
    return datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", value).replace("Z", "+00:00"))


def load(path):
    return json.loads(path.read_text())


def main(instance_path, raw_events_path, identity_path, modules_path, out):
    instance, raw_events, host = map(load, (instance_path, raw_events_path, modules_path))
    instance_label, boot_label, boot_id = identity_path.read_text().splitlines()
    instance_id = str(instance["id"])
    require(instance_label == f"instance_id={instance_id}", "Guest identity differs from instance record")
    require(re.fullmatch(r"boot_epoch_s=\d+", boot_label) and
            re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id),
            "Guest identity lacks a valid boot timestamp or boot ID")
    boot_utc = datetime.fromtimestamp(int(boot_label.split("=")[1]), timezone.utc)
    host_capture = parse_time(host["captured_at_utc"])
    boot_ref = sha256(boot_id.encode()).hexdigest()
    require(boot_ref == host.get("boot_ref_sha256") and host_capture > boot_utc,
            "Module capture was taken on another guest boot")
    shielded = instance["shieldedInstanceConfig"]
    require(all(shielded.get(key) is True for key in (
        "enableSecureBoot", "enableVtpm", "enableIntegrityMonitoring")), "Required Shielded VM settings are absent")
    require(host["schema"] == "saf-a100-loaded-signed-modules-v1" and
            all(host.get(key) is True for key in ("secure_boot_efi_variable", "mokutil_secure_boot",
                                                 "canonical_signer_label_in_builtin_trust")) and
            any(mode in host["kernel_lockdown"] for mode in ("[integrity]", "[confidentiality]")),
            "Secure Boot, kernel lockdown, or signer key evidence is absent")
    modules = host["modules"]
    require(len(modules) == 2 and {row["module"] for row in modules} == {"nvidia", "nvidia_uvm"},
            "Exact loaded modules not captured")
    for row in modules:
        require(row["signer"] == SIGNER and row["signing_key_id"] == KEY_ID and
                row["detached_signature_exact_match"] is True and row["loaded_version_matches"] is True and
                row["unsigned_module_taint_present"] is False and all(
                    re.fullmatch("[0-9a-f]{64}", row[key]) for key in
                    ("module_sha256", "distribution_signature_sha256")),
                "Module review failed the pinned signer, signature, or loaded-version checks")

    normalized = {}
    expected_project = instance["selfLink"].split("/projects/", 1)[1].split("/", 1)[0]
    expected_zone = instance["zone"].rsplit("/", 1)[1]
    for row in raw_events:
        resource = row["resource"]
        if resource["type"] != "gce_instance" or resource["labels"] != {
                "instance_id": instance_id, "project_id": expected_project, "zone": expected_zone
        } or row["logName"] != f"projects/{expected_project}/logs/{SOURCE}":
            continue
        when = parse_time(row["timestamp"])
        if abs((when - boot_utc).total_seconds()) > 90:
            continue
        payload = row["jsonPayload"]
        for event in EVENTS:
            if event in payload:
                require(event not in normalized, "Ambiguous provider event for the guest boot")
                require(re.fullmatch(r"[1-9][0-9]*", str(payload["bootCounter"])), "Invalid provider boot counter")
                verified = event == "startupEvent" or payload[event].get("policyEvaluationPassed") is True
                normalized[event] = (str(payload["bootCounter"]), when, verified)
    require(list(sorted(normalized)) == list(sorted(EVENTS)), "Missing provider startup, early or late boot event")
    ordered = [normalized[key] for key in EVENTS]
    require(len({row[0] for row in ordered}) == 1 and all(row[2] for row in ordered) and
            ordered[0][1] < ordered[1][1] < ordered[2][1] and ordered[2][1] <= host_capture,
            "Provider reports do not show an ordered successful evaluation for the same guest boot")

    result = {"schema": "saf-a100-shielded-module-review-v1", "status": "verified",
              "host_ref_sha256": sha256(instance_id.encode()).hexdigest(), "boot_ref_sha256": boot_ref,
              "signed_module_receipt_sha256": sha256(modules_path.read_bytes()).hexdigest(),
              "kernel_lockdown_verified": True, "module_signing_verified": True,
              "provider_boot_counter": int(ordered[0][0]), "guest_boot_utc": boot_utc.isoformat(),
              "provider_events": {event: {"observed_utc": record[1].isoformat(), "policy_passed": record[2]}
                                  for event, record in zip(EVENTS[1:], ordered[1:])},
              "provider_startup_utc": ordered[0][1].isoformat(),
              "correlation": "exact GCE instance ID, ordered shared boot counter, guest start within 90 seconds",
              "verification_scope": "VM Secure Boot and Shielded measured boot plus loaded Ubuntu module provenance"}
    with out.open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(f"PASS: provider early/late boot and signed modules bound to guest boot {ordered[0][0]}")


if __name__ == "__main__":
    main(*(Path(value) for value in sys.argv[1:]))
