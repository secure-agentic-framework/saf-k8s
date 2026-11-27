"""Verify fixed detached signatures before classifying inert firmware observations."""

import base64
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path("/fixture")
WORK = Path("/tmp")
EXPECTED_WINDOWS = [{"device": "fixture-gpu-a", "version": "fixture-fw-v2", "open": 50,
                     "close": 60, "review_id": "fixture-change-49"}]
EXPECTED = {
    "inside-window": {"record_id": "fixture-observation-1", "device": "fixture-gpu-a",
                      "expected": "fixture-fw-v1", "observed": "fixture-fw-v2",
                      "observed_at": 52, "marker": "firmware-observation:fixture-fw-v2"},
    "outside-window": {"record_id": "fixture-observation-2", "device": "fixture-gpu-a",
                       "expected": "fixture-fw-v1", "observed": "fixture-fw-v2",
                       "observed_at": 70, "marker": "firmware-observation:fixture-fw-v2"},
    "changed-marker": {"record_id": "fixture-observation-1", "device": "fixture-gpu-a",
                       "expected": "fixture-fw-v1", "observed": "fixture-fw-v2",
                       "observed_at": 52, "marker": "firmware-observation:fixture-fw-v1"},
    "unsigned": {"record_id": "fixture-observation-1", "device": "fixture-gpu-a",
                 "expected": "fixture-fw-v1", "observed": "fixture-fw-v2",
                 "observed_at": 52, "marker": "firmware-observation:fixture-fw-v2"},
}


def fail(message):
    raise RuntimeError(message)


def main():
    public_pem = (ROOT / "public.pem").read_bytes()
    bundle = json.loads((ROOT / "observations.json").read_text())
    if type(bundle) is not dict or set(bundle) != {"windows", "entries"}:
        fail("fixture observation bundle schema mismatch")
    if bundle["windows"] != EXPECTED_WINDOWS or type(bundle["entries"]) is not list:
        fail("fixture window or observation schema mismatch")
    if not (ROOT / "public.pem").is_file() or len(public_pem) > 4096:
        fail("fixture public key is unavailable or outside its fixed bound")

    version = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=5)
    if version.returncode != 0 or not version.stdout.startswith("OpenSSL "):
        fail("OpenSSL verifier is unavailable or returned an unexpected version response")
    public_file = ROOT / "public.pem"
    observations = {}
    for entry in bundle["entries"]:
        if type(entry) is not dict or set(entry) != {"scenario", "observation", "signature_b64"}:
            fail("fixture entry schema mismatch")
        name = entry["scenario"]
        if type(name) is not str or name not in EXPECTED:
            fail("fixture scenario label is not recognized")
        row = entry["observation"]
        if type(row) is not dict or row != EXPECTED[name]:
            fail("fixture observation identity or fields do not match the fixed fixture")
        if name in observations:
            fail("duplicate fixture observation")
        signature_b64 = entry["signature_b64"]
        if type(signature_b64) is not str:
            fail("signature field is malformed")
        payload = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
        if not signature_b64:
            signature_state = "absent"
        else:
            try:
                signature = base64.b64decode(signature_b64, validate=True)
            except (ValueError, TypeError):
                fail("signature encoding is malformed")
            if not signature or len(signature) > 4096:
                fail("signature size is outside the fixed bound")
            payload_file = WORK / f"{name}.json"
            signature_file = WORK / f"{name}.sig"
            payload_file.write_bytes(payload)
            signature_file.write_bytes(signature)
            checked = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public_file),
                                      "-signature", str(signature_file), str(payload_file)],
                                     capture_output=True, text=True, timeout=5)
            diagnostic = checked.stdout + checked.stderr
            if checked.returncode == 0:
                signature_state = "valid"
            elif checked.returncode == 1 and "Verification failure" in diagnostic:
                signature_state = "invalid"
            else:
                fail("OpenSSL signature verification infrastructure failed")

        expected_signature = {"inside-window": "valid", "outside-window": "valid",
                              "changed-marker": "invalid", "unsigned": "absent"}[name]
        if signature_state != expected_signature:
            fail("fixture signature state did not match the controlled scenario")
        if signature_state != "valid":
            result = "integrity-unverified"
        else:
            if row["marker"] != f"firmware-observation:{row['observed']}":
                fail("signature-valid observation marker does not bind the fixed version")
            matches = [window for window in bundle["windows"]
                       if window["device"] == row["device"] and window["version"] == row["observed"]
                       and window["open"] <= row["observed_at"] < window["close"]]
            result = "approved-change" if matches else "version-drift-alert"
        observations[name] = {"signature": signature_state, "result": result, "record": row}
    if set(observations) != set(EXPECTED):
        fail("fixture observation set is incomplete")
    print(json.dumps({"public_key_sha256": hashlib.sha256(public_pem).hexdigest(),
                      "verification_tool_version": version.stdout.strip(), "observations": observations}, sort_keys=True))


if __name__ == "__main__":
    main()
