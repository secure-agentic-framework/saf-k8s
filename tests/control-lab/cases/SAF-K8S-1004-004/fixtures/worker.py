"""Offline, deterministic synthetic bundle validator and enrichment worker."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path


ROOT = Path("/case")


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def evaluate(raw_bundle, pin, as_of, observations):
    digest = hashlib.sha256(raw_bundle).hexdigest()
    if not pin:
        return {"accepted": False, "quarantine_reason": "missing_digest_pin",
                "bundle_sha256": digest, "enrichments": [], "quiet_observation_ids": []}
    if digest != pin:
        return {"accepted": False, "quarantine_reason": "digest_mismatch",
                "bundle_sha256": digest, "enrichments": [], "quiet_observation_ids": []}
    try:
        bundle = json.loads(raw_bundle)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"accepted": False, "quarantine_reason": "invalid_bundle", "bundle_sha256": digest,
                "enrichments": [], "quiet_observation_ids": []}
    if parse_time(as_of) >= parse_time(bundle["expires_at"]):
        return {"accepted": False, "quarantine_reason": "expired", "bundle_sha256": digest,
                "enrichments": [], "quiet_observation_ids": []}

    rules = {(row["image_digest"], row["package"], row["affected_version"]): row
             for row in bundle["advisories"]}
    enrichments = []
    quiet = []
    for observation in observations:
        key = (observation["image_digest"], observation["package"], observation["version"])
        advisory = rules.get(key)
        if advisory is None:
            quiet.append(observation["observation_id"])
            continue
        enrichments.append({
            "observation_id": observation["observation_id"],
            "asset_ref": observation["asset_ref"],
            "match": {"image_digest": observation["image_digest"],
                      "package": observation["package"], "version": observation["version"]},
            "enrichment": {"bundle_id": bundle["bundle_id"],
                           "source_id": bundle["source_id"],
                           "advisory_id": advisory["advisory_id"],
                           "severity": advisory["severity"],
                           "fixed_version": advisory["fixed_version"]},
        })
    return {"accepted": True, "quarantine_reason": None, "bundle_sha256": digest,
            "enrichments": enrichments, "quiet_observation_ids": quiet}


def evaluate_source_response(status, raw_bundle, pin, as_of, observations):
    """A transport failure cannot be treated as an empty or newly accepted feed."""
    if status != 200:
        return {"accepted": False, "quarantine_reason": "source_unavailable",
                "enrichments": [], "quiet_observation_ids": []}
    return evaluate(raw_bundle, pin, as_of, observations)


def main():
    approved = (ROOT / "approved-bundle.json").read_bytes()
    damaged = (ROOT / "damaged-bundle.json").read_bytes()
    observations = json.loads((ROOT / "observations.json").read_text())
    pin = os.environ["EXPECTED_BUNDLE_SHA256"]
    current = os.environ["CASE_AS_OF"]
    output = {
        "baseline_unpinned": evaluate(approved, "", current, observations),
        "damaged": evaluate(damaged, pin, current, observations),
        "expired": evaluate(approved, pin, "2026-11-23T00:00:00Z", observations),
        "approved": evaluate(approved, pin, current, observations),
    }
    # Keep the result machine-readable and limited to synthetic identifiers,
    # statuses, and a digest of the public fixture bytes.
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
