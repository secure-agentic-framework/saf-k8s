"""Fixture-only bounded parser and policy observations; no executable model input."""
import hashlib
import json
import struct

MAX_FILE = 2048
MAX_HEADER = 512
LEGACY_INERT = b"SAF-LEGACY-INERT-V1\x00fixed-bytes-only"
# Ordinary declarative data only; never interpreted as executable serialization.
DECLARATIVE_JSON = b'{"schema":"saf-safe-data-v1","weights":[1.25,-2.5]}'
OTHER_DECLARATIVE_JSON = b'{"schema":"saf-safe-data-v1","weights":[0.0,0.5]}'


class FixtureError(Exception):
    pass


def safetensors_fixture():
    """Pack one known F32[2] tensor using the documented safetensors framing."""
    header = json.dumps(
        {"weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}},
        separators=(",", ":"),
    ).encode("utf-8")
    header += b" " * ((-len(header)) % 8)
    return struct.pack("<Q", len(header)) + header + struct.pack("<2f", 1.25, -2.5)


def policy_decision(format_name, allowlist, counters):
    if format_name not in allowlist:
        counters["deny_count"] += 1
        return False
    counters["allow_count"] += 1
    return True


def safe_load_narrow(data, counters):
    """Read only the fixture's one fixed tensor schema, not general model metadata."""
    counters["loader_calls"] += 1
    if len(data) > MAX_FILE or len(data) < 8:
        raise FixtureError("bounded file length rejected")
    header_len = struct.unpack("<Q", data[:8])[0]
    if header_len < 2 or header_len > MAX_HEADER or 8 + header_len > len(data):
        raise FixtureError("bounded header length rejected")
    header_bytes = data[8:8 + header_len]
    if not header_bytes.startswith(b"{"):
        raise FixtureError("header is not a safetensors JSON object")
    try:
        header = json.loads(header_bytes.decode("utf-8").rstrip(" "))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FixtureError("header JSON rejected") from exc
    # A deliberately strict fixture schema: one named tensor, exact shape/type/offsets.
    if header != {"weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}:
        raise FixtureError("fixture tensor descriptor rejected")
    payload = data[8 + header_len:]
    if len(payload) != 8:
        raise FixtureError("tensor byte length rejected")
    counters["values_read"] += 2
    return list(struct.unpack("<2f", payload))


def _json_admit_then_load(declared_format, data, approved_digests):
    """Bind a harmless JSON data parse to the exact format+digest admission decision."""
    counters = {"deny_count": 0, "loader_calls": 0, "values_read": 0}
    digest = hashlib.sha256(data).hexdigest()
    admitted = declared_format == "json-data" and digest in approved_digests
    if not admitted:
        counters["deny_count"] = 1
        return {"declared_format": declared_format, "sha256": digest,
                "admitted": False, "loader_sha256": None,
                "status": "DENY_BEFORE_LOADER", "counters": counters}
    counters["loader_calls"] = 1
    # This is the real Python standard-library declarative JSON data parser.
    value = json.loads(data.decode("utf-8"))
    counters["values_read"] = len(value["weights"])
    return {"declared_format": declared_format, "sha256": digest,
            "admitted": True, "loader_sha256": hashlib.sha256(data).hexdigest(),
            "status": "JSON_DATA_LOADED", "values": value["weights"],
            "counters": counters}


def try_load(declared_format, data, approved_formats):
    counters = {"deny_count": 0, "stub_calls": 0, "loader_calls": 0, "values_read": 0}
    observed = {"declared_format": declared_format, "sha256": hashlib.sha256(data).hexdigest(),
                "counters": counters}
    if declared_format not in approved_formats:
        counters["deny_count"] += 1
        return {**observed, "status": "DENY_FORMAT"}
    if declared_format == "legacy-inert":
        counters["stub_calls"] += 1
        return {**observed, "status": "STUB_ONLY"}
    try:
        values = safe_load_narrow(data, counters)
    except FixtureError:
        return {**observed, "status": "REJECTED_BEFORE_VALUES"}
    return {**observed, "status": "SAFE_LOADED", "values": values}


if __name__ == "__main__":
    approved = {"safetensors"}
    result = {
        "permissive": try_load("legacy-inert", LEGACY_INERT, approved | {"legacy-inert"}),
        "restricted": try_load("legacy-inert", LEGACY_INERT, approved),
        "approved": try_load("safetensors", safetensors_fixture(), approved),
        "mislabeled": try_load("safetensors", LEGACY_INERT, approved),
    }
    approved_json_digest = hashlib.sha256(DECLARATIVE_JSON).hexdigest()
    result["declarative_json"] = {
        "approved": _json_admit_then_load("json-data", DECLARATIVE_JSON,
                                           {approved_json_digest}),
        "wrong_format": _json_admit_then_load("legacy-inert", DECLARATIVE_JSON,
                                               {approved_json_digest}),
        "unapproved_digest": _json_admit_then_load("json-data", OTHER_DECLARATIVE_JSON,
                                                    {approved_json_digest}),
    }
    print(json.dumps(result, sort_keys=True))
