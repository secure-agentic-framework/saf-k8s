"""Fixture-only bounded parser and policy observations; no executable model input."""
import hashlib
import importlib.metadata
import json
import os
import pickletools
import platform
import struct
import sys
from pathlib import Path
from zipfile import ZipFile

MAX_FILE = 2048
MAX_HEADER = 512
PRIMITIVE_PICKLE_SHA256 = "06d302a110b5a89f9282c390a7c6256905840c30d98534642377242191a79a6e"
PRIMITIVE_PICKLE_OPCODES = ["PROTO", "FRAME", "EMPTY_DICT", "MEMOIZE", "SHORT_BINUNICODE",
                            "MEMOIZE", "EMPTY_LIST", "MEMOIZE", "MARK", "BINFLOAT",
                            "BINFLOAT", "APPENDS", "SETITEM", "STOP"]
LEGACY_INERT = b"SAF-LEGACY-INERT-V1\x00fixed-bytes-only"
# Ordinary declarative data only; never interpreted as executable serialization.
DECLARATIVE_JSON = b'{"schema":"saf-safe-data-v1","weights":[1.25,-2.5]}'
OTHER_DECLARATIVE_JSON = b'{"schema":"saf-safe-data-v1","weights":[0.0,0.5]}'


class FixtureError(Exception):
    pass


def safetensors_fixture(values=(1.25, -2.5)):
    """Pack one known F32[2] tensor using the documented safetensors framing."""
    header = json.dumps(
        {"weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}},
        separators=(",", ":"),
    ).encode("utf-8")
    header += b" " * ((-len(header)) % 8)
    return struct.pack("<Q", len(header)) + header + struct.pack("<2f", *values)


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
    admitted, _ = _format_digest_gate(declared_format, data, {"json-data": approved_digests})
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


def _format_digest_gate(declared_format, data, approved):
    """Shared exact-format and exact-digest activation gate before any parser call."""
    digest = hashlib.sha256(data).hexdigest()
    return digest in approved.get(declared_format, set()), digest


def native_safetensors_witness():
    """Run the pinned upstream parser only after the shared format/digest gate."""
    wheel_path = Path("/wheel/safetensors.whl")
    wheel_digest = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    expected_wheel_digest = os.environ["SAF_EXPECTED_WHEEL_SHA256"]
    expected_machine = os.environ["SAF_EXPECTED_MACHINE"]
    machine = platform.machine()
    if wheel_digest != expected_wheel_digest or machine != expected_machine:
        raise RuntimeError("locked package or runtime architecture mismatch")

    site = Path("/runtime/site")
    site.mkdir(parents=True, exist_ok=True)
    with ZipFile(wheel_path) as package:
        package.extractall(site)
    sys.path.insert(0, str(site))
    deserialize = None

    approved_data = safetensors_fixture()
    different_data = safetensors_fixture(values=(0.0, 0.5))
    approved = {"safetensors": {hashlib.sha256(approved_data).hexdigest()}}
    native_calls = 0
    outcomes = {}

    for name, declared, data in (
        ("approved", "safetensors", approved_data),
        ("wrong_format", "legacy-inert", approved_data),
        ("unapproved_digest", "safetensors", different_data),
        ("mislabeled_inert", "safetensors", LEGACY_INERT),
    ):
        calls_before = native_calls
        admitted, digest = _format_digest_gate(declared, data, approved)
        if not admitted:
            outcomes[name] = {"declared_format": declared, "sha256": digest,
                              "status": "DENY_BEFORE_NATIVE", "native_calls": native_calls,
                              "native_call_delta": native_calls - calls_before}
            continue

        if deserialize is None:
            from safetensors import deserialize as native_deserialize
            deserialize = native_deserialize
        native_calls += 1
        tensor = dict(deserialize(data))["weight"]
        # Upstream 0.8.0 deserialize returns a mapping of tensor metadata and bytes.
        values = list(struct.unpack("<2f", tensor["data"]))
        outcomes[name] = {"declared_format": declared, "sha256": digest,
                          "status": "NATIVE_LOADED", "native_calls": native_calls,
                          "native_call_delta": native_calls - calls_before,
                          "tensor_name": "weight", "dtype": tensor["dtype"],
                          "shape": list(tensor["shape"]), "values": values}

    return {"library": importlib.metadata.version("safetensors"),
            "machine": machine, "wheel_sha256": wheel_digest,
            "expected_machine": expected_machine, "outcomes": outcomes}


def primitive_pickle_rejection(path):
    """Passively inspect fixed primitive bytes, then deny before any loader dispatch."""
    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) > MAX_FILE or digest != PRIMITIVE_PICKLE_SHA256:
        raise RuntimeError("primitive-only pickle fixture did not match its bounded identity")
    opcodes = [opcode.name for opcode, _, _ in pickletools.genops(data)]
    if opcodes != PRIMITIVE_PICKLE_OPCODES:
        raise RuntimeError("primitive-only pickle fixture opcode allowlist mismatch")
    counters = {"deny_count": 0, "loader_dispatch_attempts": 0,
                "loader_calls": 0, "values_read": 0}
    admitted, observed_digest = _format_digest_gate(
        "pickle", data, {"safetensors": {hashlib.sha256(safetensors_fixture()).hexdigest()},
                         "json-data": {hashlib.sha256(DECLARATIVE_JSON).hexdigest()}})
    if admitted:
        counters["loader_dispatch_attempts"] += 1
        return {"format": "pickle", "sha256": observed_digest,
                "status": "UNEXPECTED_ADMIT_NO_LOADER_EXECUTED",
                "opcodes": opcodes, "counters": counters}
    counters["deny_count"] += 1
    return {"format": "pickle", "sha256": observed_digest,
            "status": "DENY_BEFORE_LOADER", "opcodes": opcodes,
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
    result["native_safetensors"] = native_safetensors_witness()
    result["primitive_pickle"] = primitive_pickle_rejection("/fixture/primitive-only.pickle")
    print(json.dumps(result, sort_keys=True))
