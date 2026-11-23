"""Preflight policy for three tiny inert SafeTensors fixtures."""
import importlib.metadata
import json
from pathlib import Path
import struct
import sys
from zipfile import ZipFile

MAX_HEADER = 256
MAX_ARTIFACT = 384
SHAPE = [2, 2]
VALUES = {
    "approved": ("F32", struct.pack("<4f", 0.25, -0.5, 1.0, 2.0)),
    "wrong-dtype": ("I32", struct.pack("<4i", 1, 2, 3, 4)),
    "wrong-length": ("F32", struct.pack("<3f", 0.25, -0.5, 1.0)),
}


def artifact(variant):
    dtype, data = VALUES[variant]
    header = json.dumps({"weight": {"dtype": dtype, "shape": SHAPE, "data_offsets": [0, 16]}},
                        sort_keys=True, separators=(",", ":")).encode()
    return struct.pack("<Q", len(header)) + header + data


def exact_keys(pairs):
    record = dict(pairs)
    if len(record) != len(pairs):
        raise ValueError("duplicate-field")
    return record


def preflight(data):
    if not 8 <= len(data) <= MAX_ARTIFACT:
        raise ValueError("artifact-length")
    size = struct.unpack_from("<Q", data)[0]
    end = 8 + size
    if not 0 < size <= MAX_HEADER or end > len(data):
        raise ValueError("header-length")
    metadata = json.loads(data[8:end], object_pairs_hook=exact_keys)
    if not isinstance(metadata, dict) or set(metadata) != {"weight"}:
        raise ValueError("tensor-name")
    tensor = metadata["weight"]
    if tensor.get("dtype") != "F32":
        raise ValueError("dtype-policy")
    if tensor.get("shape") != SHAPE or any(type(dimension) is not int for dimension in tensor["shape"]):
        raise ValueError("shape-policy")
    if tensor.get("data_offsets") != [0, 16] or len(data) - end != 16:
        raise ValueError("payload-length")


def run():
    site = Path("/tmp/safetensors-fixture")
    with ZipFile("/wheel/safetensors.whl") as archive:
        archive.extractall(site)
    sys.path.insert(0, str(site))
    from safetensors import deserialize
    outcomes = {}
    for mode, variant in (("baseline", "wrong-dtype"), ("governed", "wrong-dtype"),
                          ("governed", "wrong-length"), ("governed", "approved")):
        data = artifact(variant)
        key = mode + "-" + variant
        if mode == "governed":
            try:
                preflight(data)
            except ValueError as error:
                outcomes[key] = {"decision": "denied", "reason": str(error), "native_calls": 0}
                continue
        tensors = dict(deserialize(data))
        tensor = tensors["weight"]
        dtype = tensor["dtype"]
        values = struct.unpack("<4f" if dtype == "F32" else "<4i", tensor["data"])
        outcomes[key] = {"decision": "loaded", "dtype": dtype, "shape": tensor["shape"],
                         "weights": list(values), "native_calls": 1}
    print(json.dumps({"library": importlib.metadata.version("safetensors"), "outcomes": outcomes},
                     sort_keys=True))


if __name__ == "__main__":
    run()
