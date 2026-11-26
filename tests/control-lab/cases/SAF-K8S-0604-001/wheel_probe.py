"""Fixed, non-sensitive native-extension observation for the psutil wheel fixture."""
import base64
import hashlib
import importlib
import importlib.metadata
import json
from pathlib import Path
import platform
import struct
import sys

import psutil


def inspect_elf(path):
    data = path.read_bytes()
    if data[:4] != b"\x7fELF":
        raise RuntimeError("psutil wheel extension is not ELF")
    cls, encoding = data[4], data[5]
    if cls not in (1, 2) or encoding not in (1, 2):
        raise RuntimeError("unsupported ELF class or byte order")
    endian = "<" if encoding == 1 else ">"
    if cls == 2:
        machine = struct.unpack_from(endian + "H", data, 18)[0]
        phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 54)
    else:
        machine = struct.unpack_from(endian + "H", data, 18)[0]
        phoff = struct.unpack_from(endian + "I", data, 28)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 42)
    types = [struct.unpack_from(endian + "I", data, phoff + n * phentsize)[0]
             for n in range(phnum)]
    expected = {"aarch64": 183, "arm64": 183, "x86_64": 62, "amd64": 62}.get(platform.machine().lower())
    if machine != expected:
        raise RuntimeError("ELF machine does not match this image architecture")
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
            "elf_class": 64 if cls == 2 else 32, "machine": machine,
            "has_dynamic_segment": 2 in types, "has_interpreter": 3 in types}


distribution = importlib.metadata.distribution("psutil")
native = importlib.import_module("psutil._psutil_linux")
native_path = Path(native.__file__).resolve()
site_packages = Path(distribution.locate_file("")).resolve()
relative = native_path.relative_to(site_packages).as_posix()
record_entry = next(item for item in distribution.files or () if item.as_posix() == relative)
record_hash = record_entry.hash
if record_hash is None or record_hash.mode != "sha256":
    raise RuntimeError("wheel RECORD has no SHA-256 entry for the native extension")
elf = inspect_elf(native_path)
record_bytes = base64.urlsafe_b64decode(record_hash.value + "=" * (-len(record_hash.value) % 4))
if record_bytes.hex() != elf["sha256"]:
    raise RuntimeError("installed native extension differs from wheel RECORD SHA-256")
# Execute ordinary native-backed functions without reading host process lists,
# network state, or user-specific information.
process_name = psutil.Process().name()
thread_count = psutil.Process().num_threads()
print(json.dumps({
    "distribution": distribution.metadata["Name"],
    "version": distribution.version,
    "python_cache_tag": sys.implementation.cache_tag,
    "native_module": relative,
    "record_hash_algorithm": record_hash.mode,
    "record_hash_value": record_hash.value,
    "native_elf": elf,
    "native_loaded": bool(process_name) and thread_count >= 1,
    "safe_runtime_result": {"cpu_count": psutil.cpu_count(logical=True),
                            "current_process_name_nonempty": bool(process_name),
                            "thread_count_positive": thread_count >= 1},
}, sort_keys=True))
