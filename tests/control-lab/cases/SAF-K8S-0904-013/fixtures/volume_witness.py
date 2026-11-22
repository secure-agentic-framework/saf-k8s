"""Inspect only the single fixture object's SeaweedFS index and volume records."""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path("/data")
COLLECTION = "saf-case-013_saf-artifacts-0904"
MARKER = hashlib.shake_256(
    b"SAF-K8S-0904-013 public inert volume witness marker v1").digest(65536)
MARKER_SHA256 = "7ef23877d2d11a502f6d9433ce2d666b9a66263115b5dad1d105e0711407cdfc"


def witness(root):
    if hashlib.sha256(MARKER).hexdigest() != MARKER_SHA256:
        raise ValueError("fixture marker digest changed")
    indexes = [path for path in root.rglob(f"{COLLECTION}_*.idx") if path.stat().st_size]
    if len(indexes) != 1:
        raise ValueError(f"expected one nonempty index in the fixture collection, found {len(indexes)}")
    index_path = indexes[0]
    data_path = index_path.with_suffix(".dat")
    if index_path.is_symlink() or data_path.is_symlink() or data_path.stat().st_size > 64 * 1024**2:
        raise ValueError("fixture volume path does not meet the witness bounds")
    index = index_path.read_bytes()
    if len(index) != 16:
        raise ValueError("expected exactly one 16-byte entry in the fixture volume index")
    needle_id, offset_units, size = struct.unpack(">QIi", index)
    offset = offset_units * 8
    volume = data_path.read_bytes()
    if offset == 0 or size <= 0 or (offset + 16 + size) > len(volume):
        raise ValueError("fixture index entry does not point to a valid volume record")
    header_id, header_size = struct.unpack_from(">Qi", volume, offset + 4)
    if (header_id, header_size) != (needle_id, size):
        raise ValueError("fixture index entry does not match the persisted needle header")
    payload = volume[offset + 16:offset + 16 + size]
    return {
        "dat_path": str(data_path.relative_to(root)), "dat_size": len(volume),
        "dat_sha256": hashlib.sha256(volume).hexdigest(), "idx_path": str(index_path.relative_to(root)),
        "idx_size": len(index), "idx_records": 1, "idx_sha256": hashlib.sha256(index).hexdigest(),
        "indexed_needle_id_hex": format(needle_id, "016x"), "indexed_offset_units": offset_units,
        "indexed_size": size, "needle_header_matches_index": True,
        "marker_occurrences_in_dat": volume.count(MARKER), "marker_occurrences_in_indexed_record": payload.count(MARKER),
    }


if __name__ == "__main__":
    print(json.dumps(witness(ROOT), sort_keys=True))
