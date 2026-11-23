"""One A query to the case-owned authoritative Pod."""
import json
import secrets
import socket
import struct
import sys

name, server, expected = sys.argv[1:]
if name not in {"signal.fixture.test.", "health.fixture.test."}:
    raise SystemExit("Unexpected fixture name")
query_id = secrets.randbits(16)
labels = [part.encode("ascii") for part in name.rstrip(".").split(".")]
question = b"".join(bytes([len(label)]) + label for label in labels) + b"\0" + struct.pack("!HH", 1, 1)
query = struct.pack("!6H", query_id, 0, 1, 0, 0, 0) + question
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
    endpoint.settimeout(4)
    endpoint.connect((server, 1053))
    endpoint.send(query)
    response = endpoint.recv(4096)
ident, flags, questions, records, _, _ = struct.unpack("!6H", response[:12])
offset = 12 + len(question)
answer = b""
answer_name_size = 0
if response[offset:offset + 2] == b"\xc0\x0c":
    answer_name_size = 2
elif response[offset:offset + len(question) - 4] == question[:-4]:
    answer_name_size = len(question) - 4
record_start = offset + answer_name_size
if records == 1 and answer_name_size and len(response) >= record_start + 14:
    record_type, record_class, _, size = struct.unpack("!HHIH", response[record_start:record_start + 10])
    if (record_type, record_class, size) == (1, 1, 4):
        answer = response[record_start + 10:record_start + 14]
print(json.dumps({
    "matched_question": ident == query_id and questions == 1 and response[12:offset] == question,
    "authoritative_success": flags & 0x840F == 0x8400,
    "matched_answer": answer == socket.inet_aton(expected),
}))
