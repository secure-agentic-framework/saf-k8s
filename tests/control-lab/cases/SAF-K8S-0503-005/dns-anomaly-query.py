"""One harmless DNS question sent only to the owned .fixture.test zone."""
import json
import socket
import struct
import sys

name, qtype_name, server = sys.argv[1:]
qtypes = {"A": 1, "TXT": 16}
if qtype_name not in qtypes or not name.endswith(".fixture.test."):
    raise SystemExit("Refusing non-fixture DNS query")
labels = [part.encode("ascii") for part in name.rstrip(".").split(".")]
if any(not label or len(label) > 63 for label in labels):
    raise SystemExit("Invalid DNS label")
query_id = 0x5305
question = b"".join(bytes([len(label)]) + label for label in labels) + b"\0" + struct.pack("!HH", qtypes[qtype_name], 1)
packet = struct.pack("!6H", query_id, 0, 1, 0, 0, 0) + question
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
    endpoint.settimeout(3)
    endpoint.connect((server, 1053))
    endpoint.send(packet)
    response = endpoint.recv(4096)
ident, flags, questions, _, _, _ = struct.unpack("!6H", response[:12])
print(json.dumps({
    "response_received": True,
    "question_matched": ident == query_id and questions == 1 and response[12:12 + len(question)] == question,
    "rcode": flags & 0xF,
}))
