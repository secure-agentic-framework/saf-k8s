"""Verify the pinned model mount and make one fixed local bounded inference call."""
import hashlib
import http.client
import json
from pathlib import Path

MODEL = Path("/artifact/stories15M_MOE-F16.gguf")
EXPECTED_SHA256 = "1240dfc1957df9f3550dd6c1d9e64b466fc2f452d8bc34bd4e45e1a1e2ca6055"
EXPECTED_BYTES = 73466432

mount_read_only = False
for line in Path("/proc/self/mountinfo").read_text().splitlines():
    fields = line.split(" - ", 1)
    if len(fields) != 2:
        continue
    left = fields[0].split()
    mountpoint = left[4].replace("\\040", " ") if len(left) > 4 else ""
    mount_options = set(left[5].split(",")) if len(left) > 5 else set()
    if mountpoint == "/artifact":
        mount_read_only = "ro" in mount_options
        break

digest = hashlib.sha256()
size = 0
with MODEL.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
        size += len(chunk)
model_sha256 = digest.hexdigest()
model_stat = MODEL.stat()
model_mode = model_stat.st_mode & 0o777
if (not mount_read_only or model_sha256 != EXPECTED_SHA256 or size != EXPECTED_BYTES
        or model_stat.st_uid != 65534 or model_stat.st_gid != 65534 or model_mode != 0o444):
    raise RuntimeError("read-only model mount identity or bytes differ from reviewed pin")

connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=30)
try:
    connection.request("GET", "/health")
    response = connection.getresponse()
    health = json.loads(response.read(4096))
    if response.status != 200 or health != {"status": "ok"}:
        raise RuntimeError("actual pinned server did not report healthy")
    connection.request("GET", "/v1/models")
    response = connection.getresponse()
    models = json.loads(response.read(8192))
    aliases = [row.get("id") for row in models.get("data", [])]
    if aliases != ["stories15m-moe"]:
        raise RuntimeError("unexpected model alias inventory")
    body = json.dumps({"content": "Once upon a time", "add_special": False,
                       "parse_special": True, "with_pieces": False}).encode()
    connection.request("POST", "/tokenize", body=body,
                       headers={"Content-Type": "application/json"})
    response = connection.getresponse()
    token_ids = json.loads(response.read(8192)).get("tokens")
    if response.status != 200 or token_ids != [9038, 2501, 263, 931]:
        raise RuntimeError("tokenizer identity differed from the pinned fixture")
    body = json.dumps({"prompt": "Once upon a time", "n_predict": 4,
                       "temperature": 0.0, "seed": 42, "ignore_eos": True,
                       "return_tokens": True, "cache_prompt": False}).encode()
    connection.request("POST", "/completion", body=body,
                       headers={"Content-Type": "application/json"})
    response = connection.getresponse()
    completion = json.loads(response.read(32768))
    generated = completion.get("tokens")
    if (response.status != 200 or not isinstance(generated, list) or len(generated) != 4
            or completion.get("stop_type") != "limit"):
        raise RuntimeError("native CPU generation did not meet the fixed four-token bound")
finally:
    connection.close()

print(json.dumps({"mount_read_only": mount_read_only,
                  "model_sha256": model_sha256, "model_bytes": size,
                  "model_uid": model_stat.st_uid, "model_gid": model_stat.st_gid,
                  "model_mode": format(model_mode, "04o"),
                  "health_status": 200, "model_alias": aliases[0],
                  "prompt_token_ids": token_ids, "completion_tokens": len(generated),
                  "completion_limit": 4, "completion_stop_type": completion["stop_type"]},
                 separators=(",", ":")))
