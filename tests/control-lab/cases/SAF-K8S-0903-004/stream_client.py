"""Independent bounded client/verifier for the 0903-004 streaming fixture."""
import argparse
import json
import socket

from encoding_fixture import load_encoding


PORT = 8080
READY_PATH = "/health"
MAX_CLIENT_REQUESTS = 8
INPUT_CAP = 32
REQUEST_OUTPUT_CAP = 4
TOTAL_OUTPUT_CAP = 6
TEMPLATE = "Summarize this public note: {body}"
ORDINARY_BODY = "The public release note describes routine maintenance."
OVERSIZED_BODY = " ".join([ORDINARY_BODY] * 16)
OUTPUT_SEED = "one two three four five six seven eight"
EXPECTED_RAW_BODY_IDS = (791, 586, 4984, 5296, 16964, 14348, 13709, 13)
EXPECTED_ORDINARY_PROMPT_IDS = (
    9370, 5730, 553, 420, 586, 5296, 25, 578, 586, 4984, 5296, 16964, 14348, 13709, 13,
)
EXPECTED_OUTPUT_IDS = (606, 1403, 2380, 3116, 4330, 4848, 8254, 8223)
EXPECTED_OVERSIZED_PROMPT_TOKENS = 135


class Wire:
    """One short HTTP/1.1 exchange, preserving individual HTTP chunk frames."""

    def __init__(self, host, port):
        self.host, self.port = host, port
        self.requests = 0

    def request(self, method, path, body=None):
        if self.requests >= MAX_CLIENT_REQUESTS:
            raise RuntimeError("client request cap exceeded")
        self.requests += 1
        payload = b"" if body is None else json.dumps(
            body, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        headers = [
            f"{method} {path} HTTP/1.1",
            f"Host: {self.host}:{self.port}",
            "Connection: close",
            "Accept: application/json, application/x-ndjson",
        ]
        if body is not None:
            headers.extend(["Content-Type: application/json", f"Content-Length: {len(payload)}"])
        request_bytes = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + payload
        with socket.create_connection((self.host, self.port), timeout=5) as sock:
            sock.settimeout(5)
            sock.sendall(request_bytes)
            stream = sock.makefile("rb")
            status_line = stream.readline().decode("ascii").rstrip("\r\n")
            parts = status_line.split(" ", 2)
            if len(parts) < 2 or not parts[1].isdigit():
                raise AssertionError(f"invalid HTTP status line: {status_line!r}")
            status = int(parts[1])
            response_headers = {}
            while True:
                line = stream.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                key, value = line.decode("ascii").split(":", 1)
                response_headers[key.lower().strip()] = value.strip().lower()

            if response_headers.get("transfer-encoding") == "chunked":
                chunks = []
                while True:
                    size_line = stream.readline().split(b";", 1)[0].strip()
                    if not size_line:
                        raise AssertionError("missing chunk size")
                    size = int(size_line, 16)
                    if size == 0:
                        trailer = stream.readline()
                        if trailer != b"\r\n":
                            raise AssertionError("unexpected chunk trailer")
                        if stream.read(1) != b"":
                            raise AssertionError("bytes followed the terminal HTTP chunk")
                        break
                    chunk = stream.read(size)
                    if len(chunk) != size or stream.read(2) != b"\r\n":
                        raise AssertionError("truncated or malformed HTTP chunk")
                    chunks.append(chunk)
                return status, response_headers, chunks

            length = int(response_headers.get("content-length", "0"))
            payload = stream.read(length)
            if len(payload) != length:
                raise AssertionError("truncated HTTP response body")
            return status, response_headers, payload


def require(condition, name, detail, checks):
    checks.append({"name": name, "passed": bool(condition), "detail": detail})
    if not condition:
        raise AssertionError(f"{name} failed: {detail}")


def ndjson_chunks(chunks):
    records = []
    for chunk in chunks:
        if not chunk.endswith(b"\n") or chunk.count(b"\n") != 1:
            raise AssertionError("each HTTP chunk must contain exactly one NDJSON record")
        records.append(json.loads(chunk))
    return records


def verify(host):
    checks = []
    encoding = load_encoding()
    raw_body_ids = encoding.encode_ordinary(ORDINARY_BODY)
    ordinary_prompt = TEMPLATE.format(body=ORDINARY_BODY)
    oversized_prompt = TEMPLATE.format(body=OVERSIZED_BODY)
    ordinary_tokens = len(encoding.encode_ordinary(ordinary_prompt))
    oversized_tokens = len(encoding.encode_ordinary(oversized_prompt))
    output_ids = encoding.encode_ordinary(OUTPUT_SEED)
    require(tuple(raw_body_ids) == EXPECTED_RAW_BODY_IDS
            and tuple(encoding.encode_ordinary(ordinary_prompt)) == EXPECTED_ORDINARY_PROMPT_IDS
            and ordinary_tokens == 15 and len(ORDINARY_BODY.split()) == 7
            and len(ordinary_prompt.split()) == 11
            and oversized_tokens == EXPECTED_OVERSIZED_PROMPT_TOKENS
            and len(oversized_prompt.split()) == 116
            and ordinary_tokens <= INPUT_CAP < oversized_tokens, "reference_bpe_counts",
            {"raw_body_bpe": len(raw_body_ids), "raw_body_whitespace": len(ORDINARY_BODY.split()),
             "raw_body_ids": list(raw_body_ids),
             "ordinary_prompt_bpe": ordinary_tokens, "ordinary_prompt_whitespace": len(ordinary_prompt.split()),
             "ordinary_prompt_ids": list(encoding.encode_ordinary(ordinary_prompt)),
             "oversized_prompt_bpe": oversized_tokens,
             "oversized_prompt_whitespace": len(oversized_prompt.split()), "input_cap": INPUT_CAP}, checks)
    require(tuple(output_ids) == EXPECTED_OUTPUT_IDS and len(output_ids) >= TOTAL_OUTPUT_CAP,
            "reference_output_oracle", {"known_output_token_ids": output_ids}, checks)

    wire = Wire(host, PORT)
    status, _headers, payload = wire.request("GET", READY_PATH)
    health = json.loads(payload)
    require(status == 200 and health == {
        "service": "saf-0903-004-stream-fixture", "status": "ready",
        "tokenizer": "cl100k_base", "max_input_tokens": INPUT_CAP,
        "max_request_output_tokens": REQUEST_OUTPUT_CAP,
        "max_total_generated_tokens": TOTAL_OUTPUT_CAP,
        "max_post_requests": MAX_CLIENT_REQUESTS,
    }, "ready_and_caps", health, checks)

    status, headers, chunks = wire.request("POST", "/generate", {
        "prompt_id": "ordinary", "requested_output_tokens": 2,
    })
    records = ndjson_chunks(chunks)
    token_records = [row for row in records if row.get("event") == "token"]
    done_records = [row for row in records if row.get("event") == "done"]
    require(status == 200 and headers.get("transfer-encoding") == "chunked"
            and headers.get("content-type") == "application/x-ndjson; charset=utf-8"
            and len(chunks) == 3 and len(token_records) == 2 and len(done_records) == 1
            and all(type(row.get("index")) is int and type(row.get("token_id")) is int
                    and type(row.get("generated_total")) is int for row in token_records)
            and token_records == [
                {"event": "token", "index": 1, "token_id": output_ids[0], "generated_total": 1},
                {"event": "token", "index": 2, "token_id": output_ids[1], "generated_total": 2},
            ]
            and done_records[0] == {
                "event": "done", "accepted": True, "reason": "complete",
                "prompt_id": "ordinary", "input_tokens": ordinary_tokens,
                "requested_output_tokens": 2, "output_cap": REQUEST_OUTPUT_CAP,
                "output_tokens": 2, "generated_total": 2,
                "backend_dispatched": True,
            }, "bounded_real_http_stream", {"status": status, "chunks": len(chunks),
                                             "records": records}, checks)

    status, _headers, payload = wire.request("POST", "/generate", {
        "prompt_id": "oversized", "requested_output_tokens": 1,
    })
    rejected = json.loads(payload)
    require(status == 413 and rejected == {
        "accepted": False, "reason": "input_limit", "prompt_id": "oversized",
        "input_tokens": oversized_tokens, "input_cap": INPUT_CAP,
        "backend_dispatched": False,
    }, "expanded_prompt_rejected_before_dispatch", rejected, checks)

    status, headers, chunks = wire.request("POST", "/generate", {
        "prompt_id": "ordinary", "requested_output_tokens": 5,
    })
    records = ndjson_chunks(chunks)
    token_records = [row for row in records if row.get("event") == "token"]
    done_records = [row for row in records if row.get("event") == "done"]
    require(status == 200 and headers.get("transfer-encoding") == "chunked"
            and headers.get("content-type") == "application/x-ndjson; charset=utf-8"
            and len(chunks) == 5 and len(token_records) == REQUEST_OUTPUT_CAP
            and len(done_records) == 1
            and all(type(row.get("index")) is int and type(row.get("token_id")) is int
                    and type(row.get("generated_total")) is int for row in token_records)
            and token_records == [
                {"event": "token", "index": 1, "token_id": output_ids[2], "generated_total": 3},
                {"event": "token", "index": 2, "token_id": output_ids[3], "generated_total": 4},
                {"event": "token", "index": 3, "token_id": output_ids[4], "generated_total": 5},
                {"event": "token", "index": 4, "token_id": output_ids[5], "generated_total": 6},
            ]
            and done_records[0] == {
                "event": "done", "accepted": True, "reason": "request_cap",
                "prompt_id": "ordinary", "input_tokens": ordinary_tokens,
                "requested_output_tokens": 5, "output_cap": REQUEST_OUTPUT_CAP,
                "output_tokens": REQUEST_OUTPUT_CAP, "generated_total": TOTAL_OUTPUT_CAP,
                "backend_dispatched": True,
            }, "output_cap_counts_emitted_tokens", {"status": status, "chunks": len(chunks),
                                                   "records": records}, checks)

    status, _headers, payload = wire.request("GET", "/metrics")
    metrics = json.loads(payload)
    require(status == 200 and metrics == {
        "received_posts": 3,
        "backend_requests": 2,
        "backend_prompt_tokens": ordinary_tokens * 2,
        "generated_tokens": TOTAL_OUTPUT_CAP,
    }, "independent_backend_counters", metrics, checks)
    require(wire.requests == 5 and wire.requests < 10, "bounded_http_request_count",
            {"requests": wire.requests, "limit": 10}, checks)
    return {"check_count": len(checks), "checks": checks, "http_requests": wire.requests,
            "observed": {"ordinary_tokens": ordinary_tokens,
                         "oversized_tokens": oversized_tokens,
                         "output_token_ids": output_ids[:TOTAL_OUTPUT_CAP],
                         "metrics": metrics}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.host), sort_keys=True, separators=(",", ":")))
