"""Small allowlisted BPE counting and NDJSON streaming fixture."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import argparse
from urllib.parse import urlsplit

from encoding_fixture import load_encoding


HOST = "0.0.0.0"
PORT = 8080
READY_PATH = "/health"
MODEL = "cl100k_base"
MAX_INPUT_TOKENS = 32
MAX_REQUEST_OUTPUT_TOKENS = 4
MAX_TOTAL_GENERATED_TOKENS = 6
MAX_POST_REQUESTS = 8
INPUT_LIMIT_ENABLED = True

# Request bodies contain only an identifier and a small output count. Prompt
# text is selected here and expanded through the fixed template.
PROMPT_TEMPLATE = "Summarize this public note: {body}"
ORDINARY_BODY = "The public release note describes routine maintenance."
PROMPTS = {
    "ordinary": ORDINARY_BODY,
    "oversized": " ".join([ORDINARY_BODY] * 16),
}
OUTPUT_SEED = "one two three four five six seven eight"
EXPECTED_ORDINARY_IDS = (
    9370, 5730, 553, 420, 586, 5296, 25, 578, 586, 4984, 5296, 16964, 14348, 13709, 13,
)
EXPECTED_OUTPUT_IDS = (606, 1403, 2380, 3116, 4330, 4848, 8254, 8223)


class State:
    def __init__(self):
        self.encoding = load_encoding()
        self.prompt_tokens = {
            name: len(self.encoding.encode_ordinary(PROMPT_TEMPLATE.format(body=body)))
            for name, body in PROMPTS.items()
        }
        if self.prompt_tokens["ordinary"] > MAX_INPUT_TOKENS:
            raise RuntimeError("ordinary fixed prompt exceeds its configured input cap")
        if self.prompt_tokens["oversized"] <= MAX_INPUT_TOKENS:
            raise RuntimeError("oversized fixed prompt does not exceed its configured input cap")
        if tuple(self.encoding.encode_ordinary(PROMPT_TEMPLATE.format(body=ORDINARY_BODY))) != EXPECTED_ORDINARY_IDS:
            raise RuntimeError("ordinary prompt differs from the pinned cl100k_base oracle")
        if self.prompt_tokens["oversized"] != 135:
            raise RuntimeError("oversized prompt differs from the pinned cl100k_base count")
        self.output_ids = tuple(self.encoding.encode_ordinary(OUTPUT_SEED))
        if self.output_ids != EXPECTED_OUTPUT_IDS:
            raise RuntimeError("output seed differs from the pinned cl100k_base oracle")
        self.received_posts = 0
        self.backend_requests = 0
        self.backend_prompt_tokens = 0
        self.generated_tokens = 0
        self.lock = threading.Lock()

    def metrics(self):
        with self.lock:
            return {
                "received_posts": self.received_posts,
                "backend_requests": self.backend_requests,
                "backend_prompt_tokens": self.backend_prompt_tokens,
                "generated_tokens": self.generated_tokens,
            }


STATE = State()


def encode_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SAF0903Fixture/1"
    sys_version = ""

    def log_message(self, _format, *_args):
        return

    def send_json(self, status, value):
        payload = encode_json(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == READY_PATH:
            self.send_json(200, {
                "service": "saf-0903-004-stream-fixture",
                "status": "ready",
                "tokenizer": MODEL,
                "max_input_tokens": MAX_INPUT_TOKENS if INPUT_LIMIT_ENABLED else None,
                **({} if INPUT_LIMIT_ENABLED else {"input_limit_enabled": False}),
                "max_request_output_tokens": MAX_REQUEST_OUTPUT_TOKENS,
                "max_total_generated_tokens": MAX_TOTAL_GENERATED_TOKENS,
                "max_post_requests": MAX_POST_REQUESTS,
            })
        elif path == "/metrics":
            self.send_json(200, STATE.metrics())
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self):
        if urlsplit(self.path).path != "/generate":
            self.send_json(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0 or length > 256:
            self.send_json(400, {"error": "invalid_request_size"})
            return
        try:
            request = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": "invalid_json"})
            return
        if (not isinstance(request, dict)
                or set(request) != {"prompt_id", "requested_output_tokens"}
                or not isinstance(request.get("prompt_id"), str)
                or request.get("prompt_id") not in PROMPTS
                or type(request.get("requested_output_tokens")) is not int
                or not 0 <= request["requested_output_tokens"] <= 8):
            self.send_json(400, {"error": "invalid_fixed_request"})
            return

        with STATE.lock:
            if STATE.received_posts >= MAX_POST_REQUESTS:
                self.send_json(429, {"error": "request_cap"})
                return
            STATE.received_posts += 1

        prompt_id = request["prompt_id"]
        expanded_prompt = PROMPT_TEMPLATE.format(body=PROMPTS[prompt_id])
        input_tokens = len(STATE.encoding.encode_ordinary(expanded_prompt))
        if INPUT_LIMIT_ENABLED and input_tokens > MAX_INPUT_TOKENS:
            self.send_json(413, {
                "accepted": False,
                "reason": "input_limit",
                "prompt_id": prompt_id,
                "input_tokens": input_tokens,
                "input_cap": MAX_INPUT_TOKENS,
                "backend_dispatched": False,
            })
            return

        with STATE.lock:
            remaining = MAX_TOTAL_GENERATED_TOKENS - STATE.generated_tokens
            output_count = min(
                request["requested_output_tokens"],
                MAX_REQUEST_OUTPUT_TOKENS,
                remaining,
            )
            STATE.backend_requests += 1
            STATE.backend_prompt_tokens += input_tokens

        reason = "complete"
        if output_count < request["requested_output_tokens"]:
            reason = "total_cap" if remaining < min(
                request["requested_output_tokens"], MAX_REQUEST_OUTPUT_TOKENS
            ) else "request_cap"

        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()

        for index in range(output_count):
            with STATE.lock:
                if STATE.generated_tokens >= MAX_TOTAL_GENERATED_TOKENS:
                    break
                token_id = STATE.output_ids[STATE.generated_tokens]
                STATE.generated_tokens += 1
                generated_total = STATE.generated_tokens
            self.write_chunk(encode_json({
                "event": "token",
                "index": index + 1,
                "token_id": token_id,
                "generated_total": generated_total,
            }))
        self.write_chunk(encode_json({
            "event": "done",
            "accepted": True,
            "reason": reason,
            "prompt_id": prompt_id,
            "input_tokens": input_tokens,
            **({} if INPUT_LIMIT_ENABLED else {"input_limit_enabled": False}),
            "requested_output_tokens": request["requested_output_tokens"],
            "output_cap": MAX_REQUEST_OUTPUT_TOKENS,
            "output_tokens": output_count,
            "generated_total": STATE.metrics()["generated_tokens"],
            "backend_dispatched": True,
        }))
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
        self.close_connection = True

    def write_chunk(self, data):
        self.wfile.write((format(len(data), "x") + "\r\n").encode("ascii"))
        self.wfile.write(data)
        self.wfile.write(b"\r\n")
        self.wfile.flush()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-limit-disabled", action="store_true")
    args = parser.parse_args()
    INPUT_LIMIT_ENABLED = not args.input_limit_disabled
    HTTPServer((HOST, PORT), Handler).serve_forever()
