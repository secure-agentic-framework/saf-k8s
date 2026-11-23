"""Embed and inspect a keyed marker in one fixed synthetic serving template."""
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import sys
from urllib.request import urlopen

DOCUMENT_ID = "toy-neutral-v1"
MIN_POSITIONS = 10
REQUIRED_MATCHES = 10
KEY_FILE = Path("/verification/marker")
UNMARKED = (
    "The breeze moved across the field. A path followed the stream, while clouds crossed "
    "the sky. Nearby a garden rested beside the fence, and leaves settled near the gate."
)
CHOICES = (
    ("gentle", "calm"),
    ("quiet", "still"),
    ("open", "wide"),
    ("clear", "plain"),
    ("steady", "even"),
    ("soft", "mild"),
    ("small", "modest"),
    ("nearby", "close"),
    ("bright", "light"),
    ("simple", "basic"),
)


def _choice_bit(index: int, key: bytes) -> int:
    message = f"{DOCUMENT_ID}:{index}".encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).digest()
    return digest[0] & 1


def serve_synthetic(key):
    return _render_with_tokens([pair[_choice_bit(index, key)] for index, pair in enumerate(CHOICES)])


def _normalize(text: str) -> list[str]:
    """Approved benign normalization: lowercase and ignore punctuation only."""
    return re.findall(r"[a-z]+", text.lower())


def verify_synthetic(text: str, key: bytes) -> dict[str, object]:
    """Authorized fixture detector; accepts only the fixed document grammar."""
    tokens = _normalize(text)
    # Indexed variable-token positions in the fixed template. Exact grammar
    # checking prevents unrelated prose from supplying arbitrary candidate hits.
    slot_positions = (1, 6, 9, 13, 16, 20, 24, 29, 32, 37)
    expected_length = 39
    if len(tokens) != expected_length or tokens[0] != "the":
        return {"detected": False, "reason": "outside_fixed_fixture_grammar",
                "positions": 0, "matches": 0}
    observed = [tokens[position] for position in slot_positions]
    if any(word not in pair for word, pair in zip(observed, CHOICES)):
        return {"detected": False, "reason": "outside_fixed_fixture_grammar",
                "positions": 0, "matches": 0}
    # Re-render expected invariant text and compare all non-slot tokens.
    expected = _normalize(_render_with_tokens(observed))
    if tokens != expected:
        return {"detected": False, "reason": "outside_fixed_fixture_grammar",
                "positions": 0, "matches": 0}
    matches = sum(word == pair[_choice_bit(i, key)]
                  for i, (word, pair) in enumerate(zip(observed, CHOICES)))
    return {"detected": len(observed) >= MIN_POSITIONS and matches >= REQUIRED_MATCHES,
            "reason": "keyed_evidence_threshold_met" if matches >= REQUIRED_MATCHES
            else "keyed_evidence_below_threshold",
            "positions": len(observed), "matches": matches}


def _render_with_tokens(words: list[str]) -> str:
    return (
        f"The {words[0]} breeze moved across the {words[1]} field. "
        f"A {words[2]} path followed the {words[3]} stream, while {words[4]} clouds "
        f"crossed the {words[5]} sky. Nearby, a {words[6]} garden rested beside the "
        f"{words[7]} fence, and {words[8]} leaves settled near the {words[9]} gate."
    )



class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/result":
            self.send_error(404)
            return
        payload = json.dumps({"text": self.server.text}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def serve(mode):
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    server.text = serve_synthetic(KEY_FILE.read_bytes()) if mode == "marked" else UNMARKED
    server.serve_forever()


def inspect(service):
    with urlopen(f"http://{service}:8080/result", timeout=8) as response:
        body = json.load(response)
        assert set(body) == {"text"} and isinstance(body["text"], str)
    text = body["text"]
    key = KEY_FILE.read_bytes()
    normalized = " ".join(_normalize(text)).upper()
    return {"served_text": verify_synthetic(text, key),
            "normalized_text": verify_synthetic(normalized, key),
            "benign_unrelated_text": verify_synthetic(
                "A bicycle leaned beside the red brick wall after the rain.", key)}


if __name__ == "__main__":
    if sys.argv[1] == "verify":
        print(json.dumps(inspect(sys.argv[2]), sort_keys=True))
    else:
        serve(sys.argv[1])
