"""Tiny deterministic embedding pipeline; fixed benign inputs only."""
import hashlib
import json
import re
import sys
from pathlib import Path

MODEL_FORMAT = "saf-tiny-embedding/1"
DOCUMENT_FORMAT = b"SYNTH-DOC/1\n"
APPROVED_MODEL_SHA256 = "e3a1d0077990215bb53a9b38b66dda648bf7968114546f64acd592f2378cb789"
APPROVED_DOCUMENT_SHA256 = "36ed7b8ba18acebc540be08fdc34e14b8f96db6713254c67e9dd3546fd9e5817"
MALFORMED_DOCUMENT_SHA256 = "37bb5dbb559aecfcfa149acf3575b51224521c8cbbc1459bb9cbefda5231896d"
EXPECTED_VECTOR = (0.5, 0.75, 1.0)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_model(path, enforce_pin):
    raw = Path(path).read_bytes()
    actual = digest(raw)
    if enforce_pin and actual != APPROVED_MODEL_SHA256:
        return {"event": "model_rejected", "reason": "digest_mismatch",
                "approved_model_sha256": APPROVED_MODEL_SHA256,
                "observed_model_sha256": actual, "vector_emitted": False,
                "embed_calls": 0}
    try:
        parsed = json.loads(raw.decode("utf-8", errors="strict"))
        tokens = parsed["tokens"]
        rows = parsed["matrix"]
        if (parsed["format"] != MODEL_FORMAT or not isinstance(tokens, list)
                or not isinstance(rows, list) or len(tokens) != len(rows)
                or not tokens or any(not isinstance(t, str) or not re.fullmatch(r"[a-z]+", t)
                                     for t in tokens)
                or len(set(tokens)) != len(tokens)
                or any(not isinstance(row, list) or len(row) != 3 for row in rows)
                or any(type(value) not in (int, float) for row in rows for value in row)):
            raise ValueError("schema")
        matrix = tuple(tuple(float(value) for value in row) for row in rows)
        vocab = {token: matrix[index] for index, token in enumerate(tokens)}
        return {"digest": actual, "vocab": vocab}
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return {"event": "model_rejected", "reason": "format_invalid",
                "observed_model_sha256": actual, "vector_emitted": False,
                "embed_calls": 0}


def validate_document(path, expected_digest):
    raw = Path(path).read_bytes()
    if digest(raw) != expected_digest:
        return None, {"event": "document_rejected", "reason": "digest_mismatch",
                      "vector_emitted": False, "embed_calls": 0}
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, {"event": "document_rejected", "reason": "utf8_invalid",
                      "vector_emitted": False, "embed_calls": 0}
    if not text.startswith(DOCUMENT_FORMAT.decode("ascii")):
        return None, {"event": "document_rejected", "reason": "format_invalid",
                      "vector_emitted": False, "embed_calls": 0}
    body = text[len(DOCUMENT_FORMAT):].strip()
    if not body or not re.fullmatch(r"[a-z]+(?: [a-z]+)*", body):
        return None, {"event": "document_rejected", "reason": "format_invalid",
                      "vector_emitted": False, "embed_calls": 0}
    return body.split(" "), None


def embed(tokens, vocab):
    # Immutable tuple rows and a fixed average-of-token-vectors operation.
    if any(token not in vocab for token in tokens):
        raise ValueError("token_out_of_vocabulary")
    return tuple(sum(vocab[token][column] for token in tokens) / len(tokens)
                 for column in range(3))


def main():
    mode, model_path, document_path, malformed_path = sys.argv[1:]
    enforce_pin = mode == "pinned"
    model = load_model(model_path, enforce_pin)
    if "event" in model:
        print(json.dumps(model, sort_keys=True))
        return

    observations = []
    if mode == "pinned":
        _, rejected = validate_document(malformed_path, MALFORMED_DOCUMENT_SHA256)
        observations.append(rejected)
    tokens, rejected = validate_document(document_path, APPROVED_DOCUMENT_SHA256)
    if rejected:
        observations.append(rejected)
        print(json.dumps({"model_sha256": model["digest"], "observations": observations},
                         sort_keys=True))
        return

    vector = embed(tokens, model["vocab"])
    observations.append({"event": "embedded", "vector": vector,
                         "vector_emitted": True, "embed_calls": 1,
                         "model_sha256": model["digest"], "token_count": len(tokens),
                         "expected_vector_match": vector == EXPECTED_VECTOR})
    print(json.dumps({"observations": observations}, sort_keys=True))


if __name__ == "__main__":
    main()
