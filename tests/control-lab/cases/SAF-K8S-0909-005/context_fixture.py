"""Deterministic local request boundary and consumer for the RAG lab."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import sys
from typing import Any, TypedDict
from urllib.request import Request, urlopen


class NoteMetadata(TypedDict):
    topic: str
    visibility: str


class RetrievedNote(TypedDict):
    record_id: str
    source_id: str
    version: int
    text: str
    metadata: NoteMetadata


class Message(TypedDict):
    role: str
    content: str


class ContextRequest(TypedDict):
    mode: str
    messages: list[Message]
    records: list[RetrievedNote]


EXPECTED_NOTE: RetrievedNote = {
    "record_id": "note-cedar-v1",
    "source_id": "synthetic://approved/field-guide",
    "version": 1,
    "text": "Cedar sample color is amber.",
    "metadata": {"topic": "sample-facts", "visibility": "public"},
}
QUESTION = "What color is the cedar sample?"
ANSWER = "Cedar sample color is amber."
SYSTEM_MESSAGE = "Answer the user's question using the supplied approved reference records."


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(note: RetrievedNote) -> str:
    return hashlib.sha256(canonical(note)).hexdigest()


def schema_ok(note: Any) -> bool:
    if not isinstance(note, dict) or set(note) != {"record_id", "source_id", "version", "text", "metadata"}:
        return False
    if (type(note["record_id"]) is not str or type(note["source_id"]) is not str
            or type(note["version"]) is not int or type(note["text"]) is not str
            or not isinstance(note["metadata"], dict)
            or set(note["metadata"]) != {"topic", "visibility"}
            or any(type(value) is not str for value in note["metadata"].values())):
        return False
    return True


def validate(note: Any, approval: dict[str, Any]) -> tuple[bool, dict[str, bool]]:
    shape = schema_ok(note)
    provenance = shape and note["source_id"] == approval["source_id"] and note["version"] == approval["version"]
    exact_record = shape and note == approval["record"]
    exact_digest = shape and digest(note) == approval["sha256"]
    checks = {"exact_schema": shape, "approved_provenance": provenance,
              "exact_record": exact_record, "approved_digest": exact_digest}
    return all(checks.values()), checks


def make_request(mode: str, note: RetrievedNote) -> tuple[ContextRequest, dict[str, bool]]:
    if mode == "baseline":
        record_json = json.dumps(note, sort_keys=True, separators=(",", ":"))
        request: ContextRequest = {
            "mode": "baseline",
            "messages": [{"role": "system", "content": "Retrieved reference record: " + record_json}],
            "records": [note],
        }
        return request, {"validated": False}
    if mode != "governed":
        raise ValueError("unknown mode")
    with open("/approval/approved.json", encoding="utf-8") as stream:
        approval = json.load(stream)
    accepted, checks = validate(note, approval)
    if not accepted:
        raise ValueError("record failed schema or provenance validation")
    request = {
        "mode": "governed",
        "messages": [{"role": "system", "content": SYSTEM_MESSAGE},
                     {"role": "user", "content": QUESTION}],
        "records": [note],
    }
    return request, checks


def answer(request: ContextRequest) -> dict[str, Any]:
    # The fixture consumer's output is deterministic and has no model or tool dependency.
    valid_roles = [message["role"] for message in request["messages"]]
    records = request.get("records", [])
    if request["mode"] == "baseline":
        serialized_note = json.dumps(EXPECTED_NOTE, sort_keys=True, separators=(",", ":"))
        baseline_record_in_system = (len(request["messages"]) == 1
                                     and request["messages"][0]["role"] == "system"
                                     and serialized_note in request["messages"][0]["content"])
        has_fact = baseline_record_in_system and records == [EXPECTED_NOTE]
        fixed_application_messages = False
    else:
        baseline_record_in_system = False
        fixed_application_messages = request["messages"] == [
            {"role": "system", "content": SYSTEM_MESSAGE},
            {"role": "user", "content": QUESTION},
        ]
        has_fact = records == [EXPECTED_NOTE] and fixed_application_messages
    output = ANSWER if has_fact else "No approved sample fact is available."
    return {"message_roles": valid_roles, "records": records, "output": output,
            "baseline_record_in_system": baseline_record_in_system,
            "fixed_application_messages": fixed_application_messages}


class ConsumerHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/count":
            self.send_error(404)
            return
        payload = canonical({"requests": self.server.requests})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        if self.path != "/consume":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        observed = answer(request)
        self.server.requests += 1
        payload = json.dumps(observed, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args: Any) -> None:
        return


def serve() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8080), ConsumerHandler)
    server.requests = 0
    server.serve_forever()


def exchange(url: str, request: ContextRequest) -> dict[str, Any]:
    data = canonical(request)
    call = Request(url.rstrip("/") + "/consume", data=data,
                   headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(call, timeout=8) as response:
        return json.loads(response.read())


def exercise(url: str, mode: str) -> dict[str, Any]:
    with open("/source/note.json", encoding="utf-8") as stream:
        note: RetrievedNote = json.load(stream)
    request, checks = make_request(mode, note)
    observed = exchange(url, request)
    result: dict[str, Any] = {"checks": checks, "consumer": observed}
    if mode == "governed":
        # Benign content change and an extra metadata field must fail closed.
        changed = dict(note, text="Cedar sample color is blue.")
        unapproved_source = dict(note, source_id="synthetic://unapproved/field-guide")
        extra = dict(note, metadata={**note["metadata"], "region_hint": "cedar"})
        def receipt_count():
            with urlopen(url.rstrip("/") + "/count", timeout=8) as response:
                return json.load(response)["requests"]
        before = receipt_count()
        denied = []
        for label, candidate in (("benign_content_change", changed),
                                 ("unapproved_source", unapproved_source),
                                 ("extra_metadata_field", extra)):
            try:
                prepared, _ = make_request("governed", candidate)
            except ValueError:
                denied.append(label)
            else:
                exchange(url, prepared)
        result["negative_validation"] = {
            item+"_rejected": item in denied for item in
            ("benign_content_change", "unapproved_source", "extra_metadata_field")}
        result["negative_validation"]["consumer_count_unchanged"] = receipt_count() == before
    return result


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    elif sys.argv[1] == "exercise":
        print(json.dumps(exercise(sys.argv[2], sys.argv[3]), sort_keys=True))
    else:
        raise SystemExit("usage: context_fixture.py serve | exercise URL MODE")
