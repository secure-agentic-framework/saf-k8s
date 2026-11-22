"""Owned mock streaming endpoint with a bounded cross-chunk marker filter."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Event
from urllib.parse import parse_qs, urlsplit


FIXTURE = json.loads(Path("/case/fixtures.json").read_text())
ALLOWED = FIXTURE["permitted_marker"]
FORBIDDEN = FIXTURE["forbidden_dummy_marker"]
REPLACEMENT = FIXTURE["replacement"]
CHUNKS = FIXTURE["chunks"]
LIMITS = FIXTURE["limits"]
MAX_MARKER = len(FORBIDDEN)
ADVANCE = {'on': Event(), 'off': Event()}


def filter_chunks(chunks):
    """Yield output chunks while withholding a fixed marker across chunk seams.

    Pending text is bounded by one fixture chunk plus the longest marker window.
    This fixture scanner recognizes exactly one dummy marker, not data classes.
    """
    pending = ""
    redactions = 0
    for chunk in chunks:
        if len(chunk.encode("utf-8")) > LIMITS["max_chunk_bytes"]:
            raise ValueError("fixture chunk exceeds configured bound")
        pending += chunk
        while len(pending) >= MAX_MARKER:
            position = pending.find(FORBIDDEN)
            if position >= 0:
                if position:
                    yield pending[:position]
                yield REPLACEMENT
                redactions += 1
                pending = pending[position + len(FORBIDDEN):]
                continue
            releasable = len(pending) - MAX_MARKER + 1
            if releasable <= 0:
                break
            yield pending[:releasable]
            pending = pending[releasable:]
    while pending:
        position = pending.find(FORBIDDEN)
        if position < 0:
            yield pending
            break
        if position:
            yield pending[:position]
        yield REPLACEMENT
        redactions += 1
        pending = pending[position + len(FORBIDDEN):]
    return redactions


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        target = urlsplit(self.path)
        if target.path == "/healthz":
            self.empty_response(204)
            return
        query = parse_qs(target.query)
        if query.get("filter") not in (["on"], ["off"]):
            self.send_error(404)
            return
        mode = query["filter"][0]
        if target.path == "/advance":
            ADVANCE[mode].set()
            self.empty_response(204)
            return
        if target.path != "/stream":
            self.send_error(404)
            return
        ADVANCE[mode].clear()
        enabled = mode == "on"
        # The fixture bounds total source size before any bytes are sent.
        total = sum(len(part.encode("utf-8")) for part in CHUNKS)
        if total > LIMITS["max_response_bytes"]:
            self.send_error(500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-SAF-Filter", "enabled" if enabled else "disabled")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            source = self.source_chunks(mode)
            for output in filter_chunks(source) if enabled else source:
                encoded = output.encode("utf-8")
                if encoded:
                    self.wfile.write(f"{len(encoded):x}\r\n".encode("ascii") + encoded + b"\r\n")
                    self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            return

    @staticmethod
    def source_chunks(mode):
        # The client must see a prefix before the remaining source bytes exist on this response.
        yield CHUNKS[0]
        if not ADVANCE[mode].wait(timeout=8):
            raise TimeoutError("fixture client did not acknowledge the streamed prefix")
        yield from CHUNKS[1:]

    def empty_response(self, status):
        self.send_response(status)
        self.end_headers()

    def log_message(self, _format, *_args):
        # Suppress request paths and response data from container logs.
        return


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
