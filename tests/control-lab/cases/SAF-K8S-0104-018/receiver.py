"""Accept only the inert test messages addressed to the fixture review queue."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sqlite3


RECIPIENT = "fixture-platform-oncall"
CASES = {
    ("kubernetes-json-feed", "CVE-2099-0001", "advisory"),
    ("kubernetes-json-feed", "http-503", "source_error"),
    ("aws-security-bulletin-rss", "fixture:aws:001", "advisory"),
}
STORE = "/receipts/fixture.sqlite"


class Queue(BaseHTTPRequestHandler):
    def response(self, status, value):
        data = json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/notify":
            self.response(404, {"accepted": False})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 4096:
                raise ValueError("unexpected receipt size")
            row = json.loads(self.rfile.read(length))
            key = row["source"], row["event_id"], row["kind"]
            if row["recipient"] != RECIPIENT or key not in CASES:
                raise ValueError("unexpected fixture event")
        except (TypeError, ValueError, KeyError):
            self.response(400, {"accepted": False})
            return
        with sqlite3.connect(STORE) as db:
            inserted = db.execute(
                "INSERT OR IGNORE INTO receipts VALUES(?,?,?,?)", (*key, RECIPIENT),
            ).rowcount == 1
        self.response(201 if inserted else 200, {"accepted": True, "duplicate": not inserted})

    def do_GET(self):
        if self.path != "/receipts":
            self.response(404, {"accepted": False})
            return
        fields = ("source", "event_id", "kind", "recipient")
        with sqlite3.connect(STORE) as db:
            rows = db.execute("SELECT * FROM receipts ORDER BY source, event_id").fetchall()
        self.response(200, [dict(zip(fields, row)) for row in rows])


if __name__ == "__main__":
    with sqlite3.connect(STORE) as db:
        db.execute("CREATE TABLE IF NOT EXISTS receipts (source TEXT, event_id TEXT, kind TEXT, recipient TEXT, "
                   "PRIMARY KEY(source,event_id,kind,recipient))")
    HTTPServer(("0.0.0.0", 8080), Queue).serve_forever()
