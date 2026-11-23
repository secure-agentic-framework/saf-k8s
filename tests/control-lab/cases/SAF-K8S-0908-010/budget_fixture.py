"""Local one-bit release fixture with an atomic SQLite privacy ledger.

This is an intentionally small test mechanism, not a general DP accountant.
One draw from {0,1,2,3} returns 1 for three values and 0 for one value,
so replacing the protected bit has exact pure-DP cost ln(3) per release.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import sqlite3
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from mechanism import REGISTRY, review, sample

DB = Path("/ledger/budget.sqlite3")
LIMIT_UNITS = 2
SYNTHETIC_BITS = {"protected-population": 1, "independent-population": 0}


def connect():
    DB.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB, timeout=15, isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("""CREATE TABLE IF NOT EXISTS scope_ledger (
        scope TEXT PRIMARY KEY, epsilon_units INTEGER NOT NULL DEFAULT 0,
        random_draws INTEGER NOT NULL DEFAULT 0)""")
    db.execute("""CREATE TABLE IF NOT EXISTS release_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL,
        epsilon_units INTEGER NOT NULL, synthetic_bit INTEGER NOT NULL)""")
    return db


def release(scope, caller, governed):
    # `caller` is deliberately ignored. This fixture does not authenticate callers.
    del caller
    db = connect()
    try:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT epsilon_units FROM scope_ledger WHERE scope=?", (scope,)).fetchone()
        spent = row[0] if row else 0
        if governed and spent >= LIMIT_UNITS:
            db.execute("ROLLBACK")
            return {"status": 429, "decision": "budget-exhausted"}

        # The only randomized operation occurs after the threshold check, inside
        # the serialized transaction. Its result and charge commit together.
        bit = sample(SYNTHETIC_BITS[scope], REGISTRY)
        db.execute("""INSERT INTO scope_ledger(scope, epsilon_units, random_draws)
                      VALUES(?, 1, 1)
                      ON CONFLICT(scope) DO UPDATE SET
                      epsilon_units=epsilon_units+1, random_draws=random_draws+1""", (scope,))
        db.execute("INSERT INTO release_records(scope, epsilon_units, synthetic_bit) VALUES(?,1,?)",
                   (scope, bit))
        db.execute("COMMIT")
        # One synthetic bit is returned to this local fixture caller only.
        return {"status": 200, "decision": "released", "result": bit}
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    finally:
        db.close()


def state(scope):
    db = connect()
    try:
        ledger = db.execute("SELECT epsilon_units, random_draws FROM scope_ledger WHERE scope=?",
                            (scope,)).fetchone() or (0, 0)
        records = db.execute("SELECT COUNT(*) FROM release_records WHERE scope=?", (scope,)).fetchone()[0]
        return {"epsilon_units": ledger[0], "random_draws": ledger[1], "persisted_samples": records}
    finally:
        db.close()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/release":
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                scope = body.get("scope")
                if scope not in SYNTHETIC_BITS:
                    self.send_error(400)
                    return
                response = release(scope, body.get("fixture_client", "unspecified"), self.server.governed)
                status = response["status"]
                payload = json.dumps(response, sort_keys=True).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            except (json.JSONDecodeError, TypeError, ValueError):
                self.send_error(400)
                return
            except sqlite3.Error:
                self.send_error(503)
                return
        self.send_error(404)

    def do_GET(self):
        if self.path.startswith("/state/"):
            scope = self.path.removeprefix("/state/")
            if scope not in SYNTHETIC_BITS:
                self.send_error(400)
                return
            payload = json.dumps(state(scope), sort_keys=True).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_error(404)

    def log_message(self, *_):
        pass


def serve(mode):
    server = HTTPServer(("127.0.0.1", 8080), Handler)
    server.governed = mode == "governed"
    connect().close()
    server.serve_forever()


def request(path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = Request("http://127.0.0.1:8080" + path, data=data,
                  headers={"Content-Type": "application/json"})
    try:
        result = urlopen(req, timeout=8)
    except HTTPError as denied:
        result = denied
    with result:
        body = json.loads(result.read())
        if path == "/release" and body.get("status") != result.status:
            raise ValueError("Release response disagrees with its HTTP status")
        return body


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(sys.argv[2])
    elif sys.argv[1] == "release":
        print(json.dumps(request("/release", {"scope": sys.argv[2], "fixture_client": sys.argv[3]})))
    elif sys.argv[1] == "state":
        print(json.dumps(request("/state/" + sys.argv[2])))
    elif sys.argv[1] == "review":
        print(json.dumps(review(REGISTRY), sort_keys=True))
    else:
        raise ValueError("unknown fixture operation")
