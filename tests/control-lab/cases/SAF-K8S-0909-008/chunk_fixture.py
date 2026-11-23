"""Synthetic, deterministic classification-aware chunk/storage fixture."""
from __future__ import annotations

from contextlib import closing
import json
import sqlite3
import ssl
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

AUDIENCE = "saf-rag-fixture"
NS = "saf-test"
APPROVAL = "/approval/approved.json"
DB = "/data/rag-fixture.sqlite3"
TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
API_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
API_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
CLASS_ORDER = ("public", "confidential")


def approval():
    return json.loads(Path(APPROVAL).read_text())


def chunks(text, size):
    words = text.split()
    return [" ".join(words[i:i + size]) for i in range(0, len(words), size)]


def token_review(token):
    request = urllib.request.Request(
        "https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews",
        data=json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                         "spec": {"token": token, "audiences": [AUDIENCE]}}).encode(),
        headers={"Authorization": "Bearer " + Path(API_TOKEN).read_text().strip(),
                 "Content-Type": "application/json"}, method="POST")
    context = ssl.create_default_context(cafile=API_CA)
    with urllib.request.urlopen(request, context=context, timeout=5) as response:
        result = json.load(response)
    status = result.get("status", {})
    if not status.get("authenticated") or AUDIENCE not in status.get("audiences", []):
        return None
    return status.get("user", {}).get("username")


def principal_policy(username, config):
    for name, entry in config["principals"].items():
        if username == f"system:serviceaccount:{NS}:{name}":
            return entry
    return None


def vector(text):
    words = text.split()
    return [len(words), sum(len(word) for word in words)]


def database():
    con = sqlite3.connect(DB)
    for table in CLASS_ORDER:
        con.execute(f"""CREATE TABLE IF NOT EXISTS {table} (
          doc TEXT, section TEXT, ordinal INTEGER, classification TEXT CHECK(classification='{table}'),
          text TEXT, vector TEXT, PRIMARY KEY(doc, section, ordinal))""")
    con.commit()
    return con


def insert(con, config, doc, section, ordinal, text, label, destination):
    expected = section["classification"]
    table = config["destinations"].get(expected)
    if label != expected or destination != table or table not in CLASS_ORDER:
        raise ValueError("Unapproved section classification or destination")
    con.execute(f"INSERT INTO {table} VALUES (?, ?, ?, ?, ?, ?)",
                (doc, section["id"], ordinal, label, text, json.dumps(vector(text))))


def contents(con, table):
    return con.execute(f"SELECT section, ordinal, classification, text, vector FROM {table} "
                       "ORDER BY section, ordinal").fetchall()


def ingest(con, config):
    for document in config["documents"]:
        for section in document["sections"]:
            label = section["classification"]
            for index, text in enumerate(chunks(section["text"], config["chunk_words"])):
                insert(con, config, document["id"], section, index, text, label, config["destinations"][label])
    before = {table: contents(con, table) for table in CLASS_ORDER}
    sections = config["documents"][0]["sections"]
    detail = next(section for section in sections if section["id"] == "detail")
    rejections = []
    for name, label, destination in (
        ("misclassified", "public", "public"), ("missing-label", None, "public"),
        ("wrong-destination", "confidential", "public"),
    ):
        try:
            insert(con, config, config["documents"][0]["id"], detail, 99, "fixed fixture", label, destination)
        except ValueError:
            rejections.append(name)
    after = {table: contents(con, table) for table in CLASS_ORDER}
    return {"status": 200, "rejections": rejections, "state_unchanged": before == after,
            "counts": {table: len(rows) for table, rows in after.items()}}


def baseline(con, endpoint):
    if endpoint != "/retrieve/public":
        return {"status": 404}
    return {"status": 200, "texts": [row[0] for row in con.execute("SELECT text FROM shared")]}


def governed(con, endpoint, identity, config):
    if endpoint == "/ingest":
        if not identity.get("writer"):
            return {"status": 403}
        return ingest(con, config)
    if not endpoint.startswith("/retrieve/"):
        return {"status": 404}
    classification = endpoint.removeprefix("/retrieve/")
    if classification not in identity["classifications"]:
        return {"status": 403}
    table = config["destinations"][classification]
    if table not in CLASS_ORDER:
        return {"status": 503}
    rows = [list(row[:4])+[json.loads(row[4])] for row in contents(con, table)]
    return {"status": 200, "rows": rows}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        config = approval()
        auth = self.headers.get("Authorization", "")
        try:
            identity = principal_policy(token_review(auth[7:]), config) if auth.startswith("Bearer ") else None
            if identity is None:
                payload = {"status": 401}
            else:
                with closing(database()) as con, con:
                    if self.server.mode == "baseline":
                        payload = baseline(con, self.path)
                    else:
                        payload = governed(con, self.path, identity, config)
        except (OSError, sqlite3.Error):
            payload = {"status": 503}
        encoded = json.dumps(payload, sort_keys=True).encode()
        self.send_response(payload["status"])
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        pass


def serve(mode):
    if mode == "baseline":
        with closing(database()) as con, con:
            con.execute("CREATE TABLE shared (text TEXT)")
            detail = approval()["documents"][0]["sections"][1]
            con.execute("INSERT INTO shared VALUES (?)", (detail["text"].split()[0],))
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    server.mode = mode
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def client(op, endpoint):
    token = Path(TOKEN).read_text().strip()
    request = urllib.request.Request(endpoint.rstrip("/") + "/" + op, data=b"{}",
                                     headers={"Authorization": "Bearer " + token}, method="POST")
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    try:
        response = urllib.request.urlopen(request, context=context, timeout=15)
    except urllib.error.HTTPError as denied:
        response = denied
    with response:
        data = json.load(response)
        if data["status"] != response.status:
            raise RuntimeError("The fixture returned an inconsistent HTTP status")
        print(json.dumps(data, sort_keys=True))


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(sys.argv[2])
    else:
        client(sys.argv[1], sys.argv[2])
