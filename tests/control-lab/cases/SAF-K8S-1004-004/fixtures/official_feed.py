"""Read only bounded identity and timestamp fields from the official feed."""
from datetime import datetime, timezone
import hashlib
import json
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request


SOURCE = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
VERSION = "https://jsonfeed.org/version/1.1"
MAX_BYTES = 2 * 1024 * 1024
IDENTIFIER = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch():
    context = ssl.create_default_context()
    opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context))
    req = Request(SOURCE, headers={"Accept": "application/json"})
    with opener.open(req, timeout=14) as reply:
        return reply.status, reply.headers.get_content_type(), reply.read(MAX_BYTES + 1)


def parse_timestamp(value):
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise ValueError("timestamp does not match the published UTC format")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def project(payload, retrieved_at):
    document = json.loads(payload)
    if document["feed_url"] != SOURCE or document["version"] != VERSION:
        raise ValueError("the source or schema identifier differs")
    updated = parse_timestamp(document["_kubernetes_io"]["updated_at"])
    rows = document["items"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("the official feed returned no records")
    projected = {}
    for row in rows:
        ident, when = row["id"], row["date_published"]
        if not isinstance(ident, str) or not IDENTIFIER.fullmatch(ident) or ident in projected:
            raise ValueError("record identifier is malformed or repeated")
        published = parse_timestamp(when)
        if not published <= updated <= retrieved_at:
            raise ValueError("source timestamps are out of order")
        projected[ident] = when
    canonical = json.dumps(projected, sort_keys=True, separators=(",", ":")).encode()
    return {
        "version": VERSION, "source_updated_at": updated.isoformat(),
        "latest_record_published_at": max(projected.values()),
        "unique_records": len(projected), "metadata_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def main():
    try:
        status, media_type, payload = fetch()
    except (HTTPError, URLError, OSError) as error:
        print(json.dumps({"read_status": "unavailable", "exception_type": type(error).__name__}))
        return
    retrieved_at = datetime.now(timezone.utc)
    result = {
        "read_status": "received", "source": SOURCE, "ssl_default_verification": True,
        "http_status": status, "media_type": media_type, "body_bytes": len(payload),
        "body_sha256": hashlib.sha256(payload).hexdigest(), "retrieved_at": retrieved_at.isoformat(),
    }
    try:
        if status != 200 or media_type != "application/json" or len(payload) > MAX_BYTES:
            raise ValueError("response status, media type, or size outside the approved feed")
        result["projection"] = project(payload, retrieved_at)
    except (KeyError, TypeError, ValueError) as error:
        result["projection_error"] = type(error).__name__
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
