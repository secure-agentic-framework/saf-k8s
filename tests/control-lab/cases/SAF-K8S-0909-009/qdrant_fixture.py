"""Stdlib-only client for the fixed synthetic Qdrant RBAC fixture."""
import json
import ssl
import sys
import urllib.error
import urllib.request

ALPHA = "fixture-alpha"
BETA = "fixture-beta"
ADMIN_PROBE = "fixture-admin-boundary"
ADMIN_VECTORS = {"vectors": {"size": 2, "distance": "Dot"}}


def request(url, token, path, method="GET", body=None):
    data = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    headers = {"api-key": token} if token else {}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url + path, data=data, headers=headers, method=method)
    context = ssl.create_default_context(cafile="/trust/ca.crt")
    try:
        with urllib.request.urlopen(req, context=context, timeout=8) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        # Consume only status; never copy error bodies or credentials to output.
        error.read()
        return error.code, {}


def scroll(url, token, collection):
    return request(url, token, f"/collections/{collection}/points/scroll", "POST",
                   {"limit": 10, "with_payload": True, "with_vector": False})


def upsert(url, token, collection, point_id, marker):
    return request(url, token, f"/collections/{collection}/points?wait=true", "PUT", {
        "points": [{"id": point_id, "vector": [0.25, 0.75],
                    "payload": {"marker": marker, "fixture": "synthetic"}}]})


def point_count(url, token, collection):
    status, result = request(url, token, f"/collections/{collection}/points/count", "POST",
                             {"exact": True})
    return status, result.get("result", {}).get("count")


def collection_exists(url, token):
    status, result = request(url, token, f"/collections/{ADMIN_PROBE}/exists")
    return status, result.get("result", {}).get("exists") if status == 200 else None


def main():
    op, url = sys.argv[1:3]
    token = open("/identity/token", encoding="utf-8").read().strip()

    if op == "admin-probe-create":
        status, _ = request(url, token, f"/collections/{ADMIN_PROBE}",
                            "PUT", ADMIN_VECTORS)
        print(json.dumps({"status": status}, sort_keys=True))
        return

    if op == "admin-probe-exists":
        status, exists = collection_exists(url, token)
        print(json.dumps({"status": status, "exists": exists}, sort_keys=True))
        return

    if op == "admin-probe-inspect":
        status, result = request(url, token, f"/collections/{ADMIN_PROBE}")
        print(json.dumps({"metadata_read": status == 200 and result.get("status") == "ok"},
                         sort_keys=True))
        return

    if op == "admin-probe-delete":
        status, _ = request(url, token, f"/collections/{ADMIN_PROBE}", "DELETE")
        print(json.dumps({"status": status}, sort_keys=True))
        return
    if op == "initialize":
        ready = True
        for collection in (ALPHA, BETA):
            status, _ = request(url, token, "/collections/" + collection, "PUT",
                                {"vectors": {"size": 2, "distance": "Dot"}})
            ready = ready and status in (200, 201)
            status, _ = upsert(url, token, collection,
                               {ALPHA: 2, BETA: 3}[collection],
                               {ALPHA: "synthetic-alpha",
                                BETA: "synthetic-beta"}[collection])
            ready = ready and status in (200, 201)
        print(json.dumps({"collections_ready": ready}, sort_keys=True))
        return

    if op == "anonymous":
        status, _ = scroll(url, None, ALPHA)
        print(json.dumps({"status": status}))
        return

    if op == "baseline":
        markers = []
        for collection in (ALPHA, BETA):
            status, result = scroll(url, token, collection)
            if status == 200:
                markers.extend(point["payload"]["marker"] for point in result["result"]["points"])
        print(json.dumps({"markers": markers}, sort_keys=True))
        return

    if op == "count":
        collection = sys.argv[3]
        if collection not in (ALPHA, BETA):
            raise ValueError("unknown fixture collection")
        status, count = point_count(url, token, collection)
        print(json.dumps({"status": status, "count": count}, sort_keys=True))
        return

    if op == "governed":
        # The fixture role label is passed by the local runner, independent of token contents.
        own = sys.argv[3] if len(sys.argv) > 3 else ""
        if own not in (ALPHA, BETA):
            raise SystemExit("missing fixture principal label")
        opposite = BETA if own == ALPHA else ALPHA
        own_status, own_data = scroll(url, token, own)
        write_status, _ = upsert(url, token, own, 44 if own == ALPHA else 45,
                                 "synthetic-alpha-write" if own == ALPHA else "synthetic-beta-write")
        count_status, count = point_count(url, token, own)
        denied_read, _ = scroll(url, token, opposite)
        denied_write, _ = upsert(url, token, opposite, 9901,
                                 "synthetic-opposite-write-probe")
        points = own_data.get("result", {}).get("points", [])
        marker = points[0].get("payload", {}).get("marker") if points else None
        print(json.dumps({"own_read": own_status == 200 and bool(points),
            "own_write": write_status in (200, 201) and count_status == 200,
            "own_count": count,
            "own_marker": marker, "opposite_read_status": denied_read,
            "opposite_write_status": denied_write,
            "opposite_read_denied": denied_read in (401, 403)}, sort_keys=True))
        return
    raise SystemExit("unknown fixture operation")
if __name__ == "__main__":
    main()
