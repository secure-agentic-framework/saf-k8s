"""Four non-retrying in-cluster HTTPS reads for the owned APF fixture."""
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import sys
import threading


HOST = "kubernetes.default.svc"
PORT = 443
PATH = "/api/v1/namespaces/saf-test/configmaps/saf-apf-inert-read"
EXPECTED_NAME = "saf-apf-inert-read"
EXPECTED_MARKER_LENGTH = 65536
MAX_BODY = 131072
WORKERS = 4
TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("queue", "reject"):
        raise SystemExit(2)
    mode = sys.argv[1]
    projection_available = False
    tls_context = None
    token = ""
    try:
        token = TOKEN_PATH.read_text(encoding="ascii").strip()
        tls_context = ssl.create_default_context(cafile=str(CA_PATH))
        projection_available = bool(token and tls_context.check_hostname
                                    and tls_context.verify_mode == ssl.CERT_REQUIRED)
    except (OSError, UnicodeError, ssl.SSLError):
        projection_available = False
    if not projection_available:
        print(json.dumps({
            "projection_available": False,
            "tls_verified_for_all": False,
            "all_responses_classified_to_fixture": False,
            "all_reads_succeeded_with_exact_fixture": False,
            "has_expected_rejection": False,
            "only_expected_statuses": False,
        }, sort_keys=True))
        return 0

    expected_flow_hash = os.environ.get("EXPECTED_FLOW_UID_SHA256", "")
    expected_priority_hash = os.environ.get("EXPECTED_PRIORITY_UID_SHA256", "")
    barrier = threading.Barrier(WORKERS)

    def one_read(_index):
        connection = http.client.HTTPSConnection(
            HOST, PORT, timeout=6, context=tls_context,
        )
        try:
            # Complete verified TLS before synchronizing the HTTP requests.
            connection.connect()
            barrier.wait(timeout=3)
            connection.request(
                "GET", PATH,
                headers={"Authorization": f"Bearer {token}",
                         "Accept": "application/json",
                         "Connection": "close",
                         "User-Agent": "saf-apf-bounded-reference/1"},
            )
            response = connection.getresponse()
            status = response.status
            flow_uid = response.getheader("X-Kubernetes-PF-FlowSchema-UID")
            priority_uid = response.getheader("X-Kubernetes-PF-PriorityLevel-UID")
            exact_object = False
            if status == 200:
                payload = response.read(MAX_BODY + 1)
                if len(payload) <= MAX_BODY:
                    try:
                        document = json.loads(payload)
                        marker = document.get("data", {}).get("marker", "")
                        exact_object = (
                            document.get("kind") == "ConfigMap"
                            and document.get("metadata", {}).get("name") == EXPECTED_NAME
                            and len(marker) == EXPECTED_MARKER_LENGTH
                            and set(marker) == {"A"}
                        )
                    except (UnicodeError, json.JSONDecodeError, AttributeError, TypeError):
                        exact_object = False
            # http.client does not retry or follow redirects. Closing each
            # connection also prevents implicit reuse between requests.
            return {
                "tls_verified": True,
                "status": status,
                "owned_classification": bool(
                    flow_uid and priority_uid and len(expected_flow_hash) == 64
                    and hashlib.sha256(flow_uid.encode()).hexdigest() == expected_flow_hash
                    and hashlib.sha256(priority_uid.encode()).hexdigest() == expected_priority_hash
                ),
                "exact_object": exact_object,
            }
        except (OSError, ssl.SSLError, TimeoutError,
                threading.BrokenBarrierError, http.client.HTTPException):
            return {"tls_verified": False, "status": None,
                    "owned_classification": False, "exact_object": False}
        finally:
            connection.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(one_read, range(WORKERS)))
    statuses = [item["status"] for item in results]
    report = {
        "projection_available": projection_available,
        "tls_verified_for_all": all(item["tls_verified"] for item in results),
        "all_responses_classified_to_fixture": all(
            item["owned_classification"] for item in results
        ),
        "all_reads_succeeded_with_exact_fixture": all(
            item["status"] == 200 and item["exact_object"] for item in results
        ),
        "has_expected_rejection": mode == "reject" and 429 in statuses,
        "only_expected_statuses": all(
            status in ((200,) if mode == "queue" else (200, 429))
            for status in statuses
        ),
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
