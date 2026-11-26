"""Revoke the named fixture Secret using the CronJob's own Kubernetes identity."""
import json
from pathlib import Path
import ssl
from urllib.error import URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

APPROVED = {"approval_id": "saf-lab-0402-002-approval-001",
            "credential": "saf-0402-002-unused-legacy", "decision": "approved"}


def main():
    if json.loads(Path("/decision/review.json").read_text()) != APPROVED:
        raise SystemExit("Unapproved fixture retirement decision")
    mount = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    trust = ssl.create_default_context(cafile=str(mount / "ca.crt"))
    token = (mount / "token").read_text().strip()
    client = build_opener(ProxyHandler({}), HTTPSHandler(context=trust))
    request = Request(
        "https://kubernetes.default.svc/api/v1/namespaces/saf-test/secrets/" + APPROVED["credential"],
        headers={"Authorization": "Bearer " + token}, method="DELETE",
    )
    try:
        with client.open(request, timeout=8) as result:
            success = result.status in (200, 202)
    except (URLError, OSError):
        success = False
    print(json.dumps({"approved_credential_deleted": success}))
    if not success:
        raise SystemExit("The native API did not revoke the approved fixture credential")


if __name__ == "__main__":
    main()
