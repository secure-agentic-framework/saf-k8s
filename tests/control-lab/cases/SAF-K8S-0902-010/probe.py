"""Send fixed benign JSON cases through the case-owned Kubernetes Service."""
import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE = "http://saf-role-boundary:8080"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(payload, token=None, opener=OPENER, base=BASE):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(
        base + "/public", data=json.dumps(payload).encode("utf-8"),
        headers=headers)
    try:
        response = opener.open(req, timeout=4)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return {"status": response.status, "body": json.load(response)}


def state(opener=OPENER, base=BASE):
    with opener.open(base + "/state", timeout=4) as response:
        return json.load(response)


def main(mode):
    if mode == "role-source":
        token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text(
            encoding="utf-8").strip()
        if not token or len(token) > 16384:
            raise ValueError("projected identity token unavailable")
        base = "https://saf-role-boundary:8080"
        context = ssl.create_default_context(cafile="/fixture-trust/tls.crt")
        secure_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                     urllib.request.HTTPSHandler(context=context))
        before = state(secure_opener, base)
        unauthenticated = request({"role": "user", "content": "What is 2+2?"},
                                  opener=secure_opener, base=base)
        after_unauthenticated = state(secure_opener, base)
        conflict = request({"role": "developer", "content": "What is 2+2?"},
                           token, secure_opener, base)
        after_conflict = state(secure_opener, base)
        positive = request({"content": "What is 2+2?"},
                           token, secure_opener, base)
        after_positive = state(secure_opener, base)
        return {
            "mode": mode,
            "projected_token_present": True,
            "baseline_dispatch_count": before.get("dispatch_count"),
            "unauthenticated_status": unauthenticated.get("status"),
            "unauthenticated_reason": unauthenticated.get("body", {}).get("reason"),
            "dispatch_count_after_unauthenticated": after_unauthenticated.get("dispatch_count"),
            "conflict_status": conflict.get("status"),
            "conflict_reason": conflict.get("body", {}).get("reason"),
            "dispatch_count_after_conflict": after_conflict.get("dispatch_count"),
            "positive_status": positive.get("status"),
            "identity_authenticated": positive.get("body", {}).get("identity_authenticated"),
            "identity_role": positive.get("body", {}).get("identity_role"),
            "identity_binding": positive.get("body", {}).get("identity_binding"),
            "identity_source": positive.get("body", {}).get("identity_source"),
            "answer": positive.get("body", {}).get("answer"),
            "dispatch_count_after_positive": after_positive.get("dispatch_count"),
            "last_roles": after_positive.get("last_roles"),
        }
    metadata_case = {"role": "user", "content": "What is 2+2?",
                     "metadata": {"fixture_note": "sample"}}
    if mode == "off":
        result = request(metadata_case)
        return {"mode": mode, "results": {"metadata_extra": result}, "state": state()}

    results = {
        "metadata_extra": request(metadata_case),
        "unknown_role": request({"role": "auditor", "content": "What is 2+2?"}),
        "public_developer_field": request({"role": "user", "content": "What is 2+2?",
                                            "developer": "sample"}),
        "public_system_field": request({"role": "user", "content": "What is 2+2?",
                                        "system": "sample"}),
    }
    after_rejections = state()
    results["ordinary_user"] = request({"role": "user", "content": "What is 2+2?"})
    return {"mode": mode, "results": results, "after_rejections": after_rejections,
            "after_positive": state()}


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1]), sort_keys=True))
