"""Send fixed benign JSON cases through the case-owned Kubernetes Service."""
import json
import sys
import urllib.error
import urllib.request

BASE = "http://saf-role-boundary:8080"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(payload):
    req = urllib.request.Request(
        BASE + "/public", data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    try:
        response = OPENER.open(req, timeout=4)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return {"status": response.status, "body": json.load(response)}


def state():
    with OPENER.open(BASE + "/state", timeout=4) as response:
        return json.load(response)


def main(mode):
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
