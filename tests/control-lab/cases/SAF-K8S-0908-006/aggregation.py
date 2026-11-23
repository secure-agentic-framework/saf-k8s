"""Run an additive-sharing round using separate Kubernetes identities."""
import json
from pathlib import Path
import secrets
import ssl
import sys
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

PRIME = 2**61 - 1
ROUND = "fixture-round"
MEMBERS = ("alpha", "beta")
LANES = ("east", "west")
MINIMUM = 2
API = Path("/var/run/secrets/kubernetes.io/serviceaccount")
STORE = "https://kubernetes.default.svc/api/v1/namespaces/saf-test/configmaps"


def exchange(name, document=None):
    token = (API/"token").read_text().strip()
    trust = ssl.create_default_context(cafile=str(API/"ca.crt"))
    client = build_opener(ProxyHandler({}), HTTPSHandler(context=trust))
    headers = {"Authorization": "Bearer "+token}
    data = None
    if document is not None:
        headers["Content-Type"] = "application/merge-patch+json"
        data = json.dumps({"data": document}).encode()
    request = Request(f"{STORE}/{name}", data=data, headers=headers,
                      method="GET" if document is None else "PATCH")
    try:
        response = client.open(request, timeout=6)
    except HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read()).get("data", {})


def fetch(name):
    status, result = exchange(name)
    if status != 200:
        raise ValueError(f"Fixture read of {name} returned HTTP {status}")
    return result


def replace(name, document):
    status, _ = exchange(name, document)
    if status != 200:
        raise ValueError(f"Fixture write of {name} returned HTTP {status}")


def contribute(member, value):
    if member not in MEMBERS or not 0 <= value < 100:
        raise ValueError("Contributor or value is outside the approved fixture")
    uniform = secrets.randbelow(PRIME)
    shares = (uniform, (value - uniform) % PRIME)
    for lane, share in zip(LANES, shares):
        replace(f"fixture-share-{lane}-{member}",
                {"round": ROUND, "member": member, "value": str(share)})
    return {"submitted_two_lanes": True}


def summarize(lane):
    if lane not in LANES:
        raise ValueError("Unknown fixture lane")
    cohort = []
    total = 0
    for member in MEMBERS:
        result = fetch(f"fixture-share-{lane}-{member}")
        if not result["value"]:
            continue
        share = int(result["value"])
        if result["round"] != ROUND or result["member"] != member or not 0 <= share < PRIME:
            raise ValueError("The approved round or share encoding differs")
        cohort.append(member)
        total = (total + share) % PRIME
    replace(f"fixture-total-{lane}", {"round": ROUND, "cohort": json.dumps(cohort),
                                   "total": str(total)})
    return {"named_share_record_count": len(cohort)}


def release():
    east, west = [fetch(f"fixture-total-{lane}") for lane in LANES]
    cohorts = [json.loads(item["cohort"]) for item in (east, west)]
    if (east["round"] != ROUND or west["round"] != ROUND or cohorts[0] != cohorts[1]
            or len(set(cohorts[0])) < MINIMUM or any(member not in MEMBERS for member in cohorts[0])):
        return {"decision": "held", "reason": "cohort-policy"}
    totals = [int(item["total"]) for item in (east, west)]
    if not all(0 <= total < PRIME for total in totals):
        raise ValueError("An aggregate share outside the approved field was received")
    return {"decision": "released", "contributors": len(cohorts[0]), "sum": sum(totals) % PRIME}


def observe(name, expected=None):
    status, result = exchange(name)
    response = {"status": status}
    if status == 200 and expected is not None:
        response["marker_matches"] = result.get("value") == expected
    return response


def main():
    operation, *args = sys.argv[1:]
    if operation == "contribute":
        result = contribute(args[0], int(args[1]))
    elif operation == "summarize":
        result = summarize(*args)
    elif operation == "release":
        result = release()
    elif operation == "observe":
        result = observe(*args)
    else:
        raise ValueError("Unknown fixture operation")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
