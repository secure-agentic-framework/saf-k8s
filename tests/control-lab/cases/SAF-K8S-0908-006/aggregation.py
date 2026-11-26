"""Run an additive-sharing round using separate Kubernetes identities."""
import json
from pathlib import Path
import secrets
import ssl
import sys
import hashlib
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


VECTOR_ROUND = "fixture-vector-round-v1"
VECTOR_DIMENSION = 2
VECTOR_MEMBERS = ("alpha", "beta")
VECTOR_LANES = ("east", "west")


def vector_share_name(lane, member):
    return f"fixture-vector-{lane}-{member}"


def vector_total_name(lane):
    return f"fixture-vector-total-{lane}"


def vector_receipt_name(member):
    return f"fixture-vector-receipt-{member}"


def self_username():
    token = (API / "token").read_text().strip()
    trust = ssl.create_default_context(cafile=str(API / "ca.crt"))
    client = build_opener(ProxyHandler({}), HTTPSHandler(context=trust))
    request = Request(
        "https://kubernetes.default.svc/apis/authentication.k8s.io/v1/selfsubjectreviews",
        data=json.dumps({"apiVersion": "authentication.k8s.io/v1",
                         "kind": "SelfSubjectReview"}).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        method="POST")
    with client.open(request, timeout=8) as response:
        if response.status != 201 and response.status != 200:
            raise ValueError("Kubernetes did not return the caller identity")
        return json.load(response)["status"]["userInfo"]["username"]


def bound_member(member):
    expected = f"system:serviceaccount:saf-test:fixture-aggregate-{member}"
    return member in VECTOR_MEMBERS and self_username() == expected


def vector_snapshot(member):
    if member not in VECTOR_MEMBERS:
        raise ValueError("Unknown fixture participant")
    records = [fetch(vector_share_name(lane, member)) for lane in VECTOR_LANES]
    return hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":"))
                          .encode()).hexdigest()


def contribute_vector(member, submission, vector):
    if not bound_member(member):
        return {"decision": "held", "reason": "identity-mismatch", "status": 403}
    if submission != f"{VECTOR_ROUND}-{member}" or not isinstance(vector, list) \
            or len(vector) != VECTOR_DIMENSION \
            or any(type(value) is not int or not 0 <= value < 100 for value in vector):
        return {"decision": "held", "reason": "request-policy", "status": 400}
    receipt = fetch(vector_receipt_name(member))
    if receipt.get("round") == VECTOR_ROUND and receipt.get("submission_id"):
        return {"decision": "held", "reason": "replay", "status": 409}
    masks = [secrets.randbelow(PRIME) for _ in vector]
    shares = [masks, [(value - mask) % PRIME for value, mask in zip(vector, masks)]]
    replace(vector_receipt_name(member), {"round": VECTOR_ROUND,
                                           "submission_id": submission})
    for lane, values in zip(VECTOR_LANES, shares):
        replace(vector_share_name(lane, member), {
            "round": VECTOR_ROUND, "member": member, "submission_id": submission,
            "value": json.dumps(values, separators=(",", ":")),
        })
    return {"decision": "accepted", "status": 200, "identity_bound": True,
            "submitted_lanes": len(VECTOR_LANES)}


def attempt_foreign_vector():
    if not bound_member("alpha"):
        return {"status": 403, "identity_bound": False}
    status, _ = exchange(vector_share_name("east", "beta"), {
        "round": VECTOR_ROUND, "member": "beta", "submission_id": "unauthorized",
        "value": "[0,0]",
    })
    return {"status": status, "identity_bound": True}


def observe_vector(member, lane, expected_value):
    if member not in VECTOR_MEMBERS or lane not in VECTOR_LANES or not bound_member(member):
        return {"identity_bound": False, "matches": False}
    data = fetch(vector_share_name(lane, member))
    return {"identity_bound": True, "matches": data.get("value", "") == expected_value
            and data.get("round") == VECTOR_ROUND}


def replay_probe(member, submission, vector):
    before = vector_snapshot(member)
    decision = contribute_vector(member, submission, vector)
    after = vector_snapshot(member)
    return {"decision": decision.get("decision"), "status": decision.get("status"),
            "state_unchanged": before == after}


def summarize_vector(lane):
    if lane not in VECTOR_LANES:
        raise ValueError("Unknown fixture lane")
    cohort = []
    totals = [0] * VECTOR_DIMENSION
    for member in VECTOR_MEMBERS:
        record = fetch(vector_share_name(lane, member))
        if not record.get("value"):
            continue
        values = json.loads(record["value"])
        if (record.get("round") != VECTOR_ROUND or record.get("member") != member
                or record.get("submission_id") != f"{VECTOR_ROUND}-{member}"
                or not isinstance(values, list) or len(values) != VECTOR_DIMENSION
                or any(type(value) is not int or not 0 <= value < PRIME for value in values)):
            raise ValueError("A vector share is outside the approved fixture encoding")
        cohort.append(member)
        totals = [(left + right) % PRIME for left, right in zip(totals, values)]
    replace(vector_total_name(lane), {
        "round": VECTOR_ROUND, "cohort": json.dumps(cohort, separators=(",", ":")),
        "total": json.dumps(totals, separators=(",", ":")),
    })
    return {"named_share_record_count": len(cohort)}


def release_vector():
    east, west = [fetch(vector_total_name(lane)) for lane in VECTOR_LANES]
    cohorts = [json.loads(item["cohort"]) for item in (east, west)]
    if (east.get("round") != VECTOR_ROUND or west.get("round") != VECTOR_ROUND
            or cohorts[0] != cohorts[1] or len(cohorts[0]) < MINIMUM
            or any(member not in VECTOR_MEMBERS for member in cohorts[0])):
        return {"decision": "held", "reason": "cohort-policy"}
    totals = [json.loads(item["total"]) for item in (east, west)]
    if any(len(values) != VECTOR_DIMENSION
           or any(type(value) is not int or not 0 <= value < PRIME for value in values)
           for values in totals):
        raise ValueError("A vector aggregate is outside the approved fixture encoding")
    aggregate = [(left + right) % PRIME for left, right in zip(*totals)]
    return {"decision": "released", "contributors": len(cohorts[0]), "vector": aggregate}


def drop_vector(member, lane):
    if member not in VECTOR_MEMBERS or lane not in VECTOR_LANES or not bound_member(member):
        return {"status": 403, "identity_bound": False}
    replace(vector_share_name(lane, member), {
        "round": VECTOR_ROUND, "member": member, "submission_id": "", "value": "",
    })
    return {"status": 200, "identity_bound": True}


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
    elif operation == "contribute-vector":
        result = contribute_vector(args[0], args[1], json.loads(args[2]))
    elif operation == "attempt-foreign-vector":
        result = attempt_foreign_vector()
    elif operation == "observe-vector":
        result = observe_vector(*args)
    elif operation == "replay-probe":
        result = replay_probe(args[0], args[1], json.loads(args[2]))
    elif operation == "summarize-vector":
        result = summarize_vector(*args)
    elif operation == "release-vector":
        result = release_vector()
    elif operation == "drop-vector":
        result = drop_vector(*args)
    else:
        raise ValueError("Unknown fixture operation")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
