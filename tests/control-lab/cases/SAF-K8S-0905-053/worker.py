"""Apply one approved review cycle and its decision history atomically."""
import json
import os
from pathlib import Path
import ssl
from urllib.request import Request, urlopen

ROOT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
POLICY = "model-source-allowlist"
DECISIONS = "model-source-review-decisions"


def request(name, *, replace=None):
    namespace = (ROOT / "namespace").read_text().strip()
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]
    url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/configmaps/{name}"
    token = (ROOT / "token").read_text().strip()
    tls = ssl.create_default_context(cafile=str(ROOT / "ca.crt"))
    args = {"method": "GET"} if replace is None else {"method": "PUT", "data": json.dumps(replace).encode()}
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    with urlopen(Request(url, headers=headers, **args), context=tls, timeout=8) as response:
        return json.load(response)


def review():
    policy = request(POLICY)
    evidence = json.loads(request(DECISIONS)["data"]["review.json"])
    cycle = evidence["cycle"]
    prior = json.loads(policy["data"]["approved.json"])
    history = json.loads(policy["data"]["history.json"])
    if any(event["cycle"] == cycle for event in history):
        print(json.dumps({"cycle": cycle, "outcome": "already-recorded"}))
        return
    allowed, changes = [], []
    for row in prior:
        decision = evidence["decisions"].get(row["id"])
        if decision is None or decision["status"] != "approved":
            changes.append({"id": row["id"], "action": "remove",
                            "old_source": row["source"],
                            "reason": decision["reason"] if decision else "no-current-review"})
            continue
        source = decision.get("source", row["source"])
        changes.append({"id": row["id"], "action": "update" if source != row["source"] else "keep",
                        "old_source": row["source"], "current_source": source,
                        "reason": decision["reason"]})
        allowed.append({**row, "source": source, "reviewed_at": evidence["reviewed_at"]})
    event = {"cycle": cycle, "reviewed_at": evidence["reviewed_at"], "reviewer": evidence["reviewer"],
             "approver": evidence["approver"], "decisions": changes}
    policy["data"]["approved.json"] = json.dumps(allowed, sort_keys=True)
    policy["data"]["history.json"] = json.dumps([*history, event], sort_keys=True)
    request(POLICY, replace=policy)
    print(json.dumps({"cycle": cycle, "outcome": "updated"}))


if __name__ == "__main__":
    review()
