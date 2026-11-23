"""Compute explicit trust dispositions using the immutable intake dossier."""
import json
import os
from pathlib import Path
import ssl
from urllib.request import Request, urlopen

CREDENTIALS = Path("/var/run/secrets/kubernetes.io/serviceaccount")
DATA = Path("/review/dossier.json")
RESULTS = "model-trust-decisions"


def api(*, update=None):
    namespace = (CREDENTIALS / "namespace").read_text().strip()
    base = f"https://{os.environ['KUBERNETES_SERVICE_HOST']}:{os.environ['KUBERNETES_SERVICE_PORT_HTTPS']}"
    url = f"{base}/api/v1/namespaces/{namespace}/configmaps/{RESULTS}"
    token = (CREDENTIALS / "token").read_text().strip()
    tls = ssl.create_default_context(cafile=str(CREDENTIALS / "ca.crt"))
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    body = json.dumps(update).encode() if update is not None else None
    with urlopen(Request(url, body, headers, method="PUT" if body is not None else "GET"),
                 context=tls, timeout=8) as response:
        return json.load(response)


def evaluate(dossier):
    records = []
    for candidate in dossier["candidates"]:
        if candidate["provenance"]["disposition"] != "verified":
            raise ValueError("expected a verified provenance handoff")
        signals = candidate["signals"]
        unmet = sorted(name for name, need in dossier["criteria"].items()
                       if signals.get(name, {}).get("assessment") != need
                       or not signals.get(name, {}).get("evidence"))
        records.append({
            "candidate": candidate["candidate"], "digest": candidate["provenance"]["digest"],
            "provenance": candidate["provenance"], "signals": signals,
            "disposition": "rejected" if unmet else "approved",
            "unsatisfied_criteria": unmet, "reviewer": dossier["reviewer"],
            "approval_authority": dossier["approval_authority"], "criteria_revision": dossier["revision"],
        })
    return records


def main():
    dossier = json.loads(DATA.read_text())
    records = evaluate(dossier)
    approved = sorted(record["digest"] for record in records if record["disposition"] == "approved")
    state = api()
    state["data"] = {"approvedDigests": ",".join(approved), "record.json": json.dumps(records, sort_keys=True)}
    api(update=state)
    print(json.dumps({"dispositions": {r["candidate"]: r["disposition"] for r in records}}))


if __name__ == "__main__":
    main()
