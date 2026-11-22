"""Verify scoped provenance and promotion age using real commit objects."""
from hashlib import sha256
import hmac
import json
from pathlib import Path
import ssl
from urllib.request import Request, urlopen

SOURCE = Path("/input")
REFERENCE = json.loads((SOURCE/"policy.json").read_text())
IDENTITY = Path("/var/run/secrets/kubernetes.io/serviceaccount")
SECRET = Path("/authority/key").read_bytes()


def inspect(receipt, git_dates):
    claims = receipt["claims"]
    encoded = json.dumps(claims,sort_keys=True,separators=(",", ":")).encode()
    trusted = hmac.compare_digest(receipt["hmac"],hmac.new(SECRET,encoded,sha256).hexdigest())
    artifact = SOURCE / (claims["name"]+".json")
    digest = sha256(artifact.read_bytes()).hexdigest()
    commit_epoch = git_dates.get(claims["commit"])
    source_matches = commit_epoch == claims["source_epoch"]
    source_age = REFERENCE["reference_epoch"] - commit_epoch if commit_epoch is not None else None
    build_age = REFERENCE["reference_epoch"] - claims["build_epoch"]
    ordered = [
        (not trusted, "receipt-untrusted"),
        (digest != claims["sha256"], "artifact-mismatch"),
        (not source_matches, "source-mismatch"),
        (source_age is not None and source_age < 0, "future-source"),
        (build_age < 0, "future-build"),
        (source_matches and claims["build_epoch"] < commit_epoch, "build-before-source"),
        (build_age > REFERENCE["max_age_seconds"], "stale-artifact"),
        (source_age is not None and source_age > REFERENCE["max_age_seconds"], "stale-source"),
    ]
    reason = next((reason for fails,reason in ordered if fails), "current")
    return {"name":claims["name"],"commit":claims["commit"],"digest":digest,
            "source_age":source_age,"build_age":build_age,"reason":reason,
            "receipt_valid":trusted,"source_matches":source_matches,"admitted":reason=="current"}


def promote(result):
    ca = ssl.create_default_context(cafile=str(IDENTITY/"ca.crt"))
    token = (IDENTITY/"token").read_text().strip()
    data = {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"promotion-"+result["name"]},
            "immutable":True,"data":{"digest":result["digest"],"commit":result["commit"]}}
    request = Request("https://kubernetes.default.svc/api/v1/namespaces/saf-test/configmaps",
                      data=json.dumps(data).encode(),
                      headers={"Content-Type":"application/json","Authorization":f"Bearer {token}"})
    with urlopen(request, context=ca, timeout=10) as response:
        return response.status==201 and json.load(response)["data"]==data["data"]


def main():
    git_dates={commit:int(epoch) for commit,epoch in
               (line.split() for line in Path("/work/git-dates").read_text().splitlines())}
    receipts=json.loads((SOURCE/"receipts.json").read_text())
    results=[]
    for receipt in receipts:
        result=inspect(receipt,git_dates)
        result["marker_created"]=promote(result) if result["admitted"] else False
        results.append(result)
    print(json.dumps(results))


if __name__=="__main__":
    main()
