"""Small in-cluster evaluator/publisher for inert SAF source records."""
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from pathlib import Path

NS = "saf-test"
TARGET = "approved-model-sources"
CRITERIA = "source-approval-criteria"
ROOT = Path("/var/run/secrets/kubernetes.io/serviceaccount")


def request(path, method="GET", body=None):
    token = (ROOT / "token").read_text().strip()
    context = ssl.create_default_context(cafile=str(ROOT / "ca.crt"))
    url = "https://%s:%s/api/v1/namespaces/%s/configmaps/%s" % (
        os.environ["KUBERNETES_SERVICE_HOST"], os.environ["KUBERNETES_SERVICE_PORT_HTTPS"], NS, path)
    data = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/merge-patch+json"})
    try:
        with urllib.request.urlopen(req, context=context, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(errors="replace")


def read(name):
    status, obj = request(name)
    if status != 200:
        raise RuntimeError("API_READ_FAILED_%s" % status)
    return obj


def source_shape(record):
    source = record["source"]
    if not isinstance(source, str) or not source:
        return False
    if record["kind"] == "publisher":
        return source == record["publisher"] and re.fullmatch(r"[a-z0-9-]+", source) is not None
    if record["kind"] == "repository":
        ref = urlsplit(source)
        return (ref.scheme == "https" and ref.hostname == "models.example.invalid"
                and ref.netloc == ref.hostname and not ref.query and not ref.fragment
                and re.fullmatch(r"/[a-z0-9-]+/[a-z0-9-]+", ref.path) is not None)
    if record["kind"] == "registry-namespace":
        namespace = re.fullmatch(r"registry[.]example[.]invalid/[a-z0-9-]+", source)
        digest = re.fullmatch(r"sha256:[a-f0-9]{64}", record.get("cid", ""))
        return namespace is not None and digest is not None
    return False


def valid(record, criteria):
    required = {"kind", "source", "publisher", "criteria_id", "criteria",
                "approval_status", "approver", "evidence", "publisher_evidence", "license_basis"}
    return (isinstance(record, dict) and required <= set(record)
            and source_shape(record)
            and record["publisher_evidence"] == criteria["publisher_evidence"]
            and record["license_basis"] == criteria["license_basis"]
            and isinstance(record["publisher"], str) and record["publisher"]
            and record["criteria_id"] == criteria["criteria_id"]
            and record["criteria"] == criteria["criteria"]
            and record["approval_status"] == "approved"
            and record["approver"] == criteria["approver"]
            and record["evidence"] == criteria["evidence_ref"])


def main():
    mode, proposal_name = os.sys.argv[1:3]

    if mode == "unauthorized":
        status, _ = request(TARGET, "PATCH", {"data": {"records.json": "[]"}})
        if status == 403:
            print("API_FORBIDDEN target=%s" % TARGET)
            return
        raise RuntimeError("UNPRIVILEGED_PATCH_STATUS_%s" % status)
    proposal = json.loads(read(proposal_name)["data"]["record.json"])
    if mode == "publish-inactive":
        records = json.loads(read(TARGET)["data"]["records.json"])
        records.append(proposal)
        status, _ = request(TARGET, "PATCH", {"data": {"records.json": json.dumps(records, sort_keys=True)}})
        if status != 200:
            raise RuntimeError("INACTIVE_PUBLISH_FAILED_%s" % status)
        print("PUBLISHED criteria=inactive record=%s" % proposal_name)
        return

    criteria = json.loads(read(CRITERIA)["data"]["criteria.json"])
    if not valid(proposal, criteria):
        print("POLICY_REJECT record=%s" % proposal_name)
        return
    if mode == "evaluate":
        print("EVALUATION_APPROVED record=%s criteria=%s approver=%s" %
              (proposal_name, criteria["criteria_id"], criteria["approver"]))
        return
    if mode == "publish":
        records = json.loads(read(TARGET)["data"]["records.json"])
        if proposal not in records:
            records.append(proposal)
        status, _ = request(TARGET, "PATCH", {"data": {"records.json": json.dumps(records, sort_keys=True)}})
        if status != 200:
            raise RuntimeError("PUBLISH_FAILED_%s" % status)
        print("PUBLISHED kind=%s criteria=%s approver=%s evidence=%s" %
              (proposal["kind"], criteria["criteria_id"], criteria["approver"], criteria["evidence_ref"]))
        return
    raise RuntimeError("UNKNOWN_MODE")


if __name__ == "__main__":
    main()
