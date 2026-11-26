"""Native in-cluster producer used only by the disposable identity candidate."""
import hashlib
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, "/fixture")
import pipeline

NS = "saf-test"
APPROVED = {
    "input": "08a362b6a4f86ca8e61c2b7bccd4dca72c731af1338dfd796bb6d8871d2e8a0e",
    "stage1": "332ef3e0470b05b5d95355b9a838b6ee42b5e11c7fac6e36b21944fdbf4b5c6b",
    "stage2": "928f96382e91d258b9902faaf75a5475385d59eb112f18c80e0d4680379758b2",
}
VERSIONS = {"stage1": "fixture-transform-one/v1", "stage2": "fixture-transform-two/v1"}
POLICY_MESSAGE = "stage record producer identity or lineage not approved"
CONTENT_MESSAGE = "stage record does not match locked approved bytes"
TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def request(method, path, body=None, dry_run=False):
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    url = f"https://{host}:{port}{path}"
    headers = {"Authorization": "Bearer " + TOKEN.read_text().strip(),
               "Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if dry_run:
        url += "?dryRun=All"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    context = ssl.create_default_context(cafile=CA)
    try:
        with urllib.request.urlopen(req, context=context, timeout=15) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None, ""
    except urllib.error.HTTPError as error:
        # Read only in memory to verify the expected admission message. Never
        # print or persist response text, request headers, or the token.
        message = error.read().decode("utf-8", "replace")
        return error.code, None, message


def record(name, stage, payload, parent):
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": NS,
                     "labels": {"saf.example/stage-record": "true", "saf.example/stage": stage}},
        "immutable": True,
        "data": {"stage": stage, "sha256": digest(payload), "input_sha256": parent,
                 "stage_version": VERSIONS[stage], "payload.json": payload.decode("ascii")},
    }


def post_stage(stage, rec, dry=False):
    return request("POST", f"/api/v1/namespaces/{NS}/configmaps", rec, dry_run=dry)


def run(mode):
    if mode == "stage1":
        raw = Path("/fixture/approved.json").read_bytes()
        if digest(raw) != APPROVED["input"]:
            raise RuntimeError("approved input digest mismatch")
        output = pipeline.transform_one(raw)
        if digest(output) != APPROVED["stage1"]:
            raise RuntimeError("stage1 digest mismatch")
        rec = record("fixture-approved-stage1", "stage1", output, APPROVED["input"])
        created, _, _ = post_stage("stage1", rec)
        before_status, before_obj, _ = request(
            "GET", f"/api/v1/namespaces/{NS}/configmaps/fixture-approved-stage1")
        alternate_raw = Path("/fixture/alternate.json").read_bytes()
        alternate_output = pipeline.transform_one(alternate_raw)
        altered = record("fixture-approved-stage1", "stage1", alternate_output, APPROVED["input"])
        altered["data"]["sha256"] = APPROVED["stage1"]
        altered_status, _, altered_body = post_stage("stage1", altered, dry=True)
        stale = dict(rec)
        stale["data"] = dict(rec["data"], input_sha256=APPROVED["stage2"])
        denied, _, body = post_stage("stage1", stale, dry=True)
        after_status, after_obj, _ = request(
            "GET", f"/api/v1/namespaces/{NS}/configmaps/fixture-approved-stage1")
        return {"mode": mode, "create_status": created,
                "altered_dry_run_denied": altered_status >= 400 and CONTENT_MESSAGE in altered_body,
                "stale_parent_denied": denied >= 400 and (
                    POLICY_MESSAGE in body or CONTENT_MESSAGE in body),
                "record_unchanged_by_denials": before_status == 200 and after_status == 200
                    and before_obj["metadata"]["uid"] == after_obj["metadata"]["uid"]
                    and before_obj["metadata"]["resourceVersion"] == after_obj["metadata"]["resourceVersion"]}

    if mode == "stage2":
        status, parent, _ = request(
            "GET", f"/api/v1/namespaces/{NS}/configmaps/fixture-approved-stage1")
        if status != 200 or parent["data"].get("sha256") != APPROVED["stage1"]:
            raise RuntimeError("approved stage1 parent unavailable")
        input_bytes = parent["data"]["payload.json"].encode("ascii")
        if digest(input_bytes) != APPROVED["stage1"]:
            raise RuntimeError("stage1 parent payload mismatch")
        output = pipeline.transform_two(input_bytes)
        if digest(output) != APPROVED["stage2"]:
            raise RuntimeError("stage2 digest mismatch")
        rec = record("fixture-approved-stage2", "stage2", output, APPROVED["stage1"])
        created, _, _ = post_stage("stage2", rec)
        if created == 201:
            # Publish only after native admission accepted the exact record.
            Path("/pipeline").mkdir(parents=True, exist_ok=True)
            Path("/pipeline/approved-stage2.json").write_bytes(output)
        before_status, before_obj, _ = request(
            "GET", f"/api/v1/namespaces/{NS}/configmaps/fixture-approved-stage2")
        alternate_raw = Path("/fixture/alternate.json").read_bytes()
        alternate_output = pipeline.transform_two(pipeline.transform_one(alternate_raw))
        altered = record("fixture-approved-stage2", "stage2", alternate_output, APPROVED["stage1"])
        altered["data"]["sha256"] = APPROVED["stage2"]
        altered_status, _, altered_body = post_stage("stage2", altered, dry=True)
        stale = dict(rec)
        stale["data"] = dict(rec["data"], stage_version="fixture-transform-two/v0")
        denied, _, body = post_stage("stage2", stale, dry=True)
        after_status, after_obj, _ = request(
            "GET", f"/api/v1/namespaces/{NS}/configmaps/fixture-approved-stage2")
        return {"mode": mode, "parent_read_status": status, "create_status": created,
                "altered_dry_run_denied": altered_status >= 400 and CONTENT_MESSAGE in altered_body,
                "stale_version_denied": denied >= 400 and (
                    POLICY_MESSAGE in body or CONTENT_MESSAGE in body),
                "record_unchanged_by_denials": before_status == 200 and after_status == 200
                    and before_obj["metadata"]["uid"] == after_obj["metadata"]["uid"]
                    and before_obj["metadata"]["resourceVersion"] == after_obj["metadata"]["resourceVersion"]}

    if mode == "alternate":
        raw = Path("/fixture/approved.json").read_bytes()
        output = pipeline.transform_one(raw)
        if digest(output) != APPROVED["stage1"]:
            raise RuntimeError("alternate identity did not prepare the exact approved record")
        rec = record("fixture-approved-stage1", "stage1", output, APPROVED["input"])
        denied, _, body = post_stage("stage1", rec, dry=True)
        return {"mode": mode,
                "exact_record_denied": denied >= 400 and POLICY_MESSAGE in body}

    raise ValueError("unknown producer mode")


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1]), sort_keys=True, separators=(",", ":")))
