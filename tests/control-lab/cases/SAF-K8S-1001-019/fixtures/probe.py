from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import subprocess
import tempfile


aws = [os.environ["AWS_CLIENT_EXE"], "--endpoint-url", os.environ["AWS_ENDPOINT_URL"],
       "--region", "us-east-1", "s3api"]
os.environ["AWS_CONFIG_FILE"] = "/tmp/aws-config"
open(os.environ["AWS_CONFIG_FILE"], "w").write("[default]\ns3 =\n    addressing_style = path\n")
policy = json.load(open("/fixture/policy.json"))
buckets = {
    "historical": ("saf-k8s-1001-019-history", False),
    "corrected": ("saf-k8s-1001-019-corrected", True),
    "comparator": ("saf-k8s-1001-019-healthy", True),
}


def call(args):
    return subprocess.run(aws + args, check=True, capture_output=True, text=True).stdout


def parse_date(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


observed = {}
for label, (bucket, corrected) in buckets.items():
    raw_configuration = json.loads(call(["get-object-lock-configuration", "--bucket", bucket]))
    config = raw_configuration.get("ObjectLockConfiguration", {})
    default = ((config.get("Rule") or {}).get("DefaultRetention") or {})
    configured_default = default.get("Days")
    versioned = json.loads(call(["get-bucket-versioning", "--bucket", bucket])).get("Status") == "Enabled"
    if not versioned or config.get("ObjectLockEnabled") != "Enabled":
        raise SystemExit("bucket does not expose enabled versioning and Object Lock")
    classes = {}
    for item in policy["classes"]:
        source = "/fixture/" + item["payload_file"]
        with open(source, "rb") as stream:
            source_digest = hashlib.sha256(stream.read()).hexdigest()
        put = json.loads(call(["put-object", "--bucket", bucket, "--key", item["key"],
                               "--body", source, "--metadata", "fixture-class=" + item["id"]]))
        version_id = put.get("VersionId")
        if not version_id:
            raise SystemExit("versioned S3 PUT did not return VersionId")
        head_args = ["head-object", "--bucket", bucket, "--key", item["key"], "--version-id", version_id]
        head = json.loads(call(head_args))
        last_modified = parse_date(head["LastModified"])
        target_days = item["minimum_days"] if corrected else policy["historical_default_days"]
        if corrected and target_days > configured_default:
            retain_until = last_modified + timedelta(days=target_days)
            retention_request = {"Mode": policy["mode"], "RetainUntilDate":
                                 retain_until.isoformat(timespec="seconds").replace("+00:00", "Z")}
            call(["put-object-retention", "--bucket", bucket, "--key", item["key"],
                  "--version-id", version_id, "--retention", json.dumps({"Mode": policy["mode"],
                                                                           "RetainUntilDate": retention_request["RetainUntilDate"]})])
        retention = json.loads(call(["get-object-retention", "--bucket", bucket, "--key", item["key"],
                                     "--version-id", version_id]))
        retained = retention.get("Retention", {})
        retained_until = parse_date(retained["RetainUntilDate"])
        with tempfile.NamedTemporaryFile() as downloaded:
            get = json.loads(call(["get-object", "--bucket", bucket, "--key", item["key"],
                                  "--version-id", version_id, downloaded.name]))
            with open(downloaded.name, "rb") as stream:
                retrieved_digest = hashlib.sha256(stream.read()).hexdigest()
        head_version = head.get("VersionId")
        actual_seconds = (retained_until - last_modified).total_seconds()
        version_valid = (retained.get("Mode") in {"GOVERNANCE", "COMPLIANCE"}
                         and actual_seconds >= target_days * 86400 - 2
                         and retrieved_digest == source_digest and head_version == version_id
                         and get.get("VersionId") == version_id)
        satisfies_class_minimum = actual_seconds >= item["minimum_days"] * 86400 - 2
        classes[item["id"]] = {
            "configured_days": target_days,
            "class_minimum_days": item["minimum_days"],
            "minimum_satisfied": satisfies_class_minimum,
            "version_valid": version_valid,
            "mode": retained.get("Mode"),
            "effective_seconds": actual_seconds,
            "sha256": retrieved_digest,
            "version_id": version_id,
            "last_modified": head["LastModified"],
            "retain_until": retained["RetainUntilDate"],
            "head_version_id": head_version,
            "get_version_id": get.get("VersionId"),
            "content_length": head.get("ContentLength"),
            "source_digest": source_digest,
            "raw_retention": retention,
            "raw_head": head,
            "raw_get": get,
        }
        if not version_valid:
            raise SystemExit("version-specific retention or payload verification failed for " + item["id"])
    observed[label] = {"bucket": bucket, "default_days": configured_default,
                       "raw_configuration": raw_configuration, "classes": classes}
# Apply the corrected policy to the existing original versions as well as new objects.
history = observed["historical"]
historical_after = {}
for item in policy["classes"]:
    before = history["classes"][item["id"]]
    retain_until = parse_date(before["last_modified"]) + timedelta(days=item["minimum_days"])
    request = {"Mode": policy["mode"], "RetainUntilDate": retain_until.isoformat(timespec="seconds")}
    call(["put-object-retention", "--bucket", history["bucket"], "--key", item["key"],
          "--version-id", before["version_id"], "--retention", json.dumps(request)])
    retention = json.loads(call(["get-object-retention", "--bucket", history["bucket"], "--key", item["key"],
                                 "--version-id", before["version_id"]]))["Retention"]
    historical_after[item["id"]] = {"version_id": before["version_id"], "retention": retention}


def observe_delete(bucket, key, version):
    response = subprocess.run(aws + ["delete-object", "--bucket", bucket, "--key", key, "--version-id", version],
                              capture_output=True, text=True)
    match = re.search(r"An error occurred \(([^)]+)\)", response.stderr)
    return {"returncode": response.returncode, "error_code": match.group(1) if match else None}


# A case-owned unlocked comparator confirms that this fixture identity can perform a normal cleanup.
unlocked_bucket = "saf-k8s-1001-019-unlocked"
call(["create-bucket", "--bucket", unlocked_bucket])
call(["put-bucket-versioning", "--bucket", unlocked_bucket, "--versioning-configuration", "Status=Enabled"])
cleanup_source = policy["classes"][0]
unlocked = json.loads(call(["put-object", "--bucket", unlocked_bucket, "--key", cleanup_source["key"],
                            "--body", "/fixture/" + cleanup_source["payload_file"]]))
unlocked_ver = unlocked["VersionId"]
unlocked_delete = observe_delete(unlocked_bucket, cleanup_source["key"], unlocked_ver)
remaining = json.loads(call(["list-object-versions", "--bucket", unlocked_bucket, "--prefix", cleanup_source["key"]]))
unlocked_delete["still_listed"] = any(row.get("VersionId") == unlocked_ver for row in remaining.get("Versions", []))

locked = observed["corrected"]
protected = {}
for item in policy["classes"]:
    before = locked["classes"][item["id"]]
    version = before["version_id"]
    result = observe_delete(locked["bucket"], item["key"], version)
    with tempfile.NamedTemporaryFile() as output:
        fetched = json.loads(call(["get-object", "--bucket", locked["bucket"], "--key", item["key"],
                                   "--version-id", version, output.name]))
        with open(output.name, "rb") as stream:
            digest_after = hashlib.sha256(stream.read()).hexdigest()
    protected[item["id"]] = {"decision": result, "version_id": fetched["VersionId"], "sha256": digest_after}

print(json.dumps({"buckets": observed, "historical_after": historical_after,
                  "cleanup": {"unlocked": unlocked_delete, "locked": protected}}, sort_keys=True))
