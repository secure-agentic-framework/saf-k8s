"""Independent S3 version-index verifier used by scheduled reader pods."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def aws(*args, check=True):
    command = [os.environ["AWS_CLIENT_EXE"], "--endpoint-url", os.environ["AWS_ENDPOINT_URL"],
               "--region", "us-east-1", "s3api", *args]
    result = subprocess.run(command, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(result.stderr[-800:])
    return result


Path("/tmp/aws-config").write_text("[default]\ns3 =\n    addressing_style = path\n")
os.environ["AWS_CONFIG_FILE"] = "/tmp/aws-config"
bucket = os.environ["ARCHIVE_BUCKET"]
mode = os.environ.get("INDEX_MODE", "healthy")
index = json.loads((Path("/index") / f"{mode}.json").read_text())
observations = {}
for log_class, entry in index.items():
    key, expected_version = entry["key"], entry["version_id"]
    versions_raw = aws("list-object-versions", "--bucket", bucket, "--prefix", key,
                       "--output", "json")
    if versions_raw.returncode:
        observations[log_class] = {"status": "version-index-unavailable", "key": key,
                                   "error": versions_raw.stderr[-300:]}
        continue
    versions_doc = json.loads(versions_raw.stdout)
    matching = [row for row in versions_doc.get("Versions", [])
                if row.get("Key") == key and row.get("VersionId") == expected_version]
    if len(matching) != 1:
        observations[log_class] = {"status": "version-unavailable", "key": key,
                                   "expected_version_id": expected_version,
                                   "listed_version_ids": [row.get("VersionId") for row in versions_doc.get("Versions", [])
                                                           if row.get("Key") == key]}
        continue
    with tempfile.NamedTemporaryFile() as target:
        fetched = aws("get-object", "--bucket", bucket, "--key", key,
                      "--version-id", expected_version, target.name, check=False)
        if fetched.returncode:
            observations[log_class] = {"status": "object-unavailable", "key": key,
                                       "version_id": expected_version,
                                       "error": fetched.stderr[-300:]}
            continue
        payload = Path(target.name).read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != entry["sha256"]:
        observations[log_class] = {"status": "digest-mismatch", "key": key,
                                   "version_id": expected_version, "expected_sha256": entry["sha256"],
                                   "actual_sha256": digest}
        continue
    try:
        records = [json.loads(line) for line in payload.splitlines() if line]
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        observations[log_class] = {"status": "parse-error", "key": key,
                                   "version_id": expected_version, "error": type(error).__name__}
        continue
    if log_class == "audit":
        matches = [record for record in records
                   if record.get("objectRef", {}).get("name") == entry["record_id"]
                   and record.get("apiVersion") == "audit.k8s.io/v1"
                   and record.get("stage") == "ResponseComplete"]
    else:
        matches = [record for record in records
                   if record.get("record_id") == entry["record_id"]
                   and record.get("source_log_class") == log_class]
    if len(matches) != 1:
        observations[log_class] = {"status": "record-missing-or-ambiguous", "key": key,
                                   "version_id": expected_version, "parsed_records": len(records),
                                   "matches": len(matches), "sha256": digest}
        continue
    observations[log_class] = {"status": "retrieved", "key": key,
                               "version_id": expected_version, "sha256": digest,
                               "parsed_records": len(records), "record": matches[0]}

print(json.dumps({"mode": mode, "classes": observations}, sort_keys=True))
