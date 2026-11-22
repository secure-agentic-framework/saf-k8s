"""Create and index exact versioned S3 objects from source log files."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


Path("/tmp/aws-config").write_text("[default]\ns3 =\n    addressing_style = path\n")
os.environ["AWS_CONFIG_FILE"] = "/tmp/aws-config"
aws = [os.environ["AWS_CLIENT_EXE"], "--endpoint-url", os.environ["AWS_ENDPOINT_URL"],
       "--region", "us-east-1", "s3api"]


def call(*args):
    return subprocess.run(aws + list(args), check=True, capture_output=True, text=True)


bucket = os.environ["ARCHIVE_BUCKET"]
call("create-bucket", "--bucket", bucket, "--object-lock-enabled-for-bucket")
configuration = {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {
    "Mode": "COMPLIANCE", "Days": 3,
}}}
call("put-object-lock-configuration", "--bucket", bucket, "--object-lock-configuration",
     json.dumps(configuration))
entries = {}
for log_class in ("audit", "training", "inference"):
    source = Path("/fixture") / f"{log_class}.jsonl"
    payload = source.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    key = f"ai-logs/{log_class}/{os.environ['RUN_ID']}/{log_class}.jsonl"
    response = json.loads(call("put-object", "--bucket", bucket, "--key", key,
                               "--body", str(source), "--content-type", "application/x-ndjson").stdout)
    version_id = response.get("VersionId")
    if not version_id or version_id in {"null", "None"}:
        raise SystemExit(f"S3 did not return a non-null version ID for {log_class}")
    entries[log_class] = {"key": key, "version_id": version_id, "sha256": digest,
                          "record_id": os.environ[f"{log_class.upper()}_RECORD_ID"]}
protection = {
    label: json.loads(call("get-object-retention", "--bucket", bucket, "--key", entry["key"],
                           "--version-id", entry["version_id"]).stdout)
    for label, entry in entries.items()
}
with tempfile.NamedTemporaryFile() as successor:
    payload = b'{"fixture":"newer object at the same audit key"}\n'
    successor.write(payload)
    successor.flush()
    later = json.loads(call("put-object", "--bucket", bucket, "--key", entries["audit"]["key"],
                            "--body", successor.name).stdout)
latest = json.loads(call("list-object-versions", "--bucket", bucket, "--prefix", entries["audit"]["key"]).stdout)
print(json.dumps({"bucket": bucket, "versioning": json.loads(call("get-bucket-versioning", "--bucket", bucket).stdout),
                  "index": entries, "protection": protection, "audit_successor": later["VersionId"],
                  "audit_successor_sha256": hashlib.sha256(payload).hexdigest(),
                  "audit_versions": latest["Versions"]}, sort_keys=True))
