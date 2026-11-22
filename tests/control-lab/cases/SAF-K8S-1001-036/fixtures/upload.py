import hashlib
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone

open("/tmp/aws-config", "w").write("[default]\ns3 =\n    addressing_style = path\n")
os.environ["AWS_CONFIG_FILE"] = "/tmp/aws-config"
aws = [os.environ["AWS_CLIENT_EXE"], "--endpoint-url", os.environ["AWS_ENDPOINT_URL"], "--region", "us-east-1", "s3api"]
bucket, key = os.environ["RETENTION_BUCKET"], os.environ["AUDIT_KEY"]
source = "/fixture/audit-event.jsonl"
with open(source, "rb") as stream:
    digest = hashlib.sha256(stream.read()).hexdigest()
if digest != os.environ["EXPECTED_SHA256"]:
    raise SystemExit("fixture event digest mismatch")
created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
put = json.loads(subprocess.run(aws + ["put-object", "--bucket", bucket, "--key", key,
                                      "--body", source, "--metadata", f"retention-anchor={created_at}"], check=True, capture_output=True,
                         text=True).stdout)
with tempfile.NamedTemporaryFile() as target:
    subprocess.run(aws + ["get-object", "--bucket", bucket, "--key", key,
                          target.name], check=True, capture_output=True, text=True)
    with open(target.name, "rb") as stream:
        retrieved = hashlib.sha256(stream.read()).hexdigest()
if retrieved != digest:
    raise SystemExit("retrieved audit object digest mismatch")
print(json.dumps({"sha256": retrieved, "version_id": put.get("VersionId"), "retention_anchor": created_at}, sort_keys=True))
