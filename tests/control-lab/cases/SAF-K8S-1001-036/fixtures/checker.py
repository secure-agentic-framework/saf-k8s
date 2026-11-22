from datetime import datetime, timedelta, timezone
import json
import os
import subprocess
import sys

aws = [os.environ["AWS_CLIENT_EXE"], "--endpoint-url", os.environ["AWS_ENDPOINT_URL"], "--region", "us-east-1", "s3api"]
open("/tmp/aws-config", "w").write("[default]\ns3 =\n    addressing_style = path\n")
os.environ["AWS_CONFIG_FILE"] = "/tmp/aws-config"
bucket = os.environ["RETENTION_BUCKET"]
minimum = int(os.environ["SYNTHETIC_MINIMUM_DAYS"])
stage = sys.argv[1]
raw_config = json.loads(subprocess.run(
    aws + ["get-object-lock-configuration", "--bucket", bucket],
    check=True, capture_output=True, text=True).stdout)
configuration = raw_config.get("ObjectLockConfiguration", {})
default = ((configuration.get("Rule") or {}).get("DefaultRetention") or {})
days = default.get("Days")
years = default.get("Years")
observed_days = days if isinstance(days, int) else (years * 365 if isinstance(years, int) else None)
mode_ok = default.get("Mode") in {"GOVERNANCE", "COMPLIANCE"}
if observed_days is None:
    compliant, reason = False, "missing_default_retention"
elif observed_days < minimum:
    compliant, reason = False, "below_synthetic_minimum"
elif not mode_ok:
    compliant, reason = False, "unsupported_or_missing_mode"
else:
    compliant, reason = True, "compliant"

object_observation = {"checked": os.environ.get("CHECK_OBJECT") == "true",
                      "minimum_satisfied": False, "raw_retention": None}
if object_observation["checked"]:
    key = os.environ["RETENTION_KEY"]
    raw_object = json.loads(subprocess.run(
        aws + ["get-object-retention", "--bucket", bucket, "--key", key],
        check=True, capture_output=True, text=True).stdout)
    raw_head = json.loads(subprocess.run(
        aws + ["head-object", "--bucket", bucket, "--key", key],
        check=True, capture_output=True, text=True).stdout)
    retention = raw_object.get("Retention", {})
    retain_until = datetime.fromisoformat(retention["RetainUntilDate"].replace("Z", "+00:00"))
    last_modified = datetime.fromisoformat(raw_head["LastModified"].replace("Z", "+00:00"))
    minimum_edge = last_modified + timedelta(days=minimum) - timedelta(seconds=1)
    object_observation.update(
        minimum_reference="storage-last-modified",
        measured_duration_seconds=(retain_until - last_modified).total_seconds(),
        minimum_satisfied=retention.get("Mode") in {"GOVERNANCE", "COMPLIANCE"}
        and retain_until >= minimum_edge,
        raw_retention={"retention": raw_object, "head": raw_head},
    )
    if compliant and not object_observation["minimum_satisfied"]:
        reason = "effective_object_retention_below_synthetic_minimum"
    compliant = compliant and object_observation["minimum_satisfied"]

print(json.dumps({
    "stage": stage,
    "compliant": compliant,
    "reason": reason,
    "minimum_days": minimum,
    "measured_mode": default.get("Mode"),
    "measured_days": days,
    "measured_years": years,
    "raw_configuration": raw_config,
    "object_retention": object_observation,
}, sort_keys=True))
