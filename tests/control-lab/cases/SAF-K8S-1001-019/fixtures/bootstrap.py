import json
import os
import subprocess


aws = [os.environ["AWS_CLIENT_EXE"], "--endpoint-url", os.environ["AWS_ENDPOINT_URL"],
       "--region", "us-east-1", "s3api"]
os.environ["AWS_CONFIG_FILE"] = "/tmp/aws-config"
open(os.environ["AWS_CONFIG_FILE"], "w").write("[default]\ns3 =\n    addressing_style = path\n")
policy = json.load(open("/fixture/policy.json"))
buckets = {
    "historical": ("saf-k8s-1001-019-history", policy["historical_default_days"]),
    "corrected": ("saf-k8s-1001-019-corrected", policy["corrected_default_days"]),
    "comparator": ("saf-k8s-1001-019-healthy", policy["corrected_default_days"]),
}
observed = {}
for label, (bucket, days) in buckets.items():
    subprocess.run(aws + ["create-bucket", "--bucket", bucket, "--object-lock-enabled-for-bucket"],
                   check=True, capture_output=True, text=True)
    lock = {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {
        "Mode": policy["mode"], "Days": days}}}
    subprocess.run(aws + ["put-object-lock-configuration", "--bucket", bucket,
                          "--object-lock-configuration", json.dumps(lock)],
                   check=True, capture_output=True, text=True)
    versioning = json.loads(subprocess.run(aws + ["get-bucket-versioning", "--bucket", bucket],
                                            check=True, capture_output=True, text=True).stdout)
    raw_lock = json.loads(subprocess.run(aws + ["get-object-lock-configuration", "--bucket", bucket],
                                          check=True, capture_output=True, text=True).stdout)
    observed[label] = {"bucket": bucket, "versioning": versioning, "lock": raw_lock}
print(json.dumps({"buckets": observed}, sort_keys=True))
