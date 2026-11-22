import json
import os
import subprocess

open("/tmp/aws-config", "w").write("[default]\ns3 =\n    addressing_style = path\n")
os.environ["AWS_CONFIG_FILE"] = "/tmp/aws-config"
aws = [os.environ["AWS_CLIENT_EXE"], "--endpoint-url", os.environ["AWS_ENDPOINT_URL"], "--region", "us-east-1", "s3api"]
bucket = os.environ["RETENTION_BUCKET"]
subprocess.run(aws + ["create-bucket", "--bucket", bucket, "--object-lock-enabled-for-bucket"],
               check=True, capture_output=True, text=True)
configuration = json.loads(subprocess.run(
    aws + ["get-object-lock-configuration", "--bucket", bucket],
    check=True, capture_output=True, text=True).stdout)
print(json.dumps({"bucket_created": True, "raw_configuration": configuration}, sort_keys=True))
