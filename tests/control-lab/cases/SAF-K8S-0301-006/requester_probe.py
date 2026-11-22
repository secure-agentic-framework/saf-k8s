"""Submit the same inert dry-run using only this Pod's projected requester identity."""
import json
import os
from pathlib import Path
import ssl
from urllib.error import HTTPError
from urllib.request import Request, urlopen

identity = Path("/var/run/secrets/kubernetes.io/serviceaccount")
host = os.environ["KUBERNETES_SERVICE_HOST"]
port = os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]
namespace = (identity / "namespace").read_text().strip()
request = Request(
    f"https://{host}:{port}/api/v1/namespaces/{namespace}/pods?dryRun=All",
    method="POST",
    data=Path("/fixture/pod.json").read_bytes(),
    headers={"Content-Type": "application/json",
             "Authorization": "Bearer " + (identity / "token").read_text().strip()},
)
result = {"status": 0, "restricted_violation": False}
try:
    with urlopen(request, context=ssl.create_default_context(cafile=str(identity / "ca.crt")), timeout=12) as response:
        result["status"] = response.status
except HTTPError as error:
    result["status"] = error.code
    message = json.load(error).get("message", "")
    result["restricted_violation"] = 'violates PodSecurity "restricted:v1.36"' in message
print(json.dumps(result))
