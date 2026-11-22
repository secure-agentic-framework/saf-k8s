"""Read the exact fixture snapshot inputs and retain the artifact."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import ssl
from urllib.error import HTTPError
from urllib.request import Request, urlopen

namespace = os.environ["FIXTURE_NAMESPACE"]
root = Path("/var/run/secrets/kubernetes.io/serviceaccount")
ca = ssl.create_default_context(cafile=str(root / "ca.crt"))
token = (root / "token").read_text().strip()
api = "https://kubernetes.default.svc/api/v1"
configmaps = f"/namespaces/{namespace}/configmaps"
names = ("synthetic-control-record", "synthetic-crosswalk-eu", "synthetic-crosswalk-nist")


def get(suffix):
    request = Request(api + suffix, headers={"Authorization": f"Bearer {token}"})
    try:
        with urlopen(request, context=ca, timeout=7) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        if error.code != 403:
            raise
        return error.code, None


records = {}
for name in names:
    status, obj = get(f"{configmaps}/{name}")
    if status != 200 or obj["metadata"]["name"] != name or obj["metadata"]["namespace"] != namespace:
        raise RuntimeError(f"Unable to read fixture record {name}")
    records[name] = obj["data"]
status, ns = get(f"/namespaces/{namespace}")
if status != 200 or ns["metadata"]["name"] != namespace:
    raise RuntimeError("Unable to read the fixture's Pod Security Admission labels")
labels = ns["metadata"]["labels"]
pod_security = {key: value for key, value in labels.items() if key.startswith("pod-security.kubernetes.io/")}
restricted = {"unlisted_get": get(f"{configmaps}/unlisted-neighbor")[0],
              "configmap_list": get(configmaps)[0]}
if restricted != {"unlisted_get": 403, "configmap_list": 403}:
    raise RuntimeError("The scheduled collector exceeds its exact read scope")
snapshot = {
    "collected_at": datetime.now(timezone.utc).isoformat(),
    "configs": records,
    "pod_security_admission": pod_security,
    "rbac": restricted,
}
result = json.dumps(snapshot, sort_keys=True)
output = Path("/snapshots") / (os.environ["FIXTURE_POD"] + ".json")
temporary = output.with_suffix(".tmp")
temporary.write_text(result)
temporary.replace(output)
print(result)
