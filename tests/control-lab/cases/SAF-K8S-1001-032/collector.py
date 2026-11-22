"""Read only the allocated node marker and exact owned workload's stdout."""
import json
import os
from pathlib import Path
import ssl
import time
from urllib.request import Request, urlopen

NODE = os.environ["NODE_NAME"]
IDENTITY = Path("/var/run/secrets/kubernetes.io/serviceaccount")
CONTEXT = ssl.create_default_context(cafile=str(IDENTITY / "ca.crt"))
SOURCES = json.loads(Path("/sources/pods.json").read_text())
POD = SOURCES[NODE]
URL = "https://kubernetes.default.svc/api/v1/namespaces/saf-test/pods/" + POD + "/log?container=source"


def collect_once():
    token = (IDENTITY / "token").read_text().strip()
    with urlopen(Request(URL, headers={"Authorization": f"Bearer {token}"}),
                 context=CONTEXT, timeout=4) as response:
        workload = response.read().decode().splitlines()
    return {"node": NODE, "node_marker": Path("/owned-marker/marker.txt").read_text().strip(),
            "workload_lines": workload}


while True:
    try:
        print(json.dumps(collect_once(),sort_keys=True),flush=True)
    except (OSError, ValueError) as error:
        print(json.dumps({"retry": type(error).__name__}),flush=True)
    time.sleep(2)
