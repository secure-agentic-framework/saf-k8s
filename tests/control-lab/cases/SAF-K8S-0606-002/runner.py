"""Run the case-owned ephemeral packaging task and report only marker decisions."""
from hashlib import sha256
import json
import os
from pathlib import Path
import ssl
import tarfile
import urllib.error
import urllib.request

INPUT = Path("/fixture")
IDENTITY = Path("/identity")
WORK = Path("/work")


def request(url, *, token=None, context=None):
    handlers = [urllib.request.ProxyHandler({})]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    headers = {"Authorization": "Bearer " + token} if token else {}
    try:
        with urllib.request.build_opener(*handlers).open(
            urllib.request.Request(url, headers=headers), timeout=2,
        ) as response:
            return response.status, response.read(8192)
    except urllib.error.HTTPError as error:
        return error.code, b""
    except (TimeoutError, urllib.error.URLError):
        return 0, b""


def run():
    inputs = json.loads((INPUT / "inputs.json").read_text())
    expected = not (WORK / "previous-fixture-marker").exists()
    (WORK / "previous-fixture-marker").write_text("case-owned scratch marker")
    feed_results = {name: request(url)[0] for name, url in inputs["feeds"].items()}
    token = (IDENTITY / "token").read_text()
    context = ssl.create_default_context(cafile=IDENTITY / "ca.crt")
    prefix = f"https://{inputs['api']}/api/v1/namespaces/saf-test/configmaps"
    accepted, body = request(prefix + "/runner-approved-input", token=token, context=context)
    adjacent, _ = request(prefix + "/runner-other-input", token=token, context=context)
    packaged = False
    if accepted == 200:
        payload = json.loads(body)["data"]["value"]
        path = WORK / "source.txt"
        path.write_text(payload)
        archive = WORK / "artifact.tar"
        with tarfile.open(archive, "w") as output:
            output.add(path, arcname="source.txt")
        with tarfile.open(archive, "r") as result:
            content = result.extractfile("source.txt").read()
        packaged = sha256(content).hexdigest() == inputs["approved_sha256"]
    print(json.dumps({
        "private_workspace_empty": expected,
        "own_pod_uid": os.environ["POD_UID"],
        "usual_automatic_identity_mount_absent": not Path("/var/run/secrets/kubernetes.io/serviceaccount/token").exists(),
        "scoped_approved_status": accepted, "scoped_other_status": adjacent, "feeds": feed_results,
        "packaged_verified_input": packaged,
    }, sort_keys=True))


if __name__ == "__main__":
    run()
