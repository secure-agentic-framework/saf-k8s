"""Submit a fixture manifest after verification by the Job's init container."""
from hashlib import sha256
import json
from pathlib import Path
import ssl
import sys
from urllib.request import Request, urlopen


def main():
    expected_identity, expected_digest = sys.argv[1:]
    token_directory = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    manifest = Path("/bundle/manifest.json").read_bytes()
    digest = sha256(manifest).hexdigest()
    if digest != expected_digest:
        raise ValueError("Wrong immutable manifest digest at promotion")
    headers = {"Authorization": "Bearer " + (token_directory / "token").read_text().strip(),
               "Content-Type": "application/json"}
    tls = ssl.create_default_context(cafile=str(token_directory / "ca.crt"))

    def post(path, data):
        req = Request("https://kubernetes.default.svc" + path, data=data, headers=headers)
        with urlopen(req, context=tls, timeout=10) as response:
            return json.load(response)

    review = post("/apis/authentication.k8s.io/v1/selfsubjectreviews", json.dumps({
        "apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview",
    }).encode())
    username = review["status"]["userInfo"]["username"]
    if username != expected_identity:
        raise ValueError("The API reported an unexpected promotion identity")
    created = post("/api/v1/namespaces/saf-test/configmaps", manifest)
    print(json.dumps({"identity": username, "manifest_sha256": digest,
                      "object": created["metadata"]["name"]}))


if __name__ == "__main__":
    main()
