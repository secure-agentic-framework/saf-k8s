"""Issue inert fixture reads and server-side dry-run patches as this Pod's identity."""
import json
import os
from pathlib import Path
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


NAMESPACE = "saf-0401-006"
BASE = f"/api/v1/namespaces/{NAMESPACE}/configmaps/"
TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
OPS = {
    "ml": ("model-read", "GET", BASE + "saf-0401-006-model-fixture", None),
    "platform": (
        "platform-dry-run-patch", "PATCH",
        BASE + "saf-0401-006-platform-fixture?dryRun=All",
        {"metadata": {"annotations": {"saf-k8s.example/probe": "dry-run-only"}}},
    ),
    "security": ("audit-read", "GET", BASE + "saf-0401-006-security-fixture", None),
}


def main():
    api = "https://%s:%s" % (
        os.environ["KUBERNETES_SERVICE_HOST"],
        os.environ["KUBERNETES_SERVICE_PORT_HTTPS"],
    )
    context = ssl.create_default_context(cafile=str(CA))
    results = {}
    for label, method, path, body in OPS.values():
        request = Request(
            api + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": "Bearer " + TOKEN.read_text().strip(),
                     "Content-Type": "application/merge-patch+json"},
            method=method,
        )
        try:
            with urlopen(request, context=context, timeout=15) as response:
                results[label] = response.status
        except HTTPError as error:
            results[label] = error.code
        except (URLError, TimeoutError) as error:
            raise SystemExit(f"API request did not produce an authorization result: {type(error).__name__}")
    print(json.dumps(results, sort_keys=True))


if __name__ == "__main__":
    main()
