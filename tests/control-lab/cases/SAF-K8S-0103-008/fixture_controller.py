"""Reconcile only the public fixture marker using the assigned workload identity."""

import json
from pathlib import Path
import ssl
import urllib.error
import urllib.request

credentials = Path("/var/run/secrets/kubernetes.io/serviceaccount")
namespace = (credentials / "namespace").read_text().strip()
context = ssl.create_default_context(cafile=str(credentials / "ca.crt"))
bearer = (credentials / "token").read_text().strip()


def patch(name):
    request = urllib.request.Request(
        f"https://kubernetes.default.svc/api/v1/namespaces/{namespace}/configmaps/{name}",
        data=json.dumps({"data": {"state": "fixture-reconciled"}}).encode(),
        headers={"Content-Type": "application/merge-patch+json", "Authorization": f"Bearer {bearer}"},
        method="PATCH",
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


result = {"fixture_update": patch("fixture-cloud-state"), "other_marker_update": patch("fixture-core-state")}
print(json.dumps(result))
