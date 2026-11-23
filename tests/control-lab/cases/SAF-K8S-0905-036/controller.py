"""Synthetic numeric-threshold controller for the disposable lab namespace."""
import json
import os
import ssl
import time
import urllib.request


NAMESPACE = "saf-test"
TARGET = "threshold-target"
TELEMETRY = "threshold-telemetry"
POLICY = "threshold-policy"
DECISION = "threshold-decision"
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


def api(method, path, body=None):
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    api_root = "/apis/apps/v1" if path.startswith("deployments/") else "/api/v1"
    url = f"https://{host}:{port}{api_root}/namespaces/{NAMESPACE}/{path}"
    payload = None if body is None else json.dumps(body, sort_keys=True).encode()
    with open(TOKEN_PATH, encoding="utf-8") as token_file:
        token = token_file.read().strip()
    request = urllib.request.Request(url, data=payload, method=method, headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/merge-patch+json",
    })
    context = ssl.create_default_context(cafile=CA_PATH)
    with urllib.request.urlopen(request, context=context, timeout=5) as response:
        return json.load(response)


def update_decision(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    api("PATCH", f"configmaps/{DECISION}", {"data": {"decision.json": encoded}})


def main():
    while True:
        metric = int(api("GET", f"configmaps/{TELEMETRY}")["data"]["value"])
        policy = api("GET", f"configmaps/{POLICY}")["data"]
        enabled = policy["enabled"] == "true"
        threshold = int(policy["threshold"])
        stored = json.loads(api("GET", f"configmaps/{DECISION}")["data"]["decision.json"])
        prior = stored.copy()
        if stored.get("action") == "scale_to_zero":
            decision = {**stored, "last_observed_metric": metric}
        elif enabled and metric >= threshold:
            decision = {"action": "scale_to_zero", "enabled": enabled, "metric": metric,
                        "reason": "threshold_breached", "target": TARGET, "threshold": threshold,
                        "last_observed_metric": metric, "state": "pending"}
            update_decision(decision)
            prior = decision.copy()
        else:
            decision = {"action": "continue", "enabled": enabled, "metric": metric,
                        "reason": "below_threshold" if enabled else "threshold_disabled",
                        "target": TARGET, "threshold": threshold}

        if decision["action"] == "scale_to_zero":
            scale = api("GET", f"deployments/{TARGET}/scale")
            if scale["spec"].get("replicas", 0) != 0:
                api("PATCH", f"deployments/{TARGET}/scale", {"spec": {"replicas": 0}})
            decision["state"] = "enforced"
        if decision != prior:
            update_decision(decision)
        time.sleep(0.5)


if __name__ == "__main__":
    main()
