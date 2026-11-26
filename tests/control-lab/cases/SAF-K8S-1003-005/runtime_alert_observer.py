"""Read only the case-owned Prometheus alerts endpoint and return stable predicates."""
import json
import time
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

URL = "http://saf-1003-005-runtime-prometheus:9090/api/v1/alerts"
EXPECTED = {
    "PrivilegedAIWorkloadRequest": {
        "event_id": "evt-synthetic-privileged-ai-pod", "namespace": "ai-fixture",
        "verb": "create", "resource": "pods", "privileged": "true",
        "rule_id": "SAF-K8S-RULE-1003-005-01", "technique_id": "T1610",
    },
    "AIContainerExecRequest": {
        "event_id": "evt-synthetic-ai-pod-exec", "namespace": "ai-fixture",
        "verb": "create", "resource": "pods/exec", "privileged": "false",
        "rule_id": "SAF-K8S-RULE-1003-005-02", "technique_id": "T1609",
    },
}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


opener = build_opener(ProxyHandler({}), NoRedirect())
deadline = time.monotonic() + 35
observed = None
while time.monotonic() < deadline:
    try:
        request = Request(URL, headers={"Accept": "application/json"})
        with opener.open(request, timeout=3) as response:
            if response.geturl() != URL:
                raise RuntimeError("Prometheus endpoint changed")
            raw = response.read(65537)
            if len(raw) > 65536:
                raise RuntimeError("Prometheus response exceeded bound")
        payload = json.loads(raw)
        if payload.get("status") != "success" or not isinstance(payload.get("data", {}).get("alerts"), list):
            raise RuntimeError("Prometheus returned an unexpected alert response")
        alerts = payload["data"]["alerts"]
        by_name = {row.get("labels", {}).get("alertname"): row for row in alerts}
        names_exact = set(by_name) == set(EXPECTED)
        labels_exact = names_exact and all(
            all(by_name[name].get("labels", {}).get(key) == value for key, value in labels.items())
            for name, labels in EXPECTED.items())
        firing_exact = names_exact and all(by_name[name].get("state") == "firing" for name in EXPECTED)
        observed = {"prometheus_api_success": True, "exact_expected_alert_names": names_exact,
                    "expected_labels_match": labels_exact, "both_alerts_firing": firing_exact,
                    "alert_count": len(alerts)}
        if names_exact and labels_exact and firing_exact:
            break
    except (HTTPError, OSError, TimeoutError):
        observed = None
    time.sleep(.5)

if observed is None:
    observed = {"prometheus_api_success": False, "exact_expected_alert_names": False,
                "expected_labels_match": False, "both_alerts_firing": False, "alert_count": 0}
print(json.dumps(observed, sort_keys=True))
