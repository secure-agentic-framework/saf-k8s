"""Verify a fixed benign policy canary in a real ModSecurity reverse proxy."""
from contextlib import contextmanager
import http.client
import json
from pathlib import Path
import re
import subprocess
import time

SCOPE = (
    "A local Kubernetes v1.36.1 Kind cluster routes owned HTTP traffic through the pinned "
    "ModSecurity and OWASP Core Rule Set reverse proxy. The same harmless test header reaches the "
    "owned backend before the canary is installed and is denied after the rule is loaded. "
    "The test checks the specific audit rule ID and continued access for independent permitted "
    "traffic. Deployed ingress attachment, inspection coverage and managed rules need separate evidence."
)
FIXTURES = Path(__file__).with_name("fixtures")
NAMESPACE = "saf-test"
RULE_ID = "10503013"
DENIED_MARKER = "deny-example"
PERMITTED_MARKER = "allowed-after-policy"


@contextmanager
def forward(lab, phase):
    log_path = lab.evidence / f"forward-{phase}.log"
    args = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "-n", NAMESPACE, "port-forward", "--address", "127.0.0.1", "service/saf-waf", ":8080",
    ]
    with log_path.open("w") as log:
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=lab.env)
        try:
            def listener_port():
                if process.poll() is not None:
                    lab.block("Loopback forwarding exited for the owned WAF")
                found = re.search(r"Forwarding from 127\.0\.0\.1:(\d+)", log_path.read_text())
                return int(found.group(1)) if found else None

            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                port = listener_port()
                if port:
                    yield port
                    break
                time.sleep(0.25)
            else:
                lab.block("Timed out waiting for the owned WAF loopback port")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def request(port, marker):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        connection.request("GET", "/cgi-bin/marker.cgi",
                           headers={"Host": "waf.lab.test", "X-SAF-Lab-Marker": marker, "Connection": "close"})
        response = connection.getresponse()
        return response.status, response.read(4096).decode("utf-8", "replace").strip()
    finally:
        connection.close()


def arrivals(lab):
    result = lab.kubectl("exec", "deployment/saf-marker", "--", "sh", "-c",
                         "if test -f /data/arrivals.log; then cat /data/arrivals.log; fi")
    return result.stdout.splitlines()


def audited_rule(lab):
    pattern = r'"ruleId"\s*:\s*"?10503013"?\b|\[id "10503013"\]'
    deadline = time.monotonic() + 20
    while True:
        audit = lab.kubectl("logs", "deployment/saf-waf", "--since=2m").stdout
        matched = [line for line in audit.splitlines()
                   if re.search(pattern, line) and "SAF synthetic fixed-marker canary" in line]
        if matched:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


def run(lab):
    for file in ("backend.yaml", "waf-policy-off.yaml", "waf.yaml"):
        lab.apply(FIXTURES / file)
    for deployment in ("saf-marker", "saf-waf"):
        lab.kubectl("rollout", "status", f"deployment/{deployment}", "--timeout=150s", timeout=160)

    with forward(lab, "baseline") as port:
        status, body = request(port, DENIED_MARKER)
    baseline = arrivals(lab)
    lab.check("red", "The exact canary marker reaches the owned backend before activation",
              status == 200 and body == f"backend=owned-marker arrivals=1 marker={DENIED_MARKER}"
              and baseline == [DENIED_MARKER],
              {"http_status": status, "marker_response": body, "backend_arrivals": baseline})

    lab.apply(FIXTURES / "waf-policy-on.yaml")
    lab.kubectl("rollout", "restart", "deployment/saf-waf")
    lab.kubectl("rollout", "status", "deployment/saf-waf", "--timeout=150s", timeout=160)
    with forward(lab, "enforced") as port:
        denied_status, _ = request(port, DENIED_MARKER)
        denied_arrivals = arrivals(lab)
        rule_logged = audited_rule(lab)
        permitted_status, permitted_body = request(port, PERMITTED_MARKER)
    final_arrivals = arrivals(lab)
    evidence = {
        "policy_rule_id": RULE_ID,
        "exact_rule_logged": rule_logged,
        "blocked_http_status": denied_status,
        "permitted_http_status": permitted_status,
        "backend_arrivals_before": baseline,
        "backend_arrivals_after_block": denied_arrivals,
        "backend_arrivals_final": final_arrivals,
    }
    (lab.evidence / "waf-canary-observations.json").write_text(json.dumps(evidence, indent=2) + "\n")
    lab.check("green", "ModSecurity returns HTTP 403 with the exact canary rule and no new backend arrival",
              denied_status == 403 and denied_arrivals == baseline and rule_logged, evidence)
    lab.check("positive", "Independent permitted request returns the marker and is recorded by the backend",
              permitted_status == 200 and permitted_body == f"backend=owned-marker arrivals=2 marker={PERMITTED_MARKER}"
              and final_arrivals == [DENIED_MARKER, PERMITTED_MARKER],
              {"http_status": permitted_status, "marker_response": permitted_body,
               "backend_arrivals": final_arrivals})
