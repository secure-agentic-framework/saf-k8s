"""Scratch-only bounded DNS anomaly evidence extension for SAF-K8S-0503-005.

Call run_anomaly_extension(lab, pod_ip, read_logs) after the original two-query
CoreDNS logging check; it does not change that check or its observer.
"""
import json
import time
from collections import Counter
from pathlib import Path

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
QNAME_CONTROL = "volume-control.fixture.test."
QNAME_BURST = "volume-burst.fixture.test."
QNAME_LONG = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.fixture.test."
QNAME_ENTROPY = "q7m2x9k4w3p8r6t5u1c2.fixture.test."
QNAME_QTYPE = "qtype.fixture.test."


def _query(lab, qname, qtype, server):
    script = (HERE / "dns-anomaly-query.py").read_text(encoding="utf-8")
    result = lab.kubectl("exec", "dns-observer", "--", "python", "-c", script,
                         qname, qtype, server)
    return json.loads(result.stdout)


def _rows(text):
    found = []
    for line in text.splitlines():
        start = line.find("{")
        if start < 0:
            continue
        try:
            item = json.loads(line[start:])
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and {"qname", "qtype", "qclass", "proto", "rcode"} <= item.keys():
            found.append({key: item[key] for key in ("qname", "qtype", "qclass", "proto", "rcode")})
    return found


def _run_observer(lab, records):
    expected = {"control_name": QNAME_CONTROL, "volume_name": QNAME_BURST}
    _apply = lambda obj: lab.kubectl("apply", "-f", "-", payload=json.dumps(obj))
    name = "dns-anomaly-observer"
    _apply({"apiVersion":"v1", "kind":"ConfigMap", "metadata":{"name":name},
            "data":{"rows.json":json.dumps(records), "expected.json":json.dumps(expected),
                    "observer.py":(HERE / "anomaly-observer.py").read_text(encoding="utf-8"),
                    "evaluator.py":(HERE / "anomaly-evaluator.py").read_text(encoding="utf-8")}})
    workload = pod(name, [container(
        "observer", image="docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
        command=["python", "/fixture/observer.py"],
        volumeMounts=[{"name":"scope", "mountPath":"/fixture", "readOnly":True}],
    )], automountServiceAccountToken=False, volumes=[{"name":"scope", "configMap":{"name":name}}])
    _apply({"apiVersion":"batch/v1", "kind":"Job", "metadata":{"name":name},
            "spec":{"backoffLimit":0, "activeDeadlineSeconds":45,
                   "template":{"spec":workload["spec"]}}})
    lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=55s", timeout=65)
    return json.loads(lab.kubectl("logs", f"job/{name}", "-c", "observer").stdout)


def run_anomaly_extension(lab, pod_ip, read_logs):
    """Runs only 8 local .test questions; caller supplies original CoreDNS log reader."""
    probes = (
        [(QNAME_CONTROL, "A")] * 2
        + [(QNAME_BURST, "A")] * 3
        + [(QNAME_LONG, "A"), (QNAME_ENTROPY, "A"), (QNAME_QTYPE, "TXT")]
    )
    responses = [_query(lab, name, qtype, pod_ip) for name, qtype in probes]
    # Wait for the eight exact fixture rows to reach the local CoreDNS stdout.
    deadline = time.monotonic() + 8
    expected_counts = Counter(probes)
    while True:
        records = [
            row for row in _rows(read_logs())
            if (row["qname"], row["qtype"]) in expected_counts
        ]
        counts = Counter((row["qname"], row["qtype"]) for row in records)
        if len(records) >= len(probes) or time.monotonic() >= deadline:
            break
        time.sleep(0.25)
    # Exactly one test client and one isolated zone are in scope; no ambient traffic is included.
    transport_matches = all(row["qclass"] == "IN" and row["proto"] == "udp" for row in records)
    lab.check("positive", "Eight bounded local fixture DNS questions receive matching replies and exact CoreDNS log records",
              len(responses) == 8 and all(r["response_received"] and r["question_matched"] for r in responses)
              and counts == expected_counts and transport_matches,
              {"probe_count":len(probes), "responses_matched":sum(r["response_received"] and r["question_matched"] for r in responses),
               "observed_fixture_rows":len(records), "query_types":sorted({t for _,t in probes})})
    observer = _run_observer(lab, records)
    alerts = {(a["rule"],a["qname"]):a for a in observer["alerts"]}
    lab.check("red", "Bounded per-name volume counter alerts at three while the two-query control remains below threshold",
              observer["volume_control_count"] == 2 and observer["volume_burst_count"] == 3
              and ("fixture-query-volume", QNAME_BURST) in alerts
              and ("fixture-query-volume", QNAME_CONTROL) not in alerts,
              {"control_count":observer["volume_control_count"], "burst_count":observer["volume_burst_count"],
               "volume_alert":alerts.get(("fixture-query-volume", QNAME_BURST))})
    lab.check("red", "Long and high-entropy labels trigger separate bounded shape counters without cross-triggering",
              ("fixture-long-label", QNAME_LONG) in alerts
              and ("fixture-high-entropy-label", QNAME_ENTROPY) in alerts
              and not any(a["qname"] == QNAME_LONG and a["rule"] == "fixture-high-entropy-label" for a in alerts.values())
              and not any(a["qname"] == QNAME_ENTROPY and a["rule"] == "fixture-long-label" for a in alerts.values()),
              {"long_label_length":len(QNAME_LONG.split(".",1)[0]),
               "entropy_label_length":len(QNAME_ENTROPY.split(".",1)[0]),
               "shape_alerts":[a for a in observer["alerts"] if "label" in a["rule"]]})
    lab.check("red", "TXT query is distinguished from ordinary A queries by the unusual-type rule",
              ("fixture-unusual-qtype", QNAME_QTYPE) in alerts
              and observer["counts"].get(f"{QNAME_QTYPE}|TXT") == 1,
              {"txt_count":observer["counts"].get(f"{QNAME_QTYPE}|TXT",0),
               "type_alert":alerts.get(("fixture-unusual-qtype", QNAME_QTYPE))})
    lab.check("positive", "Separate local observer receives the exact independently counted anomaly decisions",
              set(alerts) == {
                  ("fixture-query-volume", QNAME_BURST),
                  ("fixture-long-label", QNAME_LONG),
                  ("fixture-high-entropy-label", QNAME_ENTROPY),
                  ("fixture-unusual-qtype", QNAME_QTYPE),
              } and observer["observed_records"] == 8,
              {"observed_records":observer["observed_records"], "alerts":observer["alerts"],
               "scope":"synthetic closed .fixture.test queries only"})
