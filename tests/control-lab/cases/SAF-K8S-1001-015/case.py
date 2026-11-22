"""Exercise Fluent Bit payload minimization against a disposable local Loki."""
import json
from pathlib import Path

from fixtures import container, pod, ready

CASE_DIR = Path(__file__).resolve().parent
QUERY_IMAGE = (
    "docker.io/library/python:3.12.8-alpine3.21@sha256:"
    "ba13ef990f6e5d13014e9e8d04c02a8fdb0fe53d6dccf6e19147f316e6cc3a84"
)
NAMESPACE = "saf-test"
LOKI_IMAGE = "grafana/loki:3.5.0@sha256:4c431d2e6b9b38718694b31c5d56be7c80dc69c513215fde1aeb5b02cd4e2665"
FLUENT_BIT_IMAGE = "cr.fluentbit.io/fluent/fluent-bit:5.1.2@sha256:d792375ca8e53be72fc25716c28f291f32c6fc6f4f31d12d0d14bc78cefe9226"
SCOPE = (
    "One Fluent Bit 5.1.2 tail -> Lua filter -> Loki 3.5.0 path in the runner's disposable Kind "
    "cluster. It reads only four case-owned fixture lines: one synthetic request, one synthetic "
    "response, one benign positive record, and one malformed line. Green behavior covers only "
    "the literal synthetic patterns PERSON_[A-Z]+_[0-9]+ and KEY_[A-Z]+_[0-9]+ in the two "
    "allow-listed text fields, drops the fixture's customer_ref and auth_fragment fields, and "
    "preserves event_id, direction, model, status, elapsed_ms and scrubbed text. Malformed tail "
    "input is replaced with a fixed marker. This does not evaluate NER, general PII detection, "
    "nested/encoded payloads, production model or application collection, retention/access "
    "governance, forensic sampling, or non-payload operational logs. All fixture values are "
    "invented and non-sensitive; no external target, service, or credential is used."
)


def apply(lab, resource):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(resource, separators=(",", ":")))


def load_fixtures():
    return json.loads((CASE_DIR / "fixtures.json").read_text())


def make_configmaps(lab, fixtures):
    apply(lab, {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf015-fixtures", "namespace": NAMESPACE},
        "immutable": True,
        "data": {"events.jsonl": "".join(json.dumps(row, separators=(",", ":")) + "\n"
                                         for row in fixtures["valid_events"])
                                + fixtures["malformed_line"] + "\n"},
    })
    loki_config = r'''auth_enabled: false
server:
  http_listen_port: 3100
common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
schema_config:
  configs:
    - from: "2024-01-01"
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
'''
    apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "saf015-loki-config", "namespace": NAMESPACE},
                "data": {"config.yaml": loki_config}})
    apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "saf015-minimizer", "namespace": NAMESPACE},
                "data": {"minimize.lua": (CASE_DIR / "minimize.lua").read_text()}})


def deploy_loki(lab):
    apply(lab, {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "saf015-loki", "namespace": NAMESPACE,
                     "labels": {"app": "saf015-loki"}},
        "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "fsGroup": 10001},
            "containers": [{"name": "loki", "image": LOKI_IMAGE, "imagePullPolicy": "IfNotPresent",
                "args": ["-config.file=/etc/loki/config.yaml"], "ports": [{"containerPort": 3100}],
                "readinessProbe": {"httpGet": {"path": "/ready", "port": 3100},
                                   "initialDelaySeconds": 5, "periodSeconds": 2},
                "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "config", "mountPath": "/etc/loki", "readOnly": True},
                                 {"name": "data", "mountPath": "/loki"}]}],
            "volumes": [{"name": "config", "configMap": {"name": "saf015-loki-config"}},
                        {"name": "data", "emptyDir": {}}],
        },
    })
    apply(lab, {"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": "saf015-loki", "namespace": NAMESPACE},
                "spec": {"selector": {"app": "saf015-loki"},
                         "ports": [{"name": "http", "port": 3100, "targetPort": 3100}]}})
    lab.kubectl("wait", "--for=condition=Ready", "pod/saf015-loki", "--timeout=120s", timeout=130)


def fluent_config(phase):
    add_filter = phase == "green"
    filters = (
        "  filters:\n"
        "    - name: lua\n"
        "      alias: saf015_payload_minimizer\n"
        "      match: saf015.*\n"
        "      script: /fluent-bit/etc/minimize.lua\n"
        "      call: minimize_payload\n"
        "      protected_mode: true\n"
        if add_filter else ""
    )
    return f'''service:
  flush: 1
  log_level: info
  http_server: true
  http_listen: 0.0.0.0
  http_port: 2020
pipeline:
  inputs:
    - name: tail
      alias: saf015_valid_json
      tag: saf015.valid
      path: /fixtures/events.jsonl
      parser: saf015_json
      read_from_head: true
      refresh_interval: 1
{filters}  outputs:
    - name: loki
      match: saf015.*
      host: saf015-loki
      port: 3100
      labels: control=SAF-K8S-1001-015,case_phase={phase}
      line_format: json
      workers: 1
parsers:
  - name: saf015_json
    format: json
'''


def start_forwarder(lab, phase):
    name = f"saf015-{phase}"
    apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": name, "namespace": NAMESPACE}, "immutable": True,
                "data": {"fluent-bit.yaml": fluent_config(phase)}})
    apply(lab, {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE, "labels": {"app": name}},
        "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "fsGroup": 1000},
            "containers": [{"name": "fluent-bit", "image": FLUENT_BIT_IMAGE,
                "imagePullPolicy": "IfNotPresent", "args": ["-c", "/fluent-bit/etc/fluent-bit.yaml"],
                "ports": [{"containerPort": 2020}],
                "securityContext": {"allowPrivilegeEscalation": False,
                                     "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [
                    {"name": "config", "mountPath": "/fluent-bit/etc/fluent-bit.yaml",
                     "subPath": "fluent-bit.yaml", "readOnly": True},
                    {"name": "fixtures", "mountPath": "/fixtures", "readOnly": True},
                    {"name": "state", "mountPath": "/tmp"},
                    *([{"name": "lua", "mountPath": "/fluent-bit/etc/minimize.lua",
                        "subPath": "minimize.lua", "readOnly": True}] if phase == "green" else []),
                ]}],
            "volumes": [
                {"name": "config", "configMap": {"name": name}},
                {"name": "fixtures", "configMap": {"name": "saf015-fixtures"}},
                {"name": "state", "emptyDir": {}},
                *([{"name": "lua", "configMap": {"name": "saf015-minimizer"}}]
                  if phase == "green" else []),
            ],
        },
    })
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=90s", timeout=100)


def query_loki(lab, phase, minimum):
    script = r'''import json,sys,time,urllib.parse,urllib.request
phase=sys.argv[1]
query='{control="SAF-K8S-1001-015",case_phase="'+phase+'"}'
for _ in range(60):
 try:
  now=time.time_ns()
  params=urllib.parse.urlencode({'query':query,'start':str(now-900_000_000_000),'end':str(now+30_000_000_000),'limit':'100','direction':'forward'})
  with urllib.request.urlopen('http://saf015-loki:3100/loki/api/v1/query_range?'+params,timeout=5) as r:
   value=json.load(r)
  count=sum(len(stream.get('values',[])) for stream in value.get('data',{}).get('result',[]))
  if value.get('status')=='success' and count>=int(sys.argv[2]):
   print(json.dumps(value,separators=(',',':'))); break
 except Exception:
  pass
 time.sleep(1)
else:
 raise SystemExit('Loki query_range did not return the requested fixture count for '+phase)
'''
    result = lab.kubectl("exec", "saf015-query", "--", "python3", "-c",
                         script, phase, str(minimum), timeout=90)
    return json.loads(result.stdout)



def extract_rows(response):
    rows = []
    for stream in response.get("data", {}).get("result", []):
        labels = stream.get("stream", {})
        for _timestamp, line in stream.get("values", []):
            rows.append({"labels": labels, "payload": json.loads(line)})
    return rows


def run(lab):
    fixtures = load_fixtures()
    make_configmaps(lab, fixtures)
    deploy_loki(lab)
    lab.create(pod("saf015-query", [container("client", image=QUERY_IMAGE)],
                   automountServiceAccountToken=False))
    ready(lab, "saf015-query")

    # Red: same fixture source, Fluent Bit Loki output active, minimization filter absent.
    start_forwarder(lab, "red")
    red_response = query_loki(lab, "red", 4)
    (lab.evidence / "red-loki-query.json").write_text(json.dumps(red_response, indent=2) + "\n")
    red_rows = extract_rows(red_response)
    red = {("saf015-malformed-001" if row["payload"] == {"log": fixtures["malformed_line"]}
            else row["payload"].get("event_id", "")): row for row in red_rows}
    red_expected_ids = sorted(fixtures["expected_red"].keys())
    red_ok = (
        len(red_rows) == 4 and sorted(red.keys()) == red_expected_ids
        and all(row["labels"] == {"control": "SAF-K8S-1001-015", "case_phase": "red",
                                  "detected_level": "unknown", "service_name": "unknown_service"}
                for row in red_rows)
        and all(red[event_id]["payload"] == fixtures["expected_red"][event_id]
                for event_id in red_expected_ids)
    )
    lab.check("red", "With minimization absent, Loki stores both synthetic payload sentinels and structured sensitive fields",
              red_ok, {"query_status": red_response.get("status"), "event_ids": sorted(red.keys()),
                       "exact_labels_and_raw_payloads_match": red_ok,
                       "request_raw_sentinels_present": all(token in json.dumps(red.get("saf015-request-001", {}).get("payload", {})) for token in fixtures["sentinels"][:2]),
                       "response_raw_sentinels_present": all(token in json.dumps(red.get("saf015-response-001", {}).get("payload", {})) for token in ("PERSON_COPPER_015", "KEY_ORBIT_015"))})

    # Green: repeat identical files through Fluent Bit's in-pipeline Lua filter.
    start_forwarder(lab, "green")
    green_response = query_loki(lab, "green", 4)
    (lab.evidence / "green-loki-query.json").write_text(json.dumps(green_response, indent=2) + "\n")
    green_rows = extract_rows(green_response)
    green = {row["payload"].get("event_id"): row for row in green_rows}
    expected_green = fixtures["expected_green"]
    green_ok = (
        len(green_rows) == 4 and sorted(green.keys()) == sorted(expected_green.keys())
        and all(row["labels"] == {"control": "SAF-K8S-1001-015", "case_phase": "green",
                                  "detected_level": "unknown", "service_name": "unknown_service"}
                for row in green_rows)
        and all(green[event_id]["payload"] == expected_green[event_id]
                for event_id in expected_green)
        and all(token not in json.dumps(green, sort_keys=True) for token in fixtures["sentinels"])
    )
    lab.check("green", "Loki stores exactly the allow-listed, pattern-masked request/response records; structured fields and malformed bytes are absent",
              green_ok, {"query_status": green_response.get("status"), "event_ids": sorted(green.keys()),
                         "exact_labels_and_minimized_payloads_match": green_ok,
                         "sentinels_absent_from_backend_result": all(token not in json.dumps(green, sort_keys=True) for token in fixtures["sentinels"])})

    positive = green.get("saf015-positive-001", {}).get("payload", {})
    positive_ok = (positive == expected_green["saf015-positive-001"]
                   and positive.get("status") == "ok"
                   and positive.get("prompt") == "Summarize the invented sample dataset.")
    lab.check("positive", "Benign request record remains queryable with its permitted metadata and unchanged operational text",
              positive_ok, {"event_id": positive.get("event_id"), "status": positive.get("status"),
                            "permitted_metadata_preserved": positive_ok})
