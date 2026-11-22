"""Route case-owned, already-collected fixtures through Fluent Bit into Loki."""
import json
import time
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
LOKI_IMAGE = "grafana/loki:3.5.0@sha256:4c431d2e6b9b38718694b31c5d56be7c80dc69c513215fde1aeb5b02cd4e2665"
FLUENT_BIT_IMAGE = "cr.fluentbit.io/fluent/fluent-bit:5.1.2@sha256:d792375ca8e53be72fc25716c28f291f32c6fc6f4f31d12d0d14bc78cefe9226"
PYTHON_IMAGE = "docker.io/library/python:3.12.8-alpine3.21@sha256:ba13ef990f6e5d13014e9e8d04c02a8fdb0fe53d6dccf6e19147f316e6cc3a84"
SCOPE = (
    "One case-owned namespace in the runner's disposable Kind cluster. Fluent Bit tails only five "
    "static case-owned JSON fixture files and exports them to a local Loki single-binary backend. "
    "Four event categories represent upstream collected records; this case does not collect or "
    "validate node, container, provider, or accelerator sources. No external endpoint or credentials."
)


def apply(lab, resource):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(resource))


def configmaps(lab, events):
    fixtures = {event["event_id"]: json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events}
    files = {
        "node.jsonl": next(v for k, v in fixtures.items() if k == "saf033-node-001"),
        "container.jsonl": next(v for k, v in fixtures.items() if k == "saf033-container-001"),
        "provider.jsonl": next(v for k, v in fixtures.items() if k == "saf033-provider-001"),
        "accelerator.jsonl": next(v for k, v in fixtures.items() if k == "saf033-accelerator-001"),
        "retention.jsonl": next(v for k, v in fixtures.items() if k == "saf033-retention-001"),
    }
    apply(lab, {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"fixtures","namespace":NAMESPACE},"data":files})
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
limits_config:
  retention_period: 72h
  retention_stream:
    - selector: '{pipeline="retention-probe"}'
      priority: 10
      period: 24h
compactor:
  working_directory: /loki/compactor
  retention_enabled: true
  delete_request_store: filesystem
'''
    apply(lab, {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"loki-config","namespace":NAMESPACE},"data":{"config.yaml":loki_config}})
    fluent_config = r'''service:
  flush: 1
  log_level: info
  http_server: true
  http_listen: 0.0.0.0
  http_port: 2020
pipeline:
  inputs:
    - name: tail
      tag: saf033.node
      alias: fixture_node
      path: /fixtures/node.jsonl
      parser: fixture_json
      read_from_head: true
      refresh_interval: 1
    - name: tail
      tag: saf033.container
      alias: fixture_container
      path: /fixtures/container.jsonl
      parser: fixture_json
      read_from_head: true
      refresh_interval: 1
    - name: tail
      tag: saf033.provider
      alias: fixture_provider
      path: /fixtures/provider.jsonl
      parser: fixture_json
      read_from_head: true
      refresh_interval: 1
    - name: tail
      tag: saf033.accelerator
      alias: fixture_accelerator
      path: /fixtures/accelerator.jsonl
      parser: fixture_json
      read_from_head: true
      refresh_interval: 1
    - name: tail
      tag: saf033.retention
      alias: fixture_retention
      path: /fixtures/retention.jsonl
      parser: fixture_json
      read_from_head: true
      refresh_interval: 1
  outputs:
    - name: loki
      @MATCH@
      host: loki
      port: 3100
      labels: control=SAF-K8S-1001-033,export_path=saf033-approved-loki-export
      label_keys: $source_class,$pipeline
      line_format: json
      workers: 1
parsers:
  - name: fixture_json
    format: json
'''
    for label, match in (
        ("given", "match: saf033.retention"),
        ("routed", "match_regex: '^saf033[.](node|container|provider|accelerator)$'"),
    ):
        apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": f"forwarder-{label}", "namespace": NAMESPACE},
                    "immutable": True, "data": {"fluent-bit.yaml": fluent_config.replace("@MATCH@", match)}})


def deploy_backend(lab):
    apply(lab, {"apiVersion":"v1","kind":"Pod","metadata":{"name":"loki","namespace":NAMESPACE,"labels":{"app":"loki"}},"spec":{"automountServiceAccountToken":False,"securityContext":{"runAsNonRoot":True,"runAsUser":10001,"fsGroup":10001},"containers":[{"name":"loki","image":LOKI_IMAGE,"imagePullPolicy":"IfNotPresent","args":["-config.file=/etc/loki/config.yaml"],"ports":[{"containerPort":3100}],"readinessProbe":{"httpGet":{"path":"/ready","port":3100},"initialDelaySeconds":5,"periodSeconds":2},"securityContext":{"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":False,"capabilities":{"drop":["ALL"]}},"volumeMounts":[{"name":"config","mountPath":"/etc/loki","readOnly":True},{"name":"data","mountPath":"/loki"}]}],"volumes":[{"name":"config","configMap":{"name":"loki-config"}},{"name":"data","emptyDir":{}}]}})
    apply(lab, {"apiVersion":"v1","kind":"Service","metadata":{"name":"loki","namespace":NAMESPACE},"spec":{"selector":{"app":"loki"},"ports":[{"name":"http","port":3100,"targetPort":3100}]}})
    lab.kubectl("wait","--for=condition=Ready","pod/loki","-n",NAMESPACE,"--timeout=120s",timeout=130)
    apply(lab, {"apiVersion":"v1","kind":"Pod","metadata":{"name":"query-client","namespace":NAMESPACE},"spec":{"restartPolicy":"Never","automountServiceAccountToken":False,"securityContext":{"runAsNonRoot":True,"runAsUser":10001},"containers":[{"name":"query","image":PYTHON_IMAGE,"imagePullPolicy":"IfNotPresent","command":["python3","-c","import time; time.sleep(3600)"],"securityContext":{"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]}}}]}})
    lab.kubectl("wait","--for=condition=Ready","pod/query-client","-n",NAMESPACE,"--timeout=90s",timeout=100)


def start_forwarder(lab, phase):
    name = f"forwarder-{phase}"
    apply(lab, {"apiVersion":"v1","kind":"Pod","metadata":{"name":name,"namespace":NAMESPACE,"labels":{"app":"fluent-bit"}},"spec":{"automountServiceAccountToken":False,"securityContext":{"runAsNonRoot":True,"runAsUser":1000,"fsGroup":1000},"containers":[{"name":"fluent-bit","image":FLUENT_BIT_IMAGE,"imagePullPolicy":"IfNotPresent","args":["-c","/fluent-bit/etc/fluent-bit.yaml"],"securityContext":{"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":False,"capabilities":{"drop":["ALL"]}},"volumeMounts":[{"name":"config","mountPath":"/fluent-bit/etc/fluent-bit.yaml","subPath":"fluent-bit.yaml","readOnly":True},{"name":"fixtures","mountPath":"/fixtures","readOnly":True},{"name":"state","mountPath":"/tmp"}]}],"volumes":[{"name":"config","configMap":{"name":name}},{"name":"fixtures","configMap":{"name":"fixtures"}},{"name":"state","emptyDir":{}}]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=75s", timeout=85)
    pod = json.loads(lab.kubectl("get", f"pod/{name}", "-o", "json").stdout)
    return pod["status"]["podIP"]


def check_sources(lab, address):
    script = """import json,sys,time,urllib.request
wanted = set(sys.argv[2:])
for _ in range(30):
    try:
        with urllib.request.urlopen(f"http://{sys.argv[1]}:2020/api/v1/metrics",timeout=2) as response:
            value = json.load(response)["input"]
        read = {name for name,data in value.items() if data.get("records",0)>=1}
        if wanted <= read:
            print(json.dumps(sorted(wanted)))
            break
    except (OSError,KeyError,ValueError):
        pass
    time.sleep(1)
else:
    raise SystemExit("Forwarder did not consume each fixture input")
"""
    names = sorted(f"fixture_{category}" for category in ("node","container","provider","accelerator","retention"))
    r = lab.kubectl("exec", "pod/query-client", "--", "python3", "-c", script, address, *names,
                    timeout=70, allow_failure=True)
    if r.returncode:
        for name in ("forwarder-given","forwarder-routed"):
            lab.kubectl("logs", f"pod/{name}", "--tail=40", allow_failure=True)
        lab.block("Could not prove the actual input counters for all fixture files")
    return json.loads(r.stdout)


def fetch_loki(lab, minimum):
    # Return the actual Loki query_range response. Timestamps remain in raw command
    # evidence; replay assertions below retain only sorted IDs and exact labels.
    script = r'''import json,sys,time,urllib.parse,urllib.request
queries={'fixture_ingest':'{control="SAF-K8S-1001-033",pipeline="fixture-ingest"}','retention_probe':'{control="SAF-K8S-1001-033",pipeline="retention-probe"}'}
def query(q):
 now=time.time_ns()
 u='http://loki:3100/loki/api/v1/query_range?'+urllib.parse.urlencode({'query':q,'start':str(now-900_000_000_000),'end':str(now+30_000_000_000),'limit':'100','direction':'forward'})
 with urllib.request.urlopen(u,timeout=5) as r: return json.load(r)
for _ in range(60):
 try:
  values={name:query(q) for name,q in queries.items()}
  count=sum(len(s.get('values',[])) for s in values['fixture_ingest'].get('data',{}).get('result',[]))
  retention=sum(len(s.get('values',[])) for s in values['retention_probe'].get('data',{}).get('result',[]))
  if all(v.get('status')=='success' for v in values.values()) and count>=int(sys.argv[1]) and retention>=1:
   print(json.dumps(values,separators=(',',':'))); break
 except Exception: pass
 time.sleep(1)
else: raise SystemExit('Loki query_range did not return all fixture and retention records')
'''
    result = lab.kubectl("exec","-n",NAMESPACE,"pod/query-client","--","python3","-c",script,str(minimum),timeout=75,allow_failure=True)
    if result.returncode:
        for name in ('loki','forwarder-given','forwarder-routed'):
            lab.kubectl('logs', f'pod/{name}', '--tail=30', allow_failure=True)
        lab.block('Loki did not return the expected scoped streams')
    return json.loads(result.stdout)


def run(lab):
    spec=json.loads((CASE_DIR/"fixtures/events.json").read_text())
    configmaps(lab,spec["events"])
    deploy_backend(lab)
    baseline = start_forwarder(lab, "given")
    sources = check_sources(lab, baseline)
    before = fetch_loki(lab, 0)
    (lab.evidence / "baseline-loki-query.json").write_text(json.dumps(before, indent=2) + "\n")
    fixture_before = before["fixture_ingest"]["data"]["result"]
    reference = before["retention_probe"]["data"]["result"]
    lab.check("red", "Fluent Bit reads all files while Loki receives only the separate comparison stream",
              not fixture_before and len(reference) == 1 and len(reference[0]["values"]) == 1 and len(sources) == 5,
              {"input_counters_nonzero": sources, "main_stream_absent": not fixture_before,
               "comparison_stream_present": bool(reference)})
    routed = start_forwarder(lab, "routed")
    check_sources(lab, routed)
    responses = fetch_loki(lab, 4)
    (lab.evidence / "routed-loki-query.json").write_text(json.dumps(responses, indent=2) + "\n")
    response=responses["fixture_ingest"]
    rows=[]
    for stream in response.get("data",{}).get("result",[]):
        labels=stream.get("stream",{})
        for _timestamp,line in stream.get("values",[]):
            event=json.loads(line)
            source_class = labels.get("source_class")
            pipeline = labels.get("pipeline")
            rows.append({
                "event_id": event.get("event_id"), "source_class": source_class,
                "pipeline": pipeline, "control": labels.get("control"),
                "export_path": labels.get("export_path"),
                "payload": event | {"source_class": source_class, "pipeline": pipeline},
            })
    fixture=[r for r in rows if r["pipeline"]=="fixture-ingest"]
    ids=sorted(r["event_id"] for r in fixture)
    label_pairs=sorted((r["event_id"],r["source_class"]) for r in fixture)
    expected_pairs=sorted(zip(spec["expected_ids"],spec["expected_source_labels"]))
    expected_payloads = {event["event_id"]: event for event in spec["events"]
                         if event["pipeline"] == "fixture-ingest"}
    exact = ids == sorted(spec["expected_ids"]) and label_pairs == expected_pairs and all(
        row["control"] == spec["control_id"]
        and row["export_path"] == "saf033-approved-loki-export"
        and row["payload"] == expected_payloads.get(row["event_id"])
        for row in fixture
    )
    lab.check("green","Loki query_range returns exactly the four expected fixture event IDs with the expected source labels",exact,{"query_status":response.get("status"),"event_ids":ids,"event_source_labels":label_pairs,"export_path_labels":sorted(set(r["export_path"] for r in fixture)),"expected_export_path":"saf033-approved-loki-export","expected_ids":sorted(spec["expected_ids"]),"expected_event_source_labels":expected_pairs,"record_count":len(fixture),"approved_export_and_payload_match":exact})
    retention=[]
    for stream in responses["retention_probe"].get("data",{}).get("result",[]):
        labels=stream.get("stream",{})
        for _timestamp,line in stream.get("values",[]):
            event=json.loads(line)
            retention.append({"event_id":event.get("event_id"),"source_class":labels.get("source_class"),"pipeline":labels.get("pipeline")})
    retention_ok=len(retention)==1 and retention[0]["event_id"]=="saf033-retention-001" and retention[0]["source_class"]=="retention_probe"
    lab.check("positive","The separate retention-probe stream reaches Loki under its own pipeline label",retention_ok,{"event_ids":sorted(r["event_id"] for r in retention),"pipeline":"retention-probe","configured_retention":"24h","default_retention":"72h"})
