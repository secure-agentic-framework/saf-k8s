"""Validate a defensive AI incident classification and ownership worksheet in a Job."""
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SCOPE = (
    "One fresh Kind Kubernetes v1.36.1 cluster runs a read-only Python validator Job over abstract, "
    "non-operational incident records and a defensive classification/traceability/ownership worksheet. "
    "The Job independently validates a deliberately incomplete/misclassified baseline and a complete "
    "candidate worksheet, then checks a permitted synthetic positive record. Raw JSON and stable "
    "summary evidence are captured. The nine control.* labels and their group boundaries in the "
    "fixture are provisional SAF-K8S examples pending verification against an authorized CTA-2114 "
    "normative copy; the test does not validate CTA class membership, definitions, or completeness. "
    "NIST AI 100-2e2025 is shown only as a separate comparator. The case verifies local worksheet "
    "traceability behavior and does not establish production coverage, incident attribution, or CTA "
    "conformance."
)

def _wait(lab, name):
    end = time.monotonic() + 100
    while time.monotonic() < end:
        job = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        conditions = {x["type"] for x in job.get("status", {}).get("conditions", []) if x.get("status") == "True"}
        if "Complete" in conditions: return
        if "Failed" in conditions: lab.block("worksheet validator Job failed")
        time.sleep(.5)
    lab.block("worksheet validator Job timed out")

def run(lab):
    fixture = json.loads((HERE / "fixtures.json").read_text())
    cm = {"apiVersion": "v1", "kind": "ConfigMap",
          "metadata": {"name": "saf-1004-001-fixture"},
          "data": {"fixture.json": json.dumps(fixture, sort_keys=True),
                   "validator.py": (HERE / "validator.py").read_text()}}
    job = {"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"saf-1004-001-validator"},"spec":{
      "backoffLimit":0,"activeDeadlineSeconds":80,"ttlSecondsAfterFinished":300,"template":{"spec":{
      "restartPolicy":"Never","automountServiceAccountToken":False,
      "securityContext":{"runAsNonRoot":True,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"}},
      "containers":[{"name":"validator","image":IMAGE,"imagePullPolicy":"IfNotPresent",
       "command":["python","/fixture/validator.py"],"resources":{"requests":{"cpu":"10m","memory":"24Mi"},"limits":{"cpu":"100m","memory":"96Mi"}},
       "securityContext":{"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]}},
       "volumeMounts":[{"name":"fixture","mountPath":"/fixture","readOnly":True}]}],
      "volumes":[{"name":"fixture","configMap":{"name":"saf-1004-001-fixture","defaultMode":292}}]}}}}
    lab.create(cm); lab.create(job); _wait(lab,"saf-1004-001-validator")
    pods=json.loads(lab.kubectl("get","pods","-l","job-name=saf-1004-001-validator","-o","json").stdout)["items"]
    name=pods[0]["metadata"]["name"]
    logs=lab.kubectl("logs",f"pod/{name}","-c","validator").stdout
    (lab.evidence/"validator.raw.log").write_text(logs)
    report = json.loads(logs)
    lab.check("red", "The worksheet catches missing links and invalid observations",
              report["baseline"] == {
                  "missing_class_links": ["control.data_poisoning", "control.model_poisoning"],
                  "invalid_records": ["INC-ABSTRACT-01", "INC-ABSTRACT-02", "INC-ABSTRACT-03"],
              }, report["baseline"])
    lab.check("green", "The worksheet accepts completed links and evidence-backed classifications",
              report["candidate"] == {"missing_class_links": [], "invalid_records": []}
              and report["cta_attribution"] == "unverified", report["candidate"])
    lab.check("positive", "An independent observation maps to a known owned class",
              report["positive"] == {"class": "control.model_poisoning", "owner": "AI/ML Engineering"},
              report["positive"])
