"""Owned-cluster demo of an explicit cross-classification transfer gate."""
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
import time

HERE = Path(__file__).resolve().parent
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
SCOPE = (
    "One Kind v1.36.1 namespace with a source Pod, bounded transfer gateway, and separate "
    "case-owned destination Pods for the public and restricted fixtures. Immutable ConfigMaps "
    "provide typed stage scope and exact approval. The cluster restricts receiver ingress to "
    "the gateway. Tests compare the same fixed event with the policy off, approval absent, "
    "approval mismatched, and approval exact, then verify the separate same-classification path. "
    "Production workflow, approval identity, tenancy, persistent stores and derived data need "
    "separate evidence."
)

NS = "saf-test"
GATE = "pipeline-gate"
DEST = {"public": "pipeline-public-destination", "restricted": "pipeline-restricted-destination"}
SOURCE = "pipeline-source"
MARKER = b"SAF fixture marker: inert synthetic data only\n"
MARKER_SHA = hashlib.sha256(MARKER).hexdigest()
EVENT = {
    "request_ref": "approval-0904-012-one-transfer",
    "event_id": "fixture-transfer-001",
    "source_stage": "training-restricted",
    "source_classification": "restricted",
    "destination_stage": "serving-public",
    "destination_classification": "public",
    "marker": "marker.txt",
    "marker_sha256": MARKER_SHA,
}
ORDINARY = {
    "request_ref": "ordinary-same-class",
    "event_id": "fixture-transfer-ordinary",
    "source_stage": "training-restricted",
    "source_classification": "restricted",
    "destination_stage": "validation-restricted",
    "destination_classification": "restricted",
    "marker": "marker.txt",
    "marker_sha256": MARKER_SHA,
}
APPROVAL = {key: EVENT[key] for key in EVENT}


def config_map(name, data, *, immutable=True):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name}, "immutable": immutable,
            "data": data}


def security_context():
    return {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
            "runAsUser": 65534, "runAsGroup": 65534,
            "seccompProfile": {"type": "RuntimeDefault"}}


def pod(name, container, *, volumes, labels, fs_group=None):
    spec = {"automountServiceAccountToken": False, "restartPolicy": "Always",
            "terminationGracePeriodSeconds": 1,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534},
            "containers": [container], "volumes": volumes}
    if fs_group is not None:
        spec["securityContext"]["fsGroup"] = fs_group
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "labels": labels}, "spec": spec}


def container(name, command, mounts, port=None):
    result = {"name": name, "image": IMAGE, "imagePullPolicy": "IfNotPresent",
              "command": command, "securityContext": security_context(),
              "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                            "limits": {"cpu": "200m", "memory": "96Mi"}},
              "volumeMounts": mounts}
    if port:
        result["ports"] = [{"name": "http", "containerPort": port}]
        result["readinessProbe"] = {"httpGet": {"path": "/healthz", "port": port},
                                    "periodSeconds": 2, "timeoutSeconds": 1,
                                    "failureThreshold": 15}
    return result


def wait_pod(lab, name):
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=80s", timeout=90)


def create_gate(lab):
    lab.create(pod(GATE, container("gate", ["python", "-B", "/fixture/gateway.py"], [
        {"name": "fixtures", "mountPath": "/fixture", "readOnly": True},
        {"name": "scope", "mountPath": "/scope", "readOnly": True},
        {"name": "policy", "mountPath": "/policy", "readOnly": True},
        {"name": "approval", "mountPath": "/approval", "readOnly": True},
    ], 8080), volumes=[
        {"name": "fixtures", "configMap": {"name": "pipeline-fixtures"}},
        {"name": "scope", "configMap": {"name": "pipeline-stage-scope"}},
        {"name": "policy", "configMap": {"name": "pipeline-policy"}},
        {"name": "approval", "configMap": {"name": "pipeline-approval", "optional": True}},
    ], labels={"app": GATE}))


def restart_gate(lab):
    lab.kubectl("delete", "pod", GATE, "--wait=true", timeout=45)
    create_gate(lab)
    wait_pod(lab, GATE)
    wait_service(lab, GATE)


def wait_service(lab, name):
    target = pod_uid(lab, name)
    limit = time.monotonic() + 15
    while time.monotonic() < limit:
        result = lab.kubectl("get", "endpointslice", "-l", f"kubernetes.io/service-name={name}",
                             "-o", "json")
        endpoints = [row.get("targetRef", {}).get("uid")
                     for item in json.loads(result.stdout)["items"] for row in (item.get("endpoints") or [])
                     if row.get("conditions", {}).get("ready") is True]
        if endpoints == [target]:
            return
        time.sleep(0.25)
    lab.block(f"The Service {name} did not target its current Ready Pod")


def deploy(lab):
    fixtures = {name: (HERE / name).read_text() for name in
                ("gateway.py", "destination.py", "marker.txt")}
    lab.create(config_map("pipeline-fixtures", fixtures))
    lab.create(config_map("pipeline-stage-scope", {
        "scope.json": json.dumps({"cross_classification": EVENT,
                                  "ordinary": ORDINARY}, sort_keys=True),
    }))
    lab.create(config_map("pipeline-policy", {
        "policy.json": json.dumps({"enabled": False}, sort_keys=True),
    }, immutable=False))
    create_gate(lab)
    lab.create({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": GATE}, "spec": {
                    "selector": {"app": GATE},
                    "ports": [{"name": "http", "port": 8080, "targetPort": 8080}],
                }})
    for classify, name in DEST.items():
        lab.create({"apiVersion": "v1", "kind": "Service",
                    "metadata": {"name": name}, "spec": {
                        "selector": {"app": name},
                        "ports": [{"name": "http", "port": 8081, "targetPort": 8081}],
                    }})
        create_destination(lab, classify, name)
    lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                "metadata": {"name": "pipeline-receiver-gateway-only"},
                "spec": {"podSelector": {"matchLabels": {"saf.example/component": "receiver"}},
                         "policyTypes": ["Ingress"],
                         "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": GATE}}}],
                                      "ports": [{"protocol": "TCP", "port": 8081}]}]}})
    lab.create(pod(SOURCE, container("source", ["python", "-B", "-c",
        "import time; time.sleep(600)"], []), volumes=[],
        labels={"app": SOURCE}))
    wait_pod(lab, GATE)
    wait_service(lab, GATE)
    wait_pod(lab, SOURCE)


def create_destination(lab, classify, name):
    lab.create(pod(name, container("receiver", ["python", "-B", "/fixture/destination.py", classify], [
        {"name": "fixtures", "mountPath": "/fixture", "readOnly": True},
        {"name": "receipt", "mountPath": "/data"},
    ], 8081), volumes=[
        {"name": "fixtures", "configMap": {"name": "pipeline-fixtures"}},
        {"name": "receipt", "emptyDir": {"sizeLimit": "1Mi"}},
    ], labels={"app": name, "saf.example/component": "receiver"}, fs_group=65534))
    wait_pod(lab, name)
    wait_service(lab, name)


def clear_public_receipt(lab):
    lab.kubectl("exec", "pod/" + DEST["public"], "--", "python", "-B", "-c",
                "from pathlib import Path; Path('/data/receipt').unlink(missing_ok=True)")
    if destination_receipt(lab, DEST["public"])["present"]:
        lab.block("The case-owned initial receipt was not cleared")


def source_request(lab, event):
    # Source process sends the same typed event each time; no host-side HTTP bypass.
    result = lab.kubectl("exec", "pod/" + SOURCE, "--", "python", "-B", "-c",
        "import json,sys,urllib.request,urllib.error; "
        "opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); "
        "body=json.dumps(json.loads(sys.argv[1]),sort_keys=True).encode(); "
        "req=urllib.request.Request('http://pipeline-gate:8080/transfer',data=body,"
        "headers={'Content-Type':'application/json'},method='POST'); "
        "\ntry:\n r=opener.open(req,timeout=3); code=r.status; raw=r.read()"
        "\nexcept urllib.error.HTTPError as e: code=e.code; raw=e.read()"
        "\nprint(json.dumps({'http_status':code,'receipt':json.loads(raw)},sort_keys=True))",
        json.dumps(event, sort_keys=True), timeout=15)
    try:
        row = json.loads(result.stdout)
        if row.get("http_status") not in (200, 403):
            lab.block(f"Transfer fixture request failed: {row}")
        return row
    except (json.JSONDecodeError, TypeError) as error:
        lab.block(f"In-cluster source returned no typed decision receipt: {error}")


def destination_receipt(lab, receiver):
    result = lab.kubectl("exec", "pod/" + receiver, "--", "python", "-B", "-c",
        "from pathlib import Path; import hashlib,json; p=Path('/data/receipt'); "
        "print(json.dumps({'present':p.is_file(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()"
        " if p.is_file() else None,'bytes':len(p.read_bytes()) if p.is_file() else 0},sort_keys=True))",
        timeout=15)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"Destination receipt observation is invalid: {error}")


def pod_uid(lab, name):
    result = lab.kubectl("get", "pod", name, "-o", "json")
    try:
        return json.loads(result.stdout)["metadata"]["uid"]
    except (KeyError, json.JSONDecodeError) as error:
        lab.block(f"Pod identity evidence is incomplete for {name}: {error}")


def observe(lab, event):
    started = datetime.now(timezone.utc).isoformat()
    before = time.monotonic()
    decision = source_request(lab, event)
    target = DEST[event["destination_classification"]]
    destination = destination_receipt(lab, target)
    elapsed_ms = round((time.monotonic() - before) * 1000, 3)
    stable = {"decision": decision, "destination": destination}
    raw = {**stable, "started_at": started, "elapsed_ms": elapsed_ms,
           "pod_uids": {"gate": pod_uid(lab, GATE), "source": pod_uid(lab, SOURCE),
                        "destination": pod_uid(lab, target)}}
    return stable, raw


def run(lab):
    deploy(lab)
    observations = {}
    raw_observations = {}
    observations["red"], raw_observations["red"] = observe(lab, EVENT)
    lab.check("red", "With cross-classification policy disabled, the fixed event is transferred",
              observations["red"]["decision"] == {"http_status": 200,
                "receipt": {"decision": "allow", "reason": "policy_disabled",
                            "request_ref": EVENT["request_ref"], "event_id": EVENT["event_id"]}}
              and observations["red"]["destination"] == {
                  "present": True, "sha256": MARKER_SHA, "bytes": len(MARKER)},
              observations["red"])

    # Remove the first receipt so each subsequent outcome is independently attributable.
    clear_public_receipt(lab)
    lab.kubectl("patch", "configmap/pipeline-policy", "--type=merge", "-p",
                json.dumps({"data": {"policy.json": json.dumps({"enabled": True}, sort_keys=True)}}))
    restart_gate(lab)
    observations["green_no_approval"], raw_observations["green_no_approval"] = observe(lab, EVENT)
    denied = observations["green_no_approval"]
    lab.check("green", "Enabled policy denies the same event without approval and creates no destination receipt",
              denied["decision"] == {"http_status": 403,
                "receipt": {"decision": "deny", "reason": "approval_required",
                            "request_ref": EVENT["request_ref"], "event_id": EVENT["event_id"]}}
              and denied["destination"] == {"present": False, "sha256": None, "bytes": 0}, denied)

    # An immutable but wrong-destination approval must not authorize the fixed event.
    wrong = dict(APPROVAL, destination_stage="other-stage")
    lab.create(config_map("pipeline-approval", {
        "approval.json": json.dumps(wrong, sort_keys=True),
    }))
    restart_gate(lab)
    observations["green_wrong_scope"], raw_observations["green_wrong_scope"] = observe(lab, EVENT)
    wrong_obs = observations["green_wrong_scope"]
    lab.check("green", "A mounted approval with a different destination stage is rejected",
              wrong_obs["decision"] == {"http_status": 403,
                "receipt": {"decision": "deny", "reason": "approval_scope_mismatch",
                            "request_ref": EVENT["request_ref"], "event_id": EVENT["event_id"]}}
              and wrong_obs["destination"] == {"present": False, "sha256": None, "bytes": 0},
              wrong_obs)

    lab.kubectl("delete", "configmap", "pipeline-approval", timeout=20)
    lab.create(config_map("pipeline-approval", {
        "approval.json": json.dumps(APPROVAL, sort_keys=True),
    }))
    restart_gate(lab)
    observations["green_exact_approval"], raw_observations["green_exact_approval"] = observe(lab, EVENT)
    exact = observations["green_exact_approval"]
    lab.check("green", "Only the exact immutable approval scope admits the transfer and destination bytes match",
              exact["decision"] == {"http_status": 200,
                "receipt": {"decision": "allow", "reason": "exact_approval",
                            "request_ref": EVENT["request_ref"], "event_id": EVENT["event_id"]}}
              and exact["destination"] == {
                  "present": True, "sha256": MARKER_SHA, "bytes": len(MARKER)}, exact)

    if destination_receipt(lab, DEST["restricted"])["present"]:
        lab.block("The separate ordinary destination received unexpected prior data")
    observations["positive"], raw_observations["positive"] = observe(lab, ORDINARY)
    ordinary = observations["positive"]
    lab.check("positive", "An ordinary same-classification stage transfer remains available",
              ordinary["decision"] == {"http_status": 200,
                "receipt": {"decision": "allow", "reason": "same_classification",
                            "request_ref": ORDINARY["request_ref"], "event_id": ORDINARY["event_id"]}}
              and ordinary["destination"] == {
                  "present": True, "sha256": MARKER_SHA, "bytes": len(MARKER)}, ordinary)

    # Stable canonical observations omit server UIDs and wall-clock timing.
    (lab.evidence / "pipeline-transfer.raw.json").write_text(
        json.dumps(raw_observations, indent=2, sort_keys=True) + "\n")
