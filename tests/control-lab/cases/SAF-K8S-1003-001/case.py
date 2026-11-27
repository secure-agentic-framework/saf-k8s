"""Exercise the STRIDE review gate as Kubernetes Jobs."""
import json
from pathlib import Path
import time

from fixtures import container

HERE = Path(__file__).resolve().parent
SCOPE = (
    "Kubernetes v1.36.1 Kind executes independent architecture-review Jobs against synthetic "
    "records. An unenforced path accepts an incomplete record. The enabled gate rejects incomplete "
    "and stale records and accepts an internally consistent record covering nine component classes. "
    "Independent case-owned approval labels and evidence links model the review workflow. "
    "Actual threat judgment, reviewer authority and deployment coverage need separate evidence."
)
AS_OF = "2026-11-22"
CONFIG = "saf-stride-fixtures"
PYTHON = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"


def run_review(lab, items, name, record, enforce):
    basename = record + ".json"
    program = (
        ["python", "/fixture/review_gate.py", f"/fixture/{basename}", "--today", AS_OF]
        if enforce else ["python", "-c",
                         'import json,sys; json.load(open(sys.argv[1])); print(json.dumps({"status":"accepted-before-gate","errors":[]}))',
                         f"/fixture/{basename}"]
    )
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65,
                 "template": {"metadata": {"labels": {"saf.review": name}},
                              "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                       "containers": [container(
                                           "review", image=PYTHON, command=program,
                                           volumeMounts=[{"name": "review", "mountPath": "/fixture", "readOnly": True}])],
                                       "volumes": [{"name": "review", "configMap": {"name": CONFIG, "items": items}}]}}},
    })
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        state = json.loads(lab.kubectl("get", "job", name, "-o", "json", timeout=15).stdout)
        settled = [condition for condition in state.get("status", {}).get("conditions", [])
                   if condition["status"] == "True" and condition["type"] in {"Failed", "Complete"}]
        if settled:
            break
        time.sleep(1)
    else:
        lab.block(f"Review Job {name} did not reach a terminal condition")
    work = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json", timeout=15).stdout)
    pod, = work["items"]
    outcome = pod["status"]["containerStatuses"][0]["state"]["terminated"]
    logs = lab.kubectl("logs", f"job/{name}", timeout=15).stdout
    if not logs.strip():
        lab.block(f"Review Job {name} exited with {outcome['exitCode']} without a gate decision")
    signals = json.loads(logs)
    return {"job": name, "job_uid": state["metadata"]["uid"], "pod_uid": pod["metadata"]["uid"],
            "controller": settled[0]["type"], "exit_code": outcome["exitCode"], "review": signals}


def run(lab):
    files = {"review_gate.py": (HERE / "review_gate.py").read_text()}
    fixtures = HERE / "fixtures"
    names = ("incomplete", "stale", "reviewed-valid")
    files.update({f"{name}.json": (fixtures / f"{name}.json").read_text() for name in names})
    files.update({file.name: file.read_text() for file in (fixtures / "evidence").glob("*.md")})
    items = [{"key": name, "path": "evidence/" + name if name.endswith(".md") else name} for name in files]
    obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CONFIG}, "data": files}
    lab.create(obj)
    original = run_review(lab, items, "stride-baseline", "incomplete", False)
    incomplete = run_review(lab, items, "stride-incomplete", "incomplete", True)
    stale = run_review(lab, items, "stride-stale", "stale", True)
    valid = run_review(lab, items, "stride-current", "reviewed-valid", True)
    raw = {"as_of": AS_OF, "baseline": original, "incomplete": incomplete, "stale": stale, "valid": valid}
    (lab.evidence / "stride-gate-observations.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    lab.check("red", "The workflow without review enforcement accepts the same incomplete submission",
              (original["controller"], original["exit_code"], original["review"]["status"]) ==
              ("Complete", 0, "accepted-before-gate"), {"completed_without_gate": True})
    observed = incomplete["review"]["errors"]
    lab.check("green", "Native Job rejects the same submission for missing component coverage and evidence",
              incomplete["controller"] == "Failed" and incomplete["exit_code"] == 1
              and "coverage-missing:api-server:spoofing" in observed
              and "data-flow-link-invalid:api-server:evidence/missing-fixture.md" in observed,
              {"coverage_and_evidence_errors": observed})
    lab.check("green", "Native Job rejects an otherwise complete review after its due date",
              stale["controller"] == "Failed" and stale["exit_code"] == 1
              and stale["review"]["errors"] == ["review-stale-or-missing"], {"freshness_enforced": True})
    approval = json.loads(files["reviewed-valid.json"])
    lab.check("positive", "The independent complete review produces a successful native Job and clean decision",
              valid["controller"] == "Complete" and valid["exit_code"] == 0
              and valid["review"] == {"status": "pass", "errors": []},
              {"components": len(approval["components"]), "mapped_threats": len(approval["threats"]),
               "named_approval_roles": len(approval["review"]["approvals"])})
    run_architecture_flow(lab)


def graph_state(configmap):
    import hashlib

    graph_text = configmap.get("data", {}).get("graph.json", "")
    graph = json.loads(graph_text)
    return {"name": configmap["metadata"]["name"],
            "namespace": configmap["metadata"].get("namespace", ""),
            "uid": configmap["metadata"]["uid"],
            "resource_version": configmap["metadata"]["resourceVersion"],
            "revision": graph.get("revision", ""), "graph_text": graph_text,
            "sha256": hashlib.sha256(graph_text.encode()).hexdigest()}


def run_architecture_job(lab, name, record, graph_text):
    import hashlib

    config_name = f"{name}-input"
    evidence = HERE / "fixtures" / "evidence"
    payload = {"stride_architecture_gate.py": (HERE / "stride_architecture_gate.py").read_text(),
               "review_gate.py": (HERE / "review_gate.py").read_text(),
               "record.json": json.dumps(record, sort_keys=True), "graph.json": graph_text}
    payload.update({f"evidence/{p.name}": p.read_text() for p in sorted(evidence.glob("*.md"))})
    data = {key.replace("evidence/", "evidence_"): value for key, value in payload.items()}
    items = [{"key": key.replace("evidence/", "evidence_"), "path": key} for key in payload]
    config = lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": config_name},
                         "immutable": True, "data": data})
    input_uid = config.get("metadata", {}).get("uid")
    if not input_uid or config.get("immutable") is not True or config.get("data") != data:
        lab.block("The STRIDE review did not receive its exact immutable inputs")
    command = ["python", "/fixture/stride_architecture_gate.py", "/fixture/record.json",
               "/fixture/graph.json", "--evidence-root", "/fixture", "--today", AS_OF]
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65,
          "template": {"metadata": {"labels": {"saf.review": name}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [container("review", image=PYTHON, command=command,
              volumeMounts=[{"name": "fixture", "mountPath": "/fixture", "readOnly": True}])],
            "volumes": [{"name": "fixture", "configMap": {"name": config_name, "items": items}}]}}}})
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", name, "-o", "json", timeout=15).stdout)
        settled = [condition for condition in job.get("status", {}).get("conditions", [])
                   if condition.get("status") == "True" and condition.get("type") in {"Failed", "Complete"}]
        if settled:
            break
        time.sleep(1)
    else:
        lab.block(f"Architecture review Job {name} did not reach a terminal condition")
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json", timeout=15).stdout)
    pod, = pods["items"]
    owner = next((ref for ref in pod.get("metadata", {}).get("ownerReferences", [])
                  if ref.get("controller") is True and ref.get("kind") == "Job"), None)
    owner_matches = bool(owner and owner.get("name") == name and owner.get("uid") == job["metadata"]["uid"])
    if not owner_matches:
        lab.block(f"Selected Pod for {name} is not owned by the observed Job UID")
    terminated = pod["status"]["containerStatuses"][0]["state"]["terminated"]
    logs = lab.kubectl("logs", f"job/{name}", timeout=15).stdout
    if not logs.strip():
        lab.block(f"Architecture review Job {name} returned no decision")
    return {"job": name, "job_uid": job["metadata"]["uid"], "pod_uid": pod["metadata"]["uid"],
            "pod_owner_uid_matches_job": owner_matches, "controller": settled[0]["type"],
            "exit_code": terminated["exitCode"], "review": json.loads(logs),
            "input_configmap_uid": input_uid, "input_record": record,
            "input_sha256": hashlib.sha256(config["data"]["record.json"].encode()).hexdigest(),
            "input_graph_sha256": hashlib.sha256(config["data"]["graph.json"].encode()).hexdigest()}


def run_architecture_flow(lab):
    import copy
    import hashlib

    graph_text = (HERE / "fixtures" / "architecture-r1.json").read_text().strip()
    graph = json.loads(graph_text)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        "name": "stride-architecture", "labels": {"saf.example/fixture": "stride-architecture-flow"},
        "annotations": {"saf.example/revision": graph["revision"]}}, "data": {"graph.json": graph_text}})
    first_cm = json.loads(lab.kubectl("get", "configmap", "stride-architecture", "-o", "json", timeout=15).stdout)
    before = graph_state(first_cm)
    original = json.loads((HERE / "fixtures" / "architecture-reviewed-valid.json").read_text())
    prior = run_architecture_job(lab, "stride-flow-before-change", original, before["graph_text"])

    lab.kubectl("patch", "configmap", "stride-architecture", "--type=merge", "-p",
                json.dumps({"metadata": {"annotations": {"saf.example/observation": "metadata-only"}}}, sort_keys=True), timeout=15)
    metadata_cm = json.loads(lab.kubectl("get", "configmap", "stride-architecture", "-o", "json", timeout=15).stdout)
    metadata_only = graph_state(metadata_cm)
    metadata_result = run_architecture_job(lab, "stride-flow-metadata-only", original, metadata_only["graph_text"])

    updated_graph = copy.deepcopy(graph)
    updated_graph["revision"] = "synthetic-architecture-r2"
    flow = next(item for item in updated_graph["flows"] if item["component"] == "model-serving-endpoint")
    flow["destination"] = "synthetic revised inference-service destination"
    updated_text = json.dumps(updated_graph, sort_keys=True, separators=(",", ":"))
    lab.kubectl("patch", "configmap", "stride-architecture", "--type=merge", "-p",
                json.dumps({"metadata": {"annotations": {"saf.example/revision": updated_graph["revision"]}},
                            "data": {"graph.json": updated_text}}, sort_keys=True), timeout=15)
    changed_cm = json.loads(lab.kubectl("get", "configmap", "stride-architecture", "-o", "json", timeout=15).stdout)
    changed = graph_state(changed_cm)
    stale = run_architecture_job(lab, "stride-flow-stale-review", original, changed["graph_text"])
    refreshed_record = copy.deepcopy(original)
    refreshed_record["reviewed_architecture"] = {"revision": changed["revision"], "sha256": changed["sha256"]}
    refreshed = run_architecture_job(lab, "stride-flow-refreshed-review", refreshed_record, changed["graph_text"])

    dangling_record = copy.deepcopy(original)
    dangling_record["threats"][0]["flow_ref"] = "flow-not-in-reviewed-graph"
    dangling = run_architecture_job(lab, "stride-flow-dangling-reference", dangling_record, before["graph_text"])
    misbound_record = copy.deepcopy(original)
    other = next(item for item in graph["flows"] if item["component"] != misbound_record["threats"][0]["component"])
    misbound_record["threats"][0]["flow_ref"] = other["id"]
    misbound_record["threats"][0]["boundary_ref"] = other["boundary_id"]
    misbound = run_architecture_job(lab, "stride-flow-cross-component-reference", misbound_record, before["graph_text"])

    snapshots = {"before": before, "metadata_only": metadata_only, "after_change": changed}
    stage_digests = [(prior, before), (metadata_result, metadata_only), (stale, changed),
                     (refreshed, changed), (dangling, before), (misbound, before)]
    if any(result["review"]["architecture_digest"] != state["sha256"]
           or result["input_graph_sha256"] != state["sha256"] for result, state in stage_digests):
        lab.block("A native STRIDE decision did not match its API-observed graph bytes")
    digest_recomputed = {name: hashlib.sha256(state["graph_text"].encode()).hexdigest() == state["sha256"]
                         for name, state in snapshots.items()}
    raw = {"graph_snapshots": snapshots, "digest_recomputed": digest_recomputed,
           "metadata_only_resource_version_advanced": before["resource_version"] != metadata_only["resource_version"],
           "metadata_only_uid_stable": before["uid"] == metadata_only["uid"],
           "metadata_only_graph_bytes_equal": before["graph_text"] == metadata_only["graph_text"],
           "architecture_revision_and_digest_changed": changed["revision"] != before["revision"] and changed["sha256"] != before["sha256"],
           "prior_review": prior, "metadata_only_review": metadata_result, "stale_review": stale,
           "refreshed_review": refreshed, "dangling_flow_review": dangling, "misbound_flow_review": misbound}
    (lab.evidence / "stride-architecture-flow-observations.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "Reviewed synthetic STRIDE threats resolve to exact component, data flow and trust boundary",
        prior["controller"] == "Complete" and prior["exit_code"] == 0 and
        prior["review"]["status"] == "pass" and len(graph["flows"]) == 9 and
        prior["pod_owner_uid_matches_job"], {"components": 9, "threats": 54, "flow_links_resolved": True})
    lab.check("positive", "Metadata-only ConfigMap update keeps the reviewed graph binding valid",
        before["uid"] == metadata_only["uid"] and before["resource_version"] != metadata_only["resource_version"] and
        before["graph_text"] == metadata_only["graph_text"] and all(digest_recomputed.values()) and
        metadata_result["controller"] == "Complete" and metadata_result["exit_code"] == 0 and
        metadata_result["review"]["status"] == "pass", {"resource_version_advanced": True, "graph_digest_unchanged": True})
    lab.check("red", "Significant DFD revision invalidates the prior STRIDE review",
        changed["uid"] == before["uid"] and changed["resource_version"] != metadata_only["resource_version"] and
        changed["revision"] != before["revision"] and changed["sha256"] != before["sha256"] and
        stale["controller"] == "Failed" and stale["exit_code"] == 1 and
        stale["review"]["errors"] == ["architecture-review-stale"],
        {"revision_changed": True, "errors": stale["review"]["errors"]})
    lab.check("positive", "Refreshed STRIDE review binds to the changed graph revision and digest",
        refreshed["controller"] == "Complete" and refreshed["exit_code"] == 0 and
        refreshed["review"]["status"] == "pass" and refreshed["pod_owner_uid_matches_job"],
        {"status": refreshed["review"]["status"], "review_bound_to_current_graph": True})
    lab.check("red", "Threat record with a dangling flow reference is rejected",
        dangling["controller"] == "Failed" and dangling["exit_code"] == 1 and
        dangling["review"]["errors"] == ["threat-flow-reference-invalid:api-server:spoofing"],
        {"errors": dangling["review"]["errors"]})
    lab.check("red", "Threat cannot cite another component's flow and boundary as its own",
        misbound["controller"] == "Failed" and misbound["exit_code"] == 1 and
        misbound["review"]["errors"] == ["threat-flow-reference-invalid:api-server:spoofing"],
        {"errors": misbound["review"]["errors"]})
