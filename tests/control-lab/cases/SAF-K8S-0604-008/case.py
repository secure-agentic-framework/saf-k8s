"""Classify fictional component findings with observed workload and service context."""
from copy import deepcopy
import json

from fixtures import BUSYBOX_IMAGE, container

TRAIN = "saf-training-marker"
SERVE = "saf-inference-marker"
CASE_NS = "saf-test"
PURPOSE = "saf.example/purpose"
SCOPE = (
    "A live Job, Deployment, Pods, Node and EndpointSlice are correlated with a reviewed "
    "fixture purpose record and fictional node and container inventories. A private in-cluster "
    "request reaches the actual inference fixture. GPU/driver presence and public "
    "reachability require separate evidence."
)


def metadata(name, purpose=None):
    fields = {"name": name}
    if purpose:
        fields["labels"] = {"app": name, PURPOSE: purpose}
    return fields


PROFILE = {(kind, name): purpose for kind, name, purpose in (
    ("Job", TRAIN, "training"), ("Deployment", SERVE, "inference")
)}


def load(lab, *resource):
    return json.loads(lab.kubectl("get", *resource, "-o", "json").stdout)


def launch(lab):
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": metadata(TRAIN, "training"),
        "spec": {"backoffLimit": 0, "template": {"metadata": {"labels": {"app": TRAIN}}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [container("task", command=["sh", "-c", "echo synthetic-training-complete"])],
        }}},
    })
    sel = {"app": SERVE}
    server = ("mkdir -p /tmp/www && printf 'saf-inference-marker\\n' > /tmp/www/health && "
              "httpd -f -p 8080 -h /tmp/www")
    lab.create({
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": metadata(SERVE, "inference"),
        "spec": {"replicas": 1, "selector": {"matchLabels": sel}, "template": {
            "metadata": {"labels": sel}, "spec": {"automountServiceAccountToken": False, "containers": [
                container("marker", command=["sh", "-c", server], readinessProbe={"httpGet": {
                    "path": "/health", "port": 8080
                }, "periodSeconds": 1, "failureThreshold": 10}),
            ]},
        }},
    })
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": metadata(SERVE), "spec": {
        "type": "ClusterIP", "selector": sel, "ports": [{"port": 8080, "targetPort": 8080}],
    }})
    lab.kubectl("wait", "--for=condition=complete", f"job/{TRAIN}", "--timeout=60s", timeout=70)
    lab.kubectl("wait", "--for=condition=Available", f"deployment/{SERVE}", "--timeout=65s", timeout=75)


def owner_is(obj, parent):
    return any(link.get("controller") and link.get("uid") == parent["metadata"]["uid"]
               for link in obj["metadata"].get("ownerReferences", []))


def context(lab, workload, pod, owned):
    node = load(lab, "node", pod["spec"]["nodeName"])
    name, kind = workload["metadata"]["name"], workload["kind"]
    policy = PROFILE.get((kind, name))
    label = workload["metadata"].get("labels", {}).get(PURPOSE)
    statuses = pod.get("status", {}).get("containerStatuses", [])
    digest_ref = statuses[0].get("imageID") if statuses else None
    image = pod["spec"]["containers"][0]["image"]
    # A valid approved fixture entry corroborates purpose and expected declared image.
    phase = policy if owned and policy == label and image == BUSYBOX_IMAGE else "unknown"
    return {"workload_name": name, "workload_kind": kind, "workload_uid": workload["metadata"]["uid"],
            "node_uid": node["metadata"]["uid"], "node_kubelet": node["status"]["nodeInfo"]["kubeletVersion"],
            "pod_uid": pod["metadata"]["uid"], "container_image": image, "observed_image_id": digest_ref,
            "phase": phase, "owner_observed": owned}


def classify(workload, finding, records):
    matches = [row for row in records if row["component"] == finding["component"]]
    if workload is None or not matches:
        return "unknown"
    if len(matches) != 1:
        return "conflict"
    row, = matches
    locus = row.get("locus")
    subject = {"node": workload["node_uid"], "container": workload["observed_image_id"]}.get(locus)
    if subject is None or not row.get("subject"):
        return "unknown"
    if row["subject"] != subject:
        return "conflict"
    return {"node": "node-driver", "container": "container-library"}[locus]


def private_request(lab):
    script = (f"i=0; while [ $i -lt 12 ]; do "
              f"wget -qO- -T 2 http://{SERVE}.{CASE_NS}.svc.cluster.local:8080/health && exit 0; "
              "i=$((i+1)); sleep 1; done; exit 1")
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": metadata("saf-private-client"),
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                         "containers": [container("client", command=["sh", "-c", script])]}})
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded",
                "pod/saf-private-client", "--timeout=35s", timeout=45)
    return lab.kubectl("logs", "saf-private-client").stdout.strip()


def run(lab):
    driver = {"advisory": "SYNTH-NODE-DRIVER", "component": "pkg:generic/saf-test-driver@1.0"}
    library = {"advisory": "SYNTH-IMAGE-LIBRARY", "component": "pkg:generic/saf-test-library@1.0"}
    baseline = [classify(None, row, []) for row in (driver, library)]
    lab.check("red", "Findings alone leave component locus and workload exposure unclassified",
              baseline == ["unknown", "unknown"], {"before_context": baseline})
    launch(lab)
    job, dep = load(lab, "job", TRAIN), load(lab, "deployment", SERVE)
    training_pod, = load(lab, "pods", "-l", f"app={TRAIN}")["items"]
    inference_pod, = load(lab, "pods", "-l", f"app={SERVE}")["items"]
    replica_set, = load(lab, "rs", "-l", f"app={SERVE}")["items"]
    training = context(lab, job, training_pod, owner_is(training_pod, job))
    inference = context(lab, dep, inference_pod, owner_is(inference_pod, replica_set) and owner_is(replica_set, dep))
    unknown_workload = deepcopy(dep)
    del unknown_workload["metadata"]["labels"][PURPOSE]
    without_hint = context(lab, unknown_workload, inference_pod, True)["phase"]
    phases = [training["phase"], inference["phase"], without_hint]
    topology_valid = all(row["owner_observed"] and row["observed_image_id"] for row in (training, inference))
    lab.check("green", "Observed owner chains and reviewed fixture metadata distinguish the two workload contexts",
              phases == ["training", "inference", "unknown"] and topology_valid,
              {"phases": phases, "owner_and_runtime_observed": topology_valid})

    node_fact = {"component": driver["component"], "locus": "node", "subject": training["node_uid"]}
    image_fact = {"component": library["component"], "locus": "container", "subject": inference["observed_image_id"]}
    wrong_node = {**node_fact, "subject": "unmatched-fixture-node"}
    wrong_image = {**image_fact, "subject": "unmatched-fixture-manifest"}
    decisions = {"correlated_node_record": classify(training, driver, [node_fact]),
                 "correlated_container_record": classify(inference, library, [image_fact]),
                 "missing_record": classify(inference, library, []),
                 "disagreeing_sources": classify(training, driver, [node_fact, wrong_node]),
                 "wrong_image_record": classify(inference, library, [wrong_image])}
    wanted = {"correlated_node_record": "node-driver", "correlated_container_record": "container-library",
              "missing_record": "unknown", "disagreeing_sources": "conflict", "wrong_image_record": "conflict"}
    lab.check("green", "Exact node and runtime image identities govern fictional component classification",
              decisions == wanted, decisions)

    body = private_request(lab)
    service = load(lab, "service", SERVE)
    slices = load(lab, "endpointslice", "-l", f"kubernetes.io/service-name={SERVE}")["items"]
    ready_endpoint = any(endpoint.get("conditions", {}).get("ready")
                         and endpoint.get("targetRef", {}).get("uid") == inference["pod_uid"]
                         for row in slices for endpoint in row["endpoints"])
    lab.check("positive", "The exact inference fixture answers privately and public reachability remains unknown",
              body == SERVE and ready_endpoint and service["spec"]["type"] == "ClusterIP",
              {"private_marker": body == SERVE, "correct_ready_backend": ready_endpoint,
               "public_reachability": "unknown"})
    (lab.evidence / "exposure-context.json").write_text(json.dumps({
        "training": training, "inference": inference, "classification": decisions,
        "service_type": service["spec"]["type"], "private_marker": body,
        "fictional_inventory": [node_fact, image_fact], "public_reachability": "unknown",
    }, indent=2, sort_keys=True) + "\n")
