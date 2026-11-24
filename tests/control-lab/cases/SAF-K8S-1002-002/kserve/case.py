"""Verify the Kubernetes Job to KServe predictor trace carrier in disposable Kind."""
from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import re
from time import monotonic, sleep

import yaml

HERE = Path(__file__).resolve().parent
VERSION = "v0.21.0"
ASSET_SHA = "d155b626a8d42f353bd637f9e5ae306a954ea6a9ddea70dbe36a16269250c6ca"
RELEASE = f"https://github.com/kserve/kserve/releases/download/{VERSION}/kserve.yaml"
CONTROLLER = f"docker.io/kserve/kserve-controller:{VERSION}@sha256:74c5de4f166f04a12e5926af37751554e8f4be900bdf3368d0a348abf5f7b0a6"
PROXY = "quay.io/brancz/kube-rbac-proxy:v0.18.0@sha256:754ab2a723c8fc7ea8e09ae1224f8af5be91849b8b2f2a3735c6237f1c534187"
ANNOTATION = "saf.example/traceparent"
CONTROLLER_NAME = "kserve-controller-manager"
WEBHOOK = "kserve-webhook-server-service"
COLLECTOR = "otel"
JOB = "saf-kserve-dispatch"
TRACEPARENT = re.compile(r"00-[0-9a-f]{32}-[0-9a-f]{16}-01")


def tls(lab):
    path = lab.kubeconfig.parent / "kserve-tls"
    path.mkdir(mode=0o700)
    ca, ca_key = path / "ca.crt", path / "ca.key"
    crt, key, csr = path / "tls.crt", path / "tls.key", path / "webhook.csr"
    dns = f"{WEBHOOK}.kserve.svc"
    ext = path / "extensions.txt"
    ext.write_text(f"subjectAltName=DNS:{dns},DNS:{dns}.cluster.local\n"
                   "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n")
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=SAF KServe fixture CA", "-keyout", str(ca_key), "-out", str(ca),
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    lab.command("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={dns}",
                "-keyout", str(key), "-out", str(csr))
    lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                "-CAcreateserial", "-extfile", str(ext), "-days", "2", "-out", str(crt))
    lab.kubectl("-n", "kserve", "create", "secret", "tls", "kserve-webhook-server-cert",
                f"--cert={crt}", f"--key={key}")
    return b64encode(ca.read_bytes()).decode("ascii")


def render_install(raw, ca):
    crds, objects = [], []
    for doc in yaml.load_all(raw, Loader=yaml.CSafeLoader):
        if not doc:
            continue
        kind, meta = doc["kind"], doc["metadata"]
        name = meta["name"]
        if kind == "CustomResourceDefinition":
            if doc["spec"].get("conversion", {}).get("strategy") != "Webhook":
                crds.append(doc)
            continue
        if kind in {"Certificate", "Issuer", "Secret", "DaemonSet", "ClusterStorageContainer"}:
            continue
        if kind == "Deployment":
            if name != CONTROLLER_NAME:
                continue
            containers = doc["spec"]["template"]["spec"]["containers"]
            images = {c["name"]: c["image"] for c in containers}
            if images != {"manager": f"kserve/kserve-controller:{VERSION}",
                          "kube-rbac-proxy": "quay.io/brancz/kube-rbac-proxy:v0.18.0"}:
                raise ValueError("KServe release controller image declarations differ from the reviewed release")
            pins = {"manager": CONTROLLER, "kube-rbac-proxy": PROXY}
            for c in containers:
                c["image"] = pins[c["name"]]
                c["imagePullPolicy"] = "IfNotPresent"
                if c["name"] == "manager":
                    c["readinessProbe"]["initialDelaySeconds"] = 3
        if kind.endswith("WebhookConfiguration"):
            names = {webhook["clientConfig"]["service"]["name"] for webhook in doc["webhooks"]}
            if names != {WEBHOOK}:
                continue
            for webhook in doc["webhooks"]:
                webhook["clientConfig"]["caBundle"] = ca
            if "annotations" in meta:
                meta["annotations"].pop("cert-manager.io/inject-ca-from", None)
        if kind == "ConfigMap" and name == "inferenceservice-config":
            doc["data"]["deploy"] = json.dumps({"defaultDeploymentMode": "Standard"})
            settings = json.loads(doc["data"]["ingress"])
            settings.update(enableGatewayApi=False, disableIngressCreation=True)
            doc["data"]["ingress"] = json.dumps(settings)
        objects.append(doc)
    return crds, objects


def get_json(lab, *arguments):
    return json.loads(lab.kubectl(*arguments, "-o", "json").stdout)



def wait_for_condition(lab, resource, condition, timeout):
    deadline = monotonic() + timeout
    while True:
        resource_state = get_json(lab, "get", resource)
        status = resource_state.get("status") or {}
        # The API can return null before the controller writes its first status.
        conditions = status.get("conditions") or []
        if any(item.get("type") == condition and item.get("status") == "True" for item in conditions):
            return resource_state, True
        remaining = deadline - monotonic()
        if remaining <= 0:
            return resource_state, False
        sleep(min(2, remaining))

def install(lab):
    raw = lab.kubeconfig.with_name("kserve-v0.21.0.yaml")
    lab.command("curl", "-fsSL", "--max-time", "60", RELEASE, "-o", str(raw), timeout=70)
    if sha256(raw.read_bytes()).hexdigest() != ASSET_SHA:
        lab.block("Published KServe manifest differs from the reviewed release asset")
    lab.kubectl("create", "namespace", "kserve")
    ca = tls(lab)
    crds, objects = render_install(raw.read_text(), ca)
    for label, docs in (("crds", crds), ("controller", objects)):
        manifest = raw.with_name(f"kserve-fixture-{label}.yaml")
        manifest.write_text(yaml.dump_all(docs, Dumper=yaml.CSafeDumper, sort_keys=False))
        lab.kubectl("-n", "kserve", "apply", "--server-side", "-f", str(manifest), timeout=160)
        if label == "crds":
            resource = "crd/inferenceservices.serving.kserve.io"
            state, established = wait_for_condition(lab, resource, "Established", 75)
            if not established:
                lab.block(f"KServe CRD {resource} was not established: {state.get('status')}")
    ready = lab.kubectl("-n", "kserve", "rollout", "status", f"deployment/{CONTROLLER_NAME}",
                        "--timeout=150s", timeout=160, allow_failure=True)
    if ready.returncode:
        logs = lab.kubectl("-n", "kserve", "logs", f"deployment/{CONTROLLER_NAME}", "-c", "manager",
                           "--tail=85", allow_failure=True)
        lab.block(f"KServe controller did not become available: {logs.stdout[-1400:]}")
    pods = get_json(lab, "-n", "kserve", "get", "pods", "-l", f"control-plane={CONTROLLER_NAME}")["items"]
    managers = [c for pod in pods for c in pod["status"].get("containerStatuses", [])
                if c["name"] == "manager" and c["ready"]]
    expected = CONTROLLER.split("@")[-1]
    observed = len(managers) == 1 and managers[0].get("imageID", "").endswith(expected)
    lab.check("positive", "The Kubernetes cluster runs the pinned KServe controller from the verified release asset",
              observed, {"release": VERSION, "manifest_sha256": ASSET_SHA,
                         "approved_controller_image_active": observed})
    return {"release": VERSION, "manifest_sha256": ASSET_SHA,
            "controller_image": CONTROLLER, "runtime_image_id": managers[0]["imageID"]}


def app_container(name, file, image, sdk, security, *, port=None):
    env = [{"name": "TRACEPARENT", "valueFrom": {"fieldRef": {"fieldPath": f"metadata.annotations['{ANNOTATION}']"}}}]
    cfg = {"name": name, "image": image, "command": ["sh", "-c",
           "pip install --disable-pip-version-check --no-cache-dir --only-binary=:all: "
           f"--target /tmp/saf-kserve-otel {sdk} && PYTHONPATH=/tmp/saf-kserve-otel exec python /code/{file}"],
           "env": env, "resources": {"requests": {"cpu": "25m", "memory": "96Mi"},
                                     "limits": {"cpu": "500m", "memory": "320Mi"}},
           "securityContext": security(), "volumeMounts": [{"name": "code", "mountPath": "/code", "readOnly": True}]}
    if port is not None:
        cfg["ports"] = [{"name": "http1", "containerPort": port}]
        cfg["readinessProbe"] = {"httpGet": {"path": "/health", "port": port}, "periodSeconds": 2}
    return cfg


def dispatch(lab, source, image, sdk, security, volume):
    supplied = source["traceparent"]
    template = {"metadata": {"annotations": {ANNOTATION: supplied}, "labels": {"saf.synthetic": "true"}},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                         "containers": [app_container("dispatch", "dispatch.py", image, sdk, security)],
                         "volumes": [volume]}}
    job = lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": JOB},
                      "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 125, "template": template}})
    lab.kubectl("wait", "--for=condition=Complete", f"job/{JOB}", "--timeout=130s", timeout=140)
    logs = lab.kubectl("logs", f"job/{JOB}").stdout
    value, = [json.loads(line)["traceparent"] for line in logs.splitlines() if line.startswith("{")]
    pod, = get_json(lab, "get", "pods", "-l", f"job-name={JOB}")["items"]
    intact = pod["metadata"].get("annotations", {}).get(ANNOTATION) == supplied
    owner = any(x["uid"] == job["metadata"]["uid"] and x["kind"] == "Job" and x.get("controller")
                for x in pod["metadata"]["ownerReferences"])
    lab.check("positive", "The running native Job received the configured upstream annotation and returned its W3C carrier",
              intact and owner and bool(TRACEPARENT.fullmatch(value)),
              {"native_job_owned_pod": owner, "supplied_carrier_projected": intact, "sampled_carrier": bool(TRACEPARENT.fullmatch(value))})
    return value, {"job": JOB, "observed_annotation": supplied, "output_carrier": value}


def create_predictor(lab, name, carrier, image, sdk, security, volume):
    container = app_container("kserve-container", "predictor.py", image, sdk, security, port=8080)
    container["env"].append({"name": "SERVICE_NAME", "value": name})
    predictor = {"automountServiceAccountToken": False, "minReplicas": 1, "maxReplicas": 1,
                 "scaleTarget": 50, "containers": [container], "volumes": [volume]}
    if carrier:
        predictor["annotations"] = {ANNOTATION: carrier}
    return lab.create({"apiVersion": "serving.kserve.io/v1beta1", "kind": "InferenceService",
                       "metadata": {"name": name, "labels": {"networking.kserve.io/visibility": "cluster-local"}},
                       "spec": {"predictor": predictor}})


def read_predictor(lab, isvc, expected):
    name = isvc["metadata"]["name"]
    state, ready = wait_for_condition(lab, f"inferenceservice/{name}", "Ready", 150)
    if not ready:
        lab.kubectl("-n", "kserve", "logs", f"deployment/{CONTROLLER_NAME}", "-c", "manager", "--tail=80",
                    allow_failure=True)
        lab.kubectl("get", "pods", "-o", "wide", allow_failure=True)
        lab.block(f"KServe did not reconcile {name}: {state.get('status', {})}")
    pods = get_json(lab, "get", "pods", "-l", f"serving.kserve.io/inferenceservice={name}")["items"]
    pod, = [pod for pod in pods if any(c.get("type") == "Ready" and c.get("status") == "True"
                                      for c in pod["status"].get("conditions", []))]
    rs_owner, = [o for o in pod["metadata"]["ownerReferences"] if o["kind"] == "ReplicaSet" and o.get("controller")]
    rs = get_json(lab, "get", "replicaset", rs_owner["name"])
    dep_owner, = [o for o in rs["metadata"]["ownerReferences"] if o["kind"] == "Deployment" and o.get("controller")]
    deployment = get_json(lab, "get", "deployment", dep_owner["name"])
    svc = get_json(lab, "get", "service", deployment["metadata"]["name"])
    owner = any(o["uid"] == isvc["metadata"]["uid"] and o["kind"] == "InferenceService" and o.get("controller")
                for o in deployment["metadata"]["ownerReferences"])
    selector = svc["spec"]["selector"]
    actual = pod["metadata"].get("annotations", {}).get(ANNOTATION, "")
    env = lab.kubectl("exec", pod["metadata"]["name"], "-c", "kserve-container", "--",
                      "python", "-c", "import os; print(os.environ.get('TRACEPARENT',''))").stdout.strip()
    mode = state["status"].get("deploymentMode")
    linked = actual == env == expected
    service_selects = bool(selector) and all(pod["metadata"]["labels"].get(k) == v for k,v in selector.items())
    lab.check("positive", f"KServe owns the {name} predictor and its actual Pod exposes the expected Downward API value",
              owner and mode == "Standard" and linked and service_selects,
              {"kserve_owns_predictor": owner, "mode": mode, "carrier_matches": linked, "internal_service": service_selects})
    http_port, = [x["port"] for x in svc["spec"]["ports"] if x.get("name") in {"http1", "http"}]
    return f"http://{svc['metadata']['name']}:{http_port}/emit", {
        "name": name, "controller_owner_chain": owner, "deployment": deployment["metadata"]["name"],
        "pod": pod["metadata"]["name"], "actual_annotation": actual, "actual_downward_api": env}


def request(lab, url):
    script = ("import sys, urllib.request; "
              "print(urllib.request.urlopen(sys.argv[1],timeout=12).read().decode())")
    response = lab.kubectl("exec", "deployment/inference", "--", "python", "-c", script, url, timeout=25)
    return json.loads(response.stdout)


def run(lab, source, image, sdk, security, collect, chain):
    installation = install(lab)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "kserve-trace-app"},
                "data": {file: (HERE / file).read_text() for file in ("dispatch.py", "predictor.py")}})
    volume = {"name": "code", "configMap": {"name": "kserve-trace-app"}}
    carrier, job = dispatch(lab, source, image, sdk, security, volume)
    no_context = create_predictor(lab, "saf-kserve-no-context", "", image, sdk, security, volume)
    positive = create_predictor(lab, "saf-kserve-linked", carrier, image, sdk, security, volume)
    missing_url, missing_meta = read_predictor(lab, no_context, "")
    positive_url, positive_meta = read_predictor(lab, positive, carrier)
    missing, linked = request(lab, missing_url), request(lab, positive_url)
    positive_id, parent_id = carrier.split("-")[1:3]
    predictor = "kserve.predictor.inference"
    stages = ["ingestion", "orchestration.dispatch", predictor]
    expected = {(positive_id, stage) for stage in stages} | {(missing["trace_id"], predictor)}
    raw, spans = collect(lab, expected)
    exact = {(s["trace_id"], s["span_id"]):s for s in spans}
    root = exact.get((missing["trace_id"], missing["span_id"]), {})
    child = exact.get((linked["trace_id"], linked["span_id"]), {})
    separated = missing["trace_id"] != positive_id and missing["parent_span_id"] == "0"*16 and root.get("parent_id") == ""
    lab.check("red", "An otherwise-equivalent KServe predictor with no carrier produces an independent sampled root",
              separated and missing["served"] is True,
              {"root_is_separate": separated, "predictor_served": missing["served"]})
    rooted = chain(spans, positive_id, stages) and linked["trace_id"] == positive_id and child.get("parent_id") == parent_id
    lab.check("green", "The Collector proves exact ingestion, native Job and KServe predictor parentage through real annotations",
              rooted and linked["served"] is True and linked["parent_span_id"] == parent_id,
              {"stages": stages, "chain_matched": rooted})
    (lab.evidence / "kserve-carrier-receipts.json").write_text(json.dumps(
        {"release": installation, "dispatch": job, "linked": {"pod":positive_meta,"receipt":linked},
         "missing": {"pod":missing_meta,"receipt":missing}, "collector_spans": spans}, indent=2) + "\n")
    (lab.evidence / "kserve-collector-debug.txt").write_text(raw)
