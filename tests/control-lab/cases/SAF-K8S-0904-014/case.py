"""Stage-scoped artifact access and lifecycle configuration on SeaweedFS 4.53."""
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
NAMESPACE = "saf-test"
STORE = "artifact-store"
CLIENT = "artifact-client"
STORE_IMAGE = "docker.io/chrislusf/seaweedfs:4.53@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0"
CLIENT_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
BUCKETS = {"a": "saf0904014-stage-a", "b": "saf0904014-stage-b"}
CONFIGMAP = "artifact-store-fixtures"

SCOPE = (
    "One fresh Kind v1.36.1 cluster runs the digest-pinned SeaweedFS 4.53 mini S3 backend "
    "with emptyDir data and a standard-library SigV4 client. Two static stage identities "
    "first have broad Read/Write access to both stage buckets, then the mounted static IAM "
    "config changes only their action scopes and the same SeaweedFS container process restarts "
    "inside the same Pod. The case checks unchanged credentials, Pod UID, Service ClusterIP, "
    "image and S3 marker hashes, then verifies cross-bucket denies, own-stage reads/writes, and "
    "stage-specific lifecycle config readback. It does not await timed expiration or establish "
    "workflow identity federation, production storage, encryption, or backing-byte reclamation."
)


def read_fixture(name):
    return (FIXTURES / name).read_text()


def pod_security(user, group, *, read_only=False):
    result = {"allowPrivilegeEscalation": False,
              "capabilities": {"drop": ["ALL"]},
              "runAsNonRoot": True,
              "runAsUser": user,
              "runAsGroup": group,
              "seccompProfile": {"type": "RuntimeDefault"}}
    if read_only:
        result["readOnlyRootFilesystem"] = True
    return result


def config_map_object(config_text):
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIGMAP, "namespace": NAMESPACE},
        "data": {
            "s3-config.json": config_text,
            "stage-a-marker.txt": read_fixture("stage-a-marker.txt"),
            "stage-b-marker.txt": read_fixture("stage-b-marker.txt"),
            "stage-a-lifecycle.xml": read_fixture("stage-a-lifecycle.xml"),
            "stage-b-lifecycle.xml": read_fixture("stage-b-lifecycle.xml"),
            "s3_probe.py": read_fixture("s3_probe.py"),
        },
    }


def deploy(lab):
    broad_config = read_fixture("s3-config-broad.json")
    lab.create(config_map_object(broad_config))
    lab.create({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": STORE, "labels": {"app": STORE}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Always",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                "runAsGroup": 1000, "fsGroup": 1000},
            "containers": [{
                "name": "seaweedfs", "image": STORE_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["weed", "mini", "-s3.config=/fixture/s3-config.json", "-dir=/data",
                            "-webdav=false", "-admin.ui=false", "-master.telemetry=false"],
                "securityContext": pod_security(1000, 1000),
                "ports": [{"name": "s3", "containerPort": 8333}],
                "resources": {"requests": {"cpu": "250m", "memory": "512Mi"},
                              "limits": {"cpu": "1500m", "memory": "1536Mi"}},
                "readinessProbe": {"tcpSocket": {"port": 8333}, "periodSeconds": 2,
                                   "timeoutSeconds": 1, "failureThreshold": 45},
                "volumeMounts": [
                    {"name": "fixtures", "mountPath": "/fixture", "readOnly": True},
                    {"name": "data", "mountPath": "/data"},
                ],
            }],
            "volumes": [
                {"name": "fixtures", "configMap": {"name": CONFIGMAP}},
                {"name": "data", "emptyDir": {"sizeLimit": "512Mi"}},
            ],
        },
    })
    lab.create({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": STORE},
        "spec": {"selector": {"app": STORE},
                 "ports": [{"name": "s3", "port": 8333, "targetPort": 8333}]},
    })
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{STORE}", "--timeout=150s", timeout=160)
    lab.create({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": CLIENT, "labels": {"app": CLIENT}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Always",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534},
            "containers": [{
                "name": "client", "image": CLIENT_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", "import time; time.sleep(3600)"],
                "securityContext": pod_security(65534, 65534, read_only=True),
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "200m", "memory": "128Mi"}},
                "volumeMounts": [{"name": "fixtures", "mountPath": "/fixture", "readOnly": True}],
            }],
            "volumes": [{"name": "fixtures", "configMap": {"name": CONFIGMAP}}],
        },
    })
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{CLIENT}", "--timeout=80s", timeout=90)
    assert_owned_s3_endpoint(lab)
    store = pod_json(lab, STORE)
    if store.get("spec", {}).get("containers", [{}])[0].get("image") != STORE_IMAGE:
        lab.block("SeaweedFS Pod image does not match the exact approved digest")
    if not any(v.get("name") == "data" and "emptyDir" in v for v in store["spec"].get("volumes", [])):
        lab.block("SeaweedFS fixture must use the case-owned emptyDir backing")


def pod_json(lab, name):
    return json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)


def assert_owned_s3_endpoint(lab):
    svc = json.loads(lab.kubectl("get", "service", STORE, "-o", "json").stdout)
    endpoints = json.loads(lab.kubectl(
        "get", "endpointslice", "-l", f"kubernetes.io/service-name={STORE}", "-o", "json").stdout)["items"]
    ready = [ep for row in endpoints for ep in (row.get("endpoints") or [])
             if ep.get("conditions", {}).get("ready") is True]
    if (not svc.get("spec", {}).get("clusterIP") or len(ready) != 1
            or ready[0].get("targetRef", {}).get("name") != STORE):
        lab.block("S3 Service does not resolve to exactly the Ready case-owned SeaweedFS Pod")


def probe(lab, operation):
    timeout = 100 if operation == "scoped" else 40
    result = lab.kubectl("exec", f"pod/{CLIENT}", "--", "python", "-B",
                         "/fixture/s3_probe.py", operation, timeout=timeout, allow_failure=True)
    if result.returncode:
        lab.block(f"S3 fixture probe {operation} failed to execute: {result.stderr.strip()}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"S3 fixture emitted no structured result for {operation}: {error}")
    if value.get("operation") != operation:
        lab.block(f"S3 fixture returned an unexpected operation result: {value}")
    return value


def credential_map(config):
    return {row["name"]: tuple((c["accessKey"], c["secretKey"]) for c in row.get("credentials", []))
            for row in config["identities"]}


def config_without_actions(config):
    return [{k: v for k, v in row.items() if k != "actions"} for row in config["identities"]]


def await_projected_config(lab, expected_sha, timeout=60):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        observed = probe(lab, "config-hash").get("sha256")
        store_mount = lab.kubectl("exec", f"pod/{STORE}", "--", "cat",
                                  "/fixture/s3-config.json")
        backend_sha = hashlib.sha256(store_mount.stdout.encode()).hexdigest()
        if observed == expected_sha == backend_sha:
            return observed
        last = f"client={observed}; backend={backend_sha}"
        time.sleep(0.5)
    lab.block(f"Scoped config did not propagate to the fixture volume; observed sha256={last}")


def await_same_pod_restart(lab, original_pod, service_ip, timeout=150):
    old_count = original_pod["status"]["containerStatuses"][0]["restartCount"]
    old_uid = original_pod["metadata"]["uid"]
    deadline = time.monotonic() + timeout
    last = "restart pending"
    while time.monotonic() < deadline:
        pod = pod_json(lab, STORE)
        status = pod.get("status", {})
        containers = status.get("containerStatuses", [])
        count = containers[0].get("restartCount", -1) if containers else -1
        ready = bool(containers and containers[0].get("ready"))
        last = f"uid-same={pod.get('metadata', {}).get('uid') == old_uid}; restartCount={count}; ready={ready}"
        if count == old_count + 1 and ready and pod.get("metadata", {}).get("uid") == old_uid:
            current_service = json.loads(lab.kubectl("get", "service", STORE, "-o", "json").stdout)
            current_ip = current_service.get("spec", {}).get("clusterIP")
            image = pod.get("spec", {}).get("containers", [{}])[0].get("image")
            if current_ip != service_ip or image != STORE_IMAGE:
                lab.block(f"Endpoint or backend image changed during scoped config reload: {last}")
            return pod, last
        if count > old_count + 1:
            lab.block(f"SeaweedFS container restarted more than once during config transition: {last}")
        time.sleep(0.5)
    lab.block(f"SeaweedFS did not restart exactly once in the same Pod: {last}")


def run(lab):
    broad = json.loads(read_fixture("s3-config-broad.json"))
    scoped = json.loads(read_fixture("s3-config-scoped.json"))
    if credential_map(broad) != credential_map(scoped):
        lab.block("Broad and scoped policy fixtures changed identity credentials")
    if config_without_actions(broad) != config_without_actions(scoped):
        lab.block("Broad and scoped config differs outside the identity action grants")

    deploy(lab)
    seeded = probe(lab, "seed")
    expected_hashes = {
        BUCKETS["a"]: hashlib.sha256(read_fixture("stage-a-marker.txt").encode()).hexdigest(),
        BUCKETS["b"]: hashlib.sha256(read_fixture("stage-b-marker.txt").encode()).hexdigest(),
    }
    lab.check("red", "Fresh store creates both stage buckets and round-trips both fixed artifact markers",
              seeded.get("buckets_created") == {BUCKETS["a"]: 200, BUCKETS["b"]: 200}
              and seeded.get("markers_seeded") == {BUCKETS["a"]: 200, BUCKETS["b"]: 200}
              and seeded.get("marker_sha256") == expected_hashes, seeded)

    broad_result = probe(lab, "broad")
    broad_ok = True
    for identity in ("stage-a", "stage-b"):
        row = broad_result.get("identities", {}).get(identity, {})
        broad_ok = broad_ok and row.get("gets") == {
            BUCKETS["a"]: {"status": 200, "sha256": expected_hashes[BUCKETS["a"]]},
            BUCKETS["b"]: {"status": 200, "sha256": expected_hashes[BUCKETS["b"]]},
        } and row.get("cross_put_status") == 200
    lab.check("red", "Under broad fixture IAM, both stage identities read both stage artifacts and write across stage buckets",
              broad_ok, broad_result)

    service_before = json.loads(lab.kubectl("get", "service", STORE, "-o", "json").stdout)
    service_ip = service_before["spec"]["clusterIP"]
    pod_before = pod_json(lab, STORE)
    configmap = config_map_object(read_fixture("s3-config-scoped.json"))
    lab.kubectl("apply", "-f", "-", payload=json.dumps(configmap))
    scoped_config_sha = hashlib.sha256(read_fixture("s3-config-scoped.json").encode()).hexdigest()
    for pod in (STORE, CLIENT):
        lab.kubectl("annotate", "pod", pod, f"saf.example.test/config-revision={scoped_config_sha}", "--overwrite")
    projected = await_projected_config(lab, scoped_config_sha, timeout=110)
    lab.check("green", "Same mounted config contains the scoped policy snapshot before process restart",
              projected == scoped_config_sha, {"sha256": projected})

    # Restart the same process/container inside the same Pod so the static S3 config is reread.
    # The emptyDir and service remain tied to the same Pod; no replacement backend is introduced.
    lab.kubectl("exec", f"pod/{STORE}", "--", "/bin/sh", "-c", "kill -TERM 1",
                allow_failure=True, timeout=15)
    pod_after, restart_observation = await_same_pod_restart(lab, pod_before, service_ip)
    assert_owned_s3_endpoint(lab)

    post_restart_data = probe(lab, "verify-admin-data").get("markers", {})
    data_preserved = post_restart_data == {
        BUCKETS["a"]: {"status": 200, "sha256": expected_hashes[BUCKETS["a"]]},
        BUCKETS["b"]: {"status": 200, "sha256": expected_hashes[BUCKETS["b"]]},
    }
    lab.check("positive", "Policy reload preserved static credentials, SeaweedFS image, Pod, Service endpoint, and seeded S3 data",
              credential_map(broad) == credential_map(scoped)
              and config_without_actions(broad) == config_without_actions(scoped)
              and pod_after.get("metadata", {}).get("uid") == pod_before.get("metadata", {}).get("uid")
              and pod_after.get("spec", {}).get("containers", [{}])[0].get("image") == STORE_IMAGE
              and service_ip == service_before["spec"].get("clusterIP")
              and data_preserved,
              {"same_pod_restarted_once": True, "service_endpoint_unchanged": True,
               "marker_readback": post_restart_data})
    (lab.evidence / "stage-policy-restart.raw.json").write_text(json.dumps({
        "container_restart": restart_observation, "before_pod_uid": pod_before["metadata"]["uid"],
        "after_pod_uid": pod_after["metadata"]["uid"], "service_cluster_ip": service_ip,
        "stage_marker_readback": post_restart_data, "scoped_config_sha256": projected,
    }, indent=2, sort_keys=True) + "\n")

    scoped_result = probe(lab, "scoped")
    scoped_ok = True
    for stage in ("a", "b"):
        row = scoped_result.get("identities", {}).get("stage-" + stage, {})
        own_bucket = BUCKETS[stage]
        other_bucket, other_key, other_payload = {
            "a": (BUCKETS["b"], "artifacts/stage-b/from-stage-a.txt",
                  b"SAF-K8S-0904-014 inert cross-stage write by A v1\n"),
            "b": (BUCKETS["a"], "artifacts/stage-a/from-stage-b.txt",
                  b"SAF-K8S-0904-014 inert cross-stage write by B v1\n"),
        }[stage]
        allowed_payload = {
            "a": b"SAF-K8S-0904-014 allowed stage-a write v1\n",
            "b": b"SAF-K8S-0904-014 allowed stage-b write v1\n",
        }[stage]
        scoped_ok = scoped_ok and row.get("own_get_status") == 200
        scoped_ok = scoped_ok and row.get("own_get_sha256") == expected_hashes[own_bucket]
        scoped_ok = scoped_ok and row.get("cross_get_status") == 403
        scoped_ok = scoped_ok and row.get("cross_put_status") == 403
        scoped_ok = scoped_ok and row.get("cross_put_preserved_status") == 200
        scoped_ok = scoped_ok and row.get("cross_put_preserved_sha256") == hashlib.sha256(other_payload).hexdigest()
        scoped_ok = scoped_ok and row.get("allowed_put_status") == 200
        scoped_ok = scoped_ok and row.get("allowed_readback_status") == 200
        scoped_ok = scoped_ok and row.get("allowed_readback_sha256") == hashlib.sha256(allowed_payload).hexdigest()
        scoped_ok = scoped_ok and row.get("cross_put_target") == f"{other_bucket}/{other_key}"
    lab.check("green", "Same stage credentials now receive S3 403 for the exact cross-stage reads and writes",
              scoped_ok, {"identities": scoped_result.get("identities")})
    lab.check("positive", "Each scoped stage still reads its own artifact and writes/readbacks an own-stage marker",
              scoped_ok, {"identities": scoped_result.get("identities")})

    lifecycle = scoped_result.get("lifecycle", [])
    lifecycle_ok = len(lifecycle) == 2 and all(
        item.get("put_status") in (200, 204) and item.get("get_status") == 200
        and item.get("matches") is True for item in lifecycle)
    lab.check("positive", "SeaweedFS stores and reads back distinct stage-bucket lifecycle rules",
              lifecycle_ok, lifecycle)
