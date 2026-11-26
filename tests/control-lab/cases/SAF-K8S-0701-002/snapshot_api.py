"""Native dry-run authorization fixture for the VolumeSnapshot API.

Call run_snapshot_api_dryrun(lab) after the case-owned PVC has bound. It installs
only hash-checked official CRDs, never installs snapshot controllers/sidecars,
and uses projected ServiceAccount tokens to submit dryRun=All requests.
"""
import hashlib
import json
from pathlib import Path
import time

from fixtures import pod

NAMESPACE = "saf-0701-002-csi"
PVC = "saf-0701-002-pvc"
SNAPSHOT_CLASS = "saf-0701-002-synthetic-snapshot-class"
AUTHORIZED_SA = "saf-0701-002-snapshot-authorized"
DENIED_SA = "saf-0701-002-snapshot-denied"
AUTHORIZED_POD = "saf-0701-002-snapshot-authorized-probe"
DENIED_POD = "saf-0701-002-snapshot-denied-probe"
SNAPSHOT_NAME = "saf-0701-002-dryrun-only-snapshot"
ROLE = "saf-0701-002-snapshot-create"
ROLE_BINDING = "saf-0701-002-snapshot-create"
IMAGE = "docker.io/library/python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89"
CRD_NAMES = (
    "volumesnapshots.snapshot.storage.k8s.io",
    "volumesnapshotclasses.snapshot.storage.k8s.io",
    "volumesnapshotcontents.snapshot.storage.k8s.io",
)


def _kubectl(lab, *args, allow_failure=False, timeout=45, payload=None):
    return lab.kubectl(*args, allow_failure=allow_failure, timeout=timeout,
                       payload=payload)


def _verify_and_install_crds(lab):
    pins = json.loads(Path(__file__).with_name("crd-pins.json").read_text())
    ref = "a6a3d9d6b5f6f1e6fa0d311148b696556e4499e8"
    if pins.get("repository") != "kubernetes-csi/external-snapshotter" or pins.get("ref") != ref:
        lab.block("Snapshot CRD source pin is not the reviewed immutable upstream commit")
    verified = []
    prefix = (
        "https://raw.githubusercontent.com/kubernetes-csi/external-snapshotter/"
        f"{ref}/client/config/crd/"
    )
    expected_names = sorted("snapshot.storage.k8s.io_" + name.split(".")[0] + ".yaml"
                            for name in CRD_NAMES)
    if set(pins["files"]) != set(expected_names):
        lab.block("Snapshot CRD pin manifest does not contain the exact reviewed three-file set")
    root = lab.kubeconfig.parent / "snapshot-crds"
    root.mkdir()
    for name in expected_names:
        expected = pins["files"][name]
        data_path = root / name
        lab.command("curl", "--fail", "--silent", "--show-error", "--location", "--max-time", "45",
                    prefix + name, "-o", str(data_path), timeout=55)
        data = data_path.read_bytes()
        git_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        if (len(data) != expected["bytes"] or git_blob != expected["git_blob_sha1"]
                or sha256 != expected["sha256"]):
            lab.block(f"Official snapshot CRD integrity mismatch: {name}")
        verified.append({"name": name, "git_blob_sha1_matches": True,
                         "sha256_matches": True, "bytes": len(data)})
    for name in expected_names:
        _kubectl(lab, "apply", "-f", str(root / name), timeout=60)

    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        ready = True
        for name in CRD_NAMES:
            result = _kubectl(lab, "get", "crd", name, "-o", "json", allow_failure=True)
            if result.returncode != 0:
                ready = False
                break
            item = json.loads(result.stdout)
            established = any(c.get("type") == "Established" and c.get("status") == "True"
                              for c in item.get("status", {}).get("conditions", []))
            ready &= established
        if ready:
            lab.check("positive", "All official v8.2.1 snapshot API CRDs match verified hashes and are Established",
                      True, {"source_ref": pins["ref"], "crds": verified,
                             "all_three_established": True})
            return
        time.sleep(1)
    lab.check("positive", "All official v8.2.1 snapshot API CRDs match verified hashes and are Established",
              False, {"source_ref": pins["ref"], "crds": verified,
                     "all_three_established": False})


def _probe_script():
    return '''import json, os, ssl, urllib.error, urllib.request

actor = os.environ["FIXTURE_ACTOR"]
token = open("/var/run/secrets/kubernetes.io/serviceaccount/token", encoding="utf-8").read().strip()
ca = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
api = "https://%s:%s" % (os.environ["KUBERNETES_SERVICE_HOST"], os.environ["KUBERNETES_SERVICE_PORT_HTTPS"])
url = api + "/apis/snapshot.storage.k8s.io/v1/namespaces/saf-0701-002-csi/volumesnapshots?dryRun=All"
body = {"apiVersion":"snapshot.storage.k8s.io/v1", "kind":"VolumeSnapshot",
        "metadata":{"name":"saf-0701-002-dryrun-only-snapshot", "namespace":"saf-0701-002-csi",
                    "labels":{"saf.example/fixture":"0701-002"}},
        "spec":{"volumeSnapshotClassName":"saf-0701-002-synthetic-snapshot-class",
                "source":{"persistentVolumeClaimName":"saf-0701-002-pvc"}}}
request = urllib.request.Request(url, data=json.dumps(body).encode(),
    headers={"Authorization":"Bearer " + token, "Content-Type":"application/json"}, method="POST")
ctx = ssl.create_default_context(cafile=ca)
try:
    with urllib.request.urlopen(request, context=ctx, timeout=20) as response:
        status = response.status
except urllib.error.HTTPError as error:
    status = error.code
    error.close()
print(json.dumps({"actor":actor, "http_status":status}))
'''


def _create_probe(lab, name, service_account, actor, probe_configmap):
    item = pod(name, [{
        "name": "api-probe", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["python3", "/probe/probe.py"],
        "env": [{"name": "FIXTURE_ACTOR", "value": actor}],
        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False,
                             "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                             "runAsUser": 65534,
                             "seccompProfile": {"type": "RuntimeDefault"}},
        "volumeMounts": [{"name": "probe", "mountPath": "/probe", "readOnly": True}],
    }], serviceAccountName=service_account, automountServiceAccountToken=True,
        restartPolicy="Never", terminationGracePeriodSeconds=1,
        volumes=[{"name": "probe", "configMap": {"name": probe_configmap}}])
    item["metadata"]["namespace"] = NAMESPACE
    _kubectl(lab, "create", "-n", NAMESPACE, "-f", "-", payload=json.dumps(item))


def _wait_probe(lab, name):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = _kubectl(lab, "get", "pod", name, "-n", NAMESPACE, "-o", "json",
                          allow_failure=True)
        if result.returncode == 0:
            phase = json.loads(result.stdout).get("status", {}).get("phase")
            if phase in ("Succeeded", "Failed"):
                return phase == "Succeeded"
        time.sleep(1)
    return False


def _log_status(lab, name, actor):
    result = _kubectl(lab, "logs", name, "-n", NAMESPACE, allow_failure=True)
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("actor") == actor and type(item.get("http_status")) is int:
            return item["http_status"]
    return None


def run_snapshot_api_dryrun(lab):
    """Use actual projected fixture tokens for one allowed and one denied request."""
    _verify_and_install_crds(lab)
    _kubectl(lab, "create", "serviceaccount", AUTHORIZED_SA, "-n", NAMESPACE)
    _kubectl(lab, "create", "serviceaccount", DENIED_SA, "-n", NAMESPACE)

    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": ROLE, "namespace": NAMESPACE},
            "rules": [{"apiGroups": ["snapshot.storage.k8s.io"],
                       "resources": ["volumesnapshots"], "verbs": ["create"]}]}
    _kubectl(lab, "create", "-n", NAMESPACE, "-f", "-", payload=json.dumps(role))
    binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
               "metadata": {"name": ROLE_BINDING, "namespace": NAMESPACE},
               "subjects": [{"kind": "ServiceAccount", "name": AUTHORIZED_SA,
                             "namespace": NAMESPACE}],
               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                           "name": ROLE}}
    _kubectl(lab, "create", "-n", NAMESPACE, "-f", "-", payload=json.dumps(binding))

    snap_class = {"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshotClass",
                  "metadata": {"name": SNAPSHOT_CLASS,
                               "labels": {"saf.example/fixture": "0701-002"}},
                  "driver": "hostpath.csi.k8s.io", "deletionPolicy": "Retain"}
    _kubectl(lab, "create", "-f", "-", payload=json.dumps(snap_class))
    configmap = {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": "saf-0701-002-snapshot-probe",
                              "namespace": NAMESPACE},
                 "data": {"probe.py": _probe_script()}}
    _kubectl(lab, "create", "-n", NAMESPACE, "-f", "-", payload=json.dumps(configmap))
    _create_probe(lab, AUTHORIZED_POD, AUTHORIZED_SA, "authorized", configmap["metadata"]["name"])
    _create_probe(lab, DENIED_POD, DENIED_SA, "unauthorized", configmap["metadata"]["name"])

    authorized_probe_succeeded = _wait_probe(lab, AUTHORIZED_POD)
    denied_probe_succeeded = _wait_probe(lab, DENIED_POD)
    probes_succeeded = authorized_probe_succeeded and denied_probe_succeeded
    allowed_status = _log_status(lab, AUTHORIZED_POD, "authorized")
    denied_status = _log_status(lab, DENIED_POD, "unauthorized")
    lab.check("positive", "Projected actor with namespaced VolumeSnapshot create receives API-server dry-run acceptance; ungranted actor receives 403",
              probes_succeeded and allowed_status == 201 and denied_status == 403,
              {"authorized_projected_token_status": allowed_status,
               "ungranted_projected_token_status": denied_status,
               "both_probe_containers_succeeded": probes_succeeded,
               "request_query": "dryRun=All"})

    get = _kubectl(lab, "get", "volumesnapshot", SNAPSHOT_NAME, "-n", NAMESPACE,
                   "-o", "json", allow_failure=True)
    absent = get.returncode != 0 and "NotFound" in get.stderr
    lab.check("positive", "Neither API dry-run persisted a VolumeSnapshot object",
              absent, {"exact_case_snapshot_absent": absent})

    # Remove only case-owned probe and authorization objects; the disposable lab
    # runner removes the cluster containing the verified CRDs.
    for name in (AUTHORIZED_POD, DENIED_POD):
        _kubectl(lab, "delete", "pod", name, "-n", NAMESPACE,
                 "--wait=true", "--timeout=30s")
    _kubectl(lab, "delete", "configmap", configmap["metadata"]["name"],
             "-n", NAMESPACE, "--wait=true", "--timeout=20s")
    _kubectl(lab, "delete", "volumesnapshotclass", SNAPSHOT_CLASS,
             "--wait=true", "--timeout=20s")
    _kubectl(lab, "delete", "rolebinding", ROLE_BINDING, "-n", NAMESPACE,
             "--wait=true", "--timeout=20s")
    _kubectl(lab, "delete", "role", ROLE, "-n", NAMESPACE,
             "--wait=true", "--timeout=20s")
    for name in (AUTHORIZED_SA, DENIED_SA):
        _kubectl(lab, "delete", "serviceaccount", name, "-n", NAMESPACE,
                 "--wait=true", "--timeout=20s")
