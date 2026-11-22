"""SeaweedFS 4.53 S3 policy and volume-data encryption fixture."""
import base64
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
STORE_IMAGE = "docker.io/chrislusf/seaweedfs:4.53@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0"
CLIENT_IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
                "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
STORE = "artifact-store"
CLIENT = "artifact-client"
BUCKET = "saf-artifacts-0904"
KEY = "evidence/marker.bin"
MARKER = (FIXTURES / "marker.bin").read_bytes()
MARKER_SHA = "7ef23877d2d11a502f6d9433ce2d666b9a66263115b5dad1d105e0711407cdfc"

SCOPE = (
    "One fresh Kind v1.36.1 namespace runs pinned SeaweedFS 4.53 with a new emptyDir for each "
    "matched S3 object write. The same fixed 64 KiB fixture bytes, bucket, key, MIME type and "
    "SigV4 request run with the documented default s3.encryptVolumeData=false and with only "
    "s3.encryptVolumeData=true added. A read-only sidecar independently records bounded raw "
    "volume .dat/.idx evidence; the signed S3 readback must match the fixed SHA-256 in both "
    "phases. It then tests a case-owned read-only bucket policy, exact denial codes after policy "
    "removal, and a scoped identity positive control. This does not establish production key "
    "custody, backups, provider configuration, federation, transfer encryption, or other stores."
)

def security(read_only=False):
    value = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
             "runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
             "seccompProfile": {"type": "RuntimeDefault"}}
    if read_only:
        value["readOnlyRootFilesystem"] = True
    return value


def config_map(name, data, binary_data=None):
    obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
           "immutable": True, "data": data}
    if binary_data:
        obj["binaryData"] = binary_data
    return obj


def service():
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": STORE},
            "spec": {"type": "ClusterIP", "selector": {"app": STORE},
                     "ports": [{"name": "s3", "port": 8333, "targetPort": 8333}]}}


def store_pod(encrypted):
    command = ["weed", "mini", "-s3.config=/fixture/s3-config.json", "-dir=/data",
               "-filer.filerGroup=saf-case-013", "-master.volumeSizeLimitMB=64",
               "-master.telemetry=false", "-webdav=false", "-admin.ui=false",
               "-s3.port.iceberg=0", "-s3.port.lance=0"]
    if encrypted:
        command.append("-s3.encryptVolumeData=true")
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": STORE, "labels": {"app": STORE}},
        "spec": {
            "automountServiceAccountToken": False, "restartPolicy": "Always",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "runAsGroup": 65534, "fsGroup": 65534},
            "containers": [
                {"name": "store", "image": STORE_IMAGE, "imagePullPolicy": "IfNotPresent",
                 "command": command, "securityContext": security(),
                 "ports": [{"name": "s3", "containerPort": 8333}],
                 "resources": {"requests": {"cpu": "100m", "memory": "256Mi"},
                               "limits": {"cpu": "750m", "memory": "768Mi"}},
                 "readinessProbe": {"tcpSocket": {"port": 8333}, "periodSeconds": 2,
                                    "timeoutSeconds": 1, "failureThreshold": 30},
                 "volumeMounts": [{"name": "fixtures", "mountPath": "/fixture", "readOnly": True},
                                  {"name": "data", "mountPath": "/data"}]},
                {"name": "witness", "image": CLIENT_IMAGE, "imagePullPolicy": "IfNotPresent",
                 "command": ["python", "-B", "-c", "import time; time.sleep(600)"],
                 "securityContext": security(read_only=True),
                 "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                               "limits": {"cpu": "200m", "memory": "128Mi"}},
                 "volumeMounts": [{"name": "data", "mountPath": "/data", "readOnly": True}]}
            ],
            "volumes": [{"name": "fixtures", "configMap": {"name": "artifact-store-fixtures"}},
                        {"name": "data", "emptyDir": {"sizeLimit": "512Mi"}}]
        }
    }


def deploy_client(lab):
    lab.create({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": CLIENT, "labels": {"app": CLIENT}},
        "spec": {"automountServiceAccountToken": False, "restartPolicy": "Always",
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                     "runAsGroup": 65534},
                 "containers": [{"name": "client", "image": CLIENT_IMAGE,
                                 "imagePullPolicy": "IfNotPresent",
                                 "command": ["python", "-B", "-c", "import time; time.sleep(600)"],
                                 "securityContext": security(read_only=True),
                                 "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                               "limits": {"cpu": "200m", "memory": "128Mi"}},
                                 "volumeMounts": [{"name": "fixtures", "mountPath": "/fixture",
                                                    "readOnly": True}]}],
                 "volumes": [{"name": "fixtures", "configMap":
                              {"name": "artifact-store-fixtures"}}]}}
    )
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{CLIENT}", "--timeout=80s", timeout=90)


def start_phase(lab, encrypted):
    pod_uid = lab.create(store_pod(encrypted))["metadata"]["uid"]
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{STORE}", "--timeout=120s", timeout=130)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        slices = lab.kubectl("get", "endpointslice", "-l", f"kubernetes.io/service-name={STORE}", "-o", "json")
        ready = [endpoint.get("targetRef", {}).get("uid")
                 for row in json.loads(slices.stdout)["items"]
                 for endpoint in row.get("endpoints", [])
                 if endpoint.get("conditions", {}).get("ready") is True]
        if ready == [pod_uid]:
            return pod_uid
        time.sleep(0.3)
    lab.block("The S3 Service did not select the current case-owned Ready Pod")


def stop_phase(lab):
    lab.kubectl("delete", "pod", STORE, "--wait=true", "--timeout=90s", timeout=100)


def probe(lab, operation):
    result = lab.kubectl("exec", f"pod/{CLIENT}", "--", "python", "-B",
                         "/fixture/s3_probe.py", operation, timeout=35)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"fixture did not emit structured output for {operation}: {error}")
    if value.get("operation") != operation or value.get("bucket") != BUCKET:
        lab.block(f"fixture returned unexpected operation/bucket for {operation}")
    return value


def raw_witness(lab):
    result = lab.kubectl("exec", "-i", f"pod/{STORE}", "-c", "witness", "--", "python", "-B",
                         "-", payload=(FIXTURES / "volume_witness.py").read_text(), timeout=35)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"read-only storage witness emitted no structured result: {error}")
    if value.get("idx_records") != 1 or value.get("needle_header_matches_index") is not True:
        lab.block("raw volume index/header does not identify the single stored needle")
    return value


def run(lab):
    marker_hash = hashlib.sha256(MARKER).hexdigest()
    if len(MARKER) != 65536 or marker_hash != MARKER_SHA:
        lab.block("owned deterministic marker fixture failed its fixed length/SHA-256 check")
    config = (FIXTURES / "s3-config.json").read_text()
    policy = (FIXTURES / "public-bucket-policy.json").read_text()
    probe_source = (FIXTURES / "s3_probe.py").read_text()
    lab.create(config_map("artifact-store-fixtures",
        {"s3-config.json": config, "public-bucket-policy.json": policy,
         "s3_probe.py": probe_source}, {"marker.bin": base64.b64encode(MARKER).decode()}))
    lab.create(service())
    deploy_client(lab)

    unencrypted_pod = start_phase(lab, encrypted=False)
    off = probe(lab, "volume-off")
    raw_off = raw_witness(lab)
    lab.check("red", "Unencrypted S3 volume stores the exact fixture marker in its indexed raw data file",
              off.get("put_status") == 200 and off.get("get_status") == 200
              and off.get("marker_sha256") == MARKER_SHA and off.get("marker_length") == len(MARKER)
              and off.get("content_type") == "application/octet-stream"
              and raw_off.get("marker_occurrences_in_dat") == 1
              and raw_off.get("marker_occurrences_in_indexed_record") == 1,
              {"s3": off, "plaintext_marker_in_indexed_record": raw_off["marker_occurrences_in_indexed_record"] == 1})
    stop_phase(lab)

    encrypted_pod = start_phase(lab, encrypted=True)
    if encrypted_pod == unencrypted_pod:
        lab.block("The off/on phases must use separate Pods and emptyDir volumes")
    on = probe(lab, "volume-on")
    raw_on = raw_witness(lab)
    lab.check("green", "Encrypt-volume-data switch preserves signed S3 readback while the indexed raw volume bytes differ from plaintext",
              on.get("put_status") == 200 and on.get("get_status") == 200
              and on.get("marker_sha256") == MARKER_SHA and on.get("marker_length") == len(MARKER)
              and on.get("content_type") == "application/octet-stream"
              and raw_on.get("marker_occurrences_in_dat") == 0
              and raw_on.get("dat_size", 0) > 0
              and raw_on["indexed_size"] >= len(MARKER)
              and raw_on.get("idx_records") == 1
              and raw_on.get("needle_header_matches_index") is True,
              {"s3": on, "plaintext_marker_in_indexed_record": raw_on["marker_occurrences_in_indexed_record"] == 1,
               "raw_volume_bytes_differ_from_the_off_phase": raw_on["dat_sha256"] != raw_off["dat_sha256"]})
    lab.check("positive", "Off/on phases used the same fixed bytes, S3 bucket/key, MIME type, and client operation",
              off.get("marker_sha256") == on.get("marker_sha256") == MARKER_SHA
              and off.get("key") == on.get("key") == KEY
              and off.get("content_type") == on.get("content_type") == "application/octet-stream"
              and off.get("marker_length") == on.get("marker_length") == len(MARKER),
              {"off_sha256": off.get("marker_sha256"), "on_sha256": on.get("marker_sha256"),
               "key": KEY, "length": len(MARKER), "content_type": "application/octet-stream"})
    # All raw storage evidence was collected before testing bucket-policy changes.
    public = probe(lab, "policy-public")
    lab.check("red", "The read-only bucket policy permits the exact anonymous read and denies the fixed anonymous write",
              public.get("policy_put_status") in (200, 204)
              and public.get("policy_read_status") == 200 and public.get("policy_read_matches") is True
              and public.get("anonymous_get_status") == 200
              and public.get("anonymous_get_sha256") == MARKER_SHA
              and public.get("anonymous_put_status") == 403
              and public.get("anonymous_put_error") == "AccessDenied", public)
    private = probe(lab, "policy-private")
    lab.check("green", "Removing bucket policy returns exact AccessDenied codes for anonymous GET and PUT",
              private.get("policy_delete_status") in (200, 204)
              and private.get("policy_read_status") == 404
              and private.get("policy_read_error") == "NoSuchBucketPolicy"
              and private.get("anonymous_get_status") == 403
              and private.get("anonymous_get_error") == "AccessDenied"
              and private.get("anonymous_put_status") == 403
              and private.get("anonymous_put_error") == "AccessDenied", private)
    absent = probe(lab, "policy-absent")
    lab.check("positive", "Administrator confirms policy absence using the S3 policy API",
              absent.get("policy_read_status") == 404
              and absent.get("policy_read_error") == "NoSuchBucketPolicy", absent)
    approved = probe(lab, "approved-positive")
    lab.check("positive", "Bucket-scoped pipeline fixture identity retains read and write after anonymous policy removal",
              approved.get("get_status") == 200 and approved.get("get_sha256") == MARKER_SHA
              and approved.get("put_status") == 200 and approved.get("readback_status") == 200
              and approved.get("readback_sha256") == approved.get("expected_readback_sha256"), approved)
    (lab.evidence / "seaweedfs-volume-and-policy.json").write_text(json.dumps({
        "volume_encryption_off": {"s3": off, "raw_volume": raw_off},
        "volume_encryption_on": {"s3": on, "raw_volume": raw_on},
        "public_policy": public, "private_policy": private,
        "policy_absent_readback": absent, "approved_identity": approved,
        "unencrypted_pod_uid": unencrypted_pod, "encrypted_pod_uid": encrypted_pod,
        "marker_sha256": MARKER_SHA, "marker_length": len(MARKER),
        "backend_image": STORE_IMAGE
    }, indent=2, sort_keys=True) + "\n")
