"""Verify real kube-apiserver webhook delivery and receiver PVC retention."""

import base64
import json
from pathlib import Path
import re
import time


CASE_DIR = Path(__file__).resolve().parent
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
RECEIVER_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAMESPACE = "saf-test"
SERVICE_IP = "10.96.42.26"
SERVICE_NAME = "audit-sink"
POD_NAME = "audit-sink"
PVC_NAME = "audit-sink-data"
STORAGE_CLASS = "saf-audit-webhook-localpath"
SCOPE = (
    "One digest-pinned kind Kubernetes v1.36.1 cluster, namespace saf-test, and narrowly "
    "scoped ConfigMap metadata events. The API server's native audit webhook sends actual "
    "audit.k8s.io/v1 EventList batches over TLS to a case-owned receiver whose CA is pinned "
    "in the webhook kubeconfig. A unique inert ConfigMap create is matched to its exact "
    "ResponseComplete auditID at the receiver. The case compares emptyDir loss with a "
    "case-owned PVC, deletes and recreates the PVC-backed receiver Pod, checks prior exact "
    "IDs, and confirms a new post-restart event. It does not establish production SIEM, "
    "audit.log, managed-exporter, tamper resistance, long-term retention, or failure-domain durability."
)


def prepare_kind(lab, temporary: Path) -> Path:
    policy = temporary / "audit-policy.yaml"
    policy.write_bytes((CASE_DIR / "audit-policy.yaml").read_bytes())
    (temporary / "receiver.py").write_bytes((CASE_DIR / "receiver.py").read_bytes())
    ca = temporary / "receiver-ca.crt"
    ca_key = temporary / "receiver-ca.key"
    request = temporary / "receiver.csr"
    ca_config = temporary / "ca.cnf"
    ca_config.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ca\n"
        "[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
    )
    extensions = temporary / "tls.cnf"
    extensions.write_text(
        f"subjectAltName=DNS:{SERVICE_NAME}.{NAMESPACE}.svc\n"
        "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
    )
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-sha256", "-days", "2", "-config", str(ca_config), "-subj", "/CN=SAF audit fixture CA",
                "-keyout", str(ca_key), "-out", str(ca))
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", f"/CN={SERVICE_NAME}.{NAMESPACE}.svc",
                "-keyout", str(temporary / "receiver-server.key"), "-out", str(request))
    lab.command("openssl", "x509", "-req", "-in", str(request), "-CA", str(ca),
                "-CAkey", str(ca_key), "-set_serial", "1", "-days", "2", "-sha256",
                "-extfile", str(extensions), "-out", str(temporary / "receiver-server.crt"))
    ca_key.unlink()
    ca = ca.read_bytes()
    webhook = temporary / "audit-webhook.kubeconfig"
    webhook.write_text(json.dumps({
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "case-receiver", "cluster": {
            "server": f"https://{SERVICE_IP}:8443",
            "tls-server-name": f"{SERVICE_NAME}.{NAMESPACE}.svc",
            "certificate-authority-data": base64.b64encode(ca).decode("ascii"),
        }}],
        "users": [{"name": "webhook", "user": {}}],
        "contexts": [{"name": "webhook", "context": {
            "cluster": "case-receiver", "user": "webhook",
        }}],
        "current-context": "webhook",
    }), encoding="utf-8")
    config = temporary / "kind.yaml"
    config.write_text(
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n  - role: control-plane\n    extraMounts:\n"
        f"      - hostPath: {json.dumps(str(policy))}\n"
        "        containerPath: /etc/kubernetes/audit-policy.yaml\n        readOnly: true\n"
        f"      - hostPath: {json.dumps(str(webhook))}\n"
        "        containerPath: /etc/kubernetes/audit-webhook.kubeconfig\n        readOnly: true\n"
        "kubeadmConfigPatches:\n  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n    kind: ClusterConfiguration\n"
        "    apiServer:\n      extraArgs:\n"
        "        - name: audit-policy-file\n          value: /etc/kubernetes/audit-policy.yaml\n"
        "        - name: audit-webhook-config-file\n          value: /etc/kubernetes/audit-webhook.kubeconfig\n"
        "        - name: audit-webhook-mode\n          value: batch\n"
        "        - name: audit-webhook-version\n          value: audit.k8s.io/v1\n"
        "        - name: audit-webhook-initial-backoff\n          value: 1s\n"
        "        - name: audit-webhook-batch-max-wait\n          value: 1s\n"
        "      extraVolumes:\n"
        "        - name: audit-policy\n          hostPath: /etc/kubernetes/audit-policy.yaml\n"
        "          mountPath: /etc/kubernetes/audit-policy.yaml\n"
        "          readOnly: true\n          pathType: File\n"
        "        - name: audit-webhook\n          hostPath: /etc/kubernetes/audit-webhook.kubeconfig\n"
        "          mountPath: /etc/kubernetes/audit-webhook.kubeconfig\n"
        "          readOnly: true\n          pathType: File\n",
        encoding="utf-8",
    )
    return config


def sink_pod(storage):
    if storage == "persistent":
        volume = {"persistentVolumeClaim": {"claimName": PVC_NAME}}
        storage_mount = {"name": "data", "mountPath": "/data"}
    elif storage == "ephemeral":
        volume = {"emptyDir": {}}
        storage_mount = {"name": "data", "mountPath": "/data"}
    else:
        raise ValueError(storage)
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": POD_NAME, "namespace": NAMESPACE,
                     "labels": {"app": SERVICE_NAME, "storage": storage}},
        "spec": {
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 5,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                 "runAsGroup": 10001, "fsGroup": 10001,
                                 "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "receiver", "image": RECEIVER_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-u", "/app/receiver.py"],
                "ports": [{"name": "https", "containerPort": 8443}],
                "readinessProbe": {"httpGet": {"path": "/healthz", "port": "https",
                                                   "scheme": "HTTPS"},
                                   "periodSeconds": 1, "failureThreshold": 30},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [
                    {"name": "code", "mountPath": "/app", "readOnly": True},
                    {"name": "tls", "mountPath": "/tls", "readOnly": True},
                    storage_mount,
                ],
            }],
            "volumes": [
                {"name": "code", "configMap": {"name": "audit-sink-code"}},
                {"name": "tls", "secret": {"secretName": "audit-sink-tls"}},
                {"name": "data", **volume},
            ],
        },
    }


def set_service_target(lab, storage):
    lab.kubectl("patch", "service", SERVICE_NAME, "--type=merge", "-p",
                json.dumps({"spec": {"selector": {"app": SERVICE_NAME, "storage": storage}}}))


def deploy_receiver(lab, storage):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(sink_pod(storage)))
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{POD_NAME}", "--timeout=90s", timeout=100)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        endpoints = json.loads(lab.kubectl("get", "endpoints", SERVICE_NAME, "-o", "json").stdout)
        if any(subset.get("addresses") for subset in endpoints.get("subsets", [])):
            snapshot(lab)
            return
        time.sleep(0.5)
    lab.block("The ready receiver Pod did not become an endpoint of the case-owned Service")


def snapshot(lab):
    probe = r"""import http.client, socket, ssl, sys, time
context = ssl.create_default_context(cafile="/tls/ca.crt")
address, name = sys.argv[1:]
deadline = time.monotonic() + 25
while True:
    try:
        with socket.create_connection((address, 8443), timeout=2) as stream:
            with context.wrap_socket(stream, server_hostname=name) as tls:
                tls.sendall(f"GET /snapshot HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
                response = http.client.HTTPResponse(tls)
                response.begin()
                if response.status != 200:
                    raise RuntimeError(f"Unexpected snapshot status {response.status}")
                print(response.read().decode())
                break
    except (ConnectionRefusedError, TimeoutError):
        if time.monotonic() >= deadline:
            raise
        time.sleep(1)
"""
    result = lab.kubectl("exec", f"pod/{POD_NAME}", "--", "python", "-c", probe,
                         SERVICE_IP, f"{SERVICE_NAME}.{NAMESPACE}.svc")
    return json.loads(result.stdout)


def matching_event(events, name):
    matches = []
    for event in events:
        ref = event.get("objectRef") or {}
        status = event.get("responseStatus") or {}
        if (event.get("stage") == "ResponseComplete" and event.get("level") == "Metadata"
                and event.get("verb") == "create" and ref.get("resource") == "configmaps"
                and ref.get("namespace") == NAMESPACE and ref.get("name") == name
                and status.get("code") == 201 and "requestObject" not in event
                and "responseObject" not in event and re.fullmatch(r"[0-9a-f-]{16,64}", event.get("auditID", ""))):
            matches.append(event)
    ids = sorted({event["auditID"] for event in matches})
    return ids, matches


def wait_for_event(lab, name, timeout=35):
    deadline = time.monotonic() + timeout
    events = []
    while time.monotonic() < deadline:
        events = snapshot(lab)
        ids, _ = matching_event(events, name)
        if ids:
            break
        time.sleep(0.5)
    ids, matches = matching_event(events, name)
    if not ids:
        lab.kubectl("-n", "kube-system", "logs", "-l", "component=kube-apiserver", "--tail=65", allow_failure=True)
        lab.kubectl("logs", POD_NAME, "--tail=30", allow_failure=True)
    return ids, matches


def create_marker(lab, name):
    obj = {"apiVersion": "v1", "kind": "ConfigMap",
           "metadata": {"name": name, "namespace": NAMESPACE}, "data": {"fixture": "inert"}}
    result = lab.kubectl("create", "--raw", f"/api/v1/namespaces/{NAMESPACE}/configmaps",
                         "-f", "-", "--v=8", payload=json.dumps(obj))
    ids = set(re.findall(r"(?i)\baudit-id\s*:\s*([a-f0-9-]{36})", result.stderr))
    if len(ids) != 1 or json.loads(result.stdout)["metadata"]["name"] != name:
        lab.block("ConfigMap create did not return the expected target and Audit-Id")
    return ids.pop()


def retain_raw_ids(lab, label, event_sets):
    raw = {name: matching_event(events, name)[0] for name, events in event_sets.items()}
    destination = lab.evidence / f"raw-audit-ids-{label}.json"
    destination.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return raw


def assert_delivery(lab, name, events):
    ids, matches = matching_event(events, name)
    ok = len(ids) == 1 and bool(matches)
    return ok, {"unique_audit_id_count": len(ids),
                "metadata_only": bool(matches) and all(
                    "requestObject" not in event and "responseObject" not in event for event in matches),
                "successful_response": bool(matches) and all(
                    (event.get("responseStatus") or {}).get("code") == 201 for event in matches)}


def run(lab):
    lab.kubectl("create", "configmap", "audit-sink-code",
                f"--from-file=receiver.py={lab.kubeconfig.with_name('receiver.py')}")
    lab.kubectl("create", "secret", "generic", "audit-sink-tls",
                f"--from-file=tls.crt={lab.kubeconfig.with_name('receiver-server.crt')}",
                f"--from-file=tls.key={lab.kubeconfig.with_name('receiver-server.key')}",
                f"--from-file=ca.crt={lab.kubeconfig.with_name('receiver-ca.crt')}")
    lab.kubectl("apply", "-f", "-", payload=json.dumps({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": SERVICE_NAME, "namespace": NAMESPACE},
        "spec": {"type": "ClusterIP", "clusterIP": SERVICE_IP,
                 "selector": {"app": SERVICE_NAME, "storage": "ephemeral"},
                 "ports": [{"name": "https", "port": 8443, "targetPort": 8443}]},
    }))
    lab.kubectl("apply", "-f", "-", payload=json.dumps({
        "apiVersion": "storage.k8s.io/v1", "kind": "StorageClass",
        "metadata": {"name": STORAGE_CLASS},
        "provisioner": "rancher.io/local-path",
        "reclaimPolicy": "Delete",
        "volumeBindingMode": "WaitForFirstConsumer",
    }))

    deploy_receiver(lab, "ephemeral")
    ephemeral_id = create_marker(lab, "audit-ephemeral-before-restart")
    ephemeral_ids, ephemeral_events = wait_for_event(lab, "audit-ephemeral-before-restart")
    ephemeral_ok = ephemeral_ids == [ephemeral_id]
    lab.check("red", "An actual API-server audit event reaches an emptyDir-backed receiver",
              ephemeral_ok, {"unique_audit_id_count": len(ephemeral_ids),
                             "receiver_records_present": bool(ephemeral_events)})
    retain_raw_ids(lab, "ephemeral-before", {"audit-ephemeral-before-restart": ephemeral_events})

    lab.kubectl("delete", "pod", POD_NAME, "--wait=true", "--timeout=45s", timeout=55)
    deploy_receiver(lab, "ephemeral")
    after_ephemeral_restart = snapshot(lab)
    lost_ids, _ = matching_event(after_ephemeral_restart, "audit-ephemeral-before-restart")
    lab.check("red", "Deleting and recreating the receiver Pod loses its emptyDir audit record",
              not lost_ids, {"old_event_record_present_after_pod_recreation": bool(lost_ids)})

    lab.kubectl("delete", "pod", POD_NAME, "--wait=true", "--timeout=45s", timeout=55)
    set_service_target(lab, "persistent")
    lab.kubectl("apply", "-f", "-", payload=json.dumps({
        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
        "metadata": {"name": PVC_NAME, "namespace": NAMESPACE},
        "spec": {"storageClassName": STORAGE_CLASS, "accessModes": ["ReadWriteOnce"],
                 "resources": {"requests": {"storage": "32Mi"}}},
    }))
    deploy_receiver(lab, "persistent")
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Bound", f"pvc/{PVC_NAME}",
                "--timeout=120s", timeout=130)
    claim = json.loads(lab.kubectl("get", "pvc", PVC_NAME, "-o", "json").stdout)
    volume_name = claim.get("spec", {}).get("volumeName")
    if not volume_name:
        lab.block("The receiver PVC did not bind to a PersistentVolume")
    before_pod = json.loads(lab.kubectl("get", "pod", POD_NAME, "-o", "json").stdout)
    expected_old = create_marker(lab, "audit-pvc-before-restart")
    before_ids, before_events = wait_for_event(lab, "audit-pvc-before-restart")
    before_ok, before_summary = assert_delivery(lab, "audit-pvc-before-restart", before_events)
    lab.check("positive", "The live API-server webhook delivers one successful metadata event to the PVC receiver",
              before_ok and before_ids == [expected_old], before_summary | {"pvc_bound": True, "pv_name_present": bool(volume_name)})
    retain_raw_ids(lab, "pvc-before", {"audit-pvc-before-restart": before_events})

    lab.kubectl("delete", "pod", POD_NAME, "--wait=true", "--timeout=45s", timeout=55)
    deploy_receiver(lab, "persistent")
    after_restart = snapshot(lab)
    after_claim = json.loads(lab.kubectl("get", "pvc", PVC_NAME, "-o", "json").stdout)
    after_pod = json.loads(lab.kubectl("get", "pod", POD_NAME, "-o", "json").stdout)
    same_claim = (after_claim["spec"].get("volumeName") == volume_name
                  and after_claim["metadata"]["uid"] == claim["metadata"]["uid"])
    replaced = after_pod["metadata"]["uid"] != before_pod["metadata"]["uid"]
    mounted = any(v.get("persistentVolumeClaim", {}).get("claimName") == PVC_NAME
                  for v in after_pod["spec"]["volumes"])
    retained_ids, retained_events = matching_event(after_restart, "audit-pvc-before-restart")
    retained = len(before_ids) == 1 and retained_ids == before_ids
    lab.check("green", "The exact pre-restart auditID remains on the same bound PVC after receiver Pod recreation",
              retained and same_claim and replaced and mounted, {"pre_restart_unique_ids": len(before_ids),
                         "same_ids_still_present": retained,
                         "pvc_binding_unchanged": same_claim, "pod_replaced": replaced, "mounted_same_claim": mounted,
                         "retained_event_metadata_only": bool(retained_events) and all(
                             "requestObject" not in event and "responseObject" not in event
                             for event in retained_events)})
    retain_raw_ids(lab, "pvc-after-restart", {"audit-pvc-before-restart": after_restart})

    expected_new = create_marker(lab, "audit-pvc-after-restart")
    new_ids, new_events = wait_for_event(lab, "audit-pvc-after-restart")
    new_ok, new_summary = assert_delivery(lab, "audit-pvc-after-restart", new_events)
    lab.check("green", "The restarted PVC-backed receiver accepts a new real audit event",
              new_ok and new_ids == [expected_new] and new_ids != before_ids, new_summary | {
                  "new_event_id_distinct_from_prior": bool(new_ids) and new_ids != before_ids,
              })
    retain_raw_ids(lab, "pvc-after-new-delivery", {"audit-pvc-after-restart": new_events})
    (lab.evidence / "raw-audit-response-ids.json").write_text(json.dumps({
        "ephemeral": ephemeral_id, "pvc_before": expected_old, "pvc_after": expected_new,
    }, indent=2) + "\n")
