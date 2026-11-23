"""Exercise kubeadm-managed stacked-etcd leaf certificate renewal in disposable Kind."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shlex
import time


SCOPE = (
    "One disposable Kind v1.36.1 control-plane node using kubeadm's local PKI and stacked etcd. "
    "The case detects a partial renewal, completes kubeadm "
    "certificate renewal, restarts the etcd and kube-apiserver static Pods, compares public "
    "certificate receipts before/after and live etcd server/peer receipts to renewed files, "
    "then writes and reads back a synthetic ConfigMap through the Kubernetes API. "
    "No private key, token, secret value, external PKI, multi-member behavior, scheduled "
    "rotation, or production cluster is exercised."
)

NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
CERTS = {
    "etcd/server": "/etc/kubernetes/pki/etcd/server.crt",
    "etcd/peer": "/etc/kubernetes/pki/etcd/peer.crt",
    "apiserver-etcd-client": "/etc/kubernetes/pki/apiserver-etcd-client.crt",
}
EXPECTED_EKU = {
    "etcd/server": "TLS Web Server Authentication,TLS Web Client Authentication",
    "etcd/peer": "TLS Web Server Authentication,TLS Web Client Authentication",
    "apiserver-etcd-client": "TLS Web Client Authentication",
}
RAW_FILE = "certificate-rotation.raw.json"


def node(lab, script, *, timeout=30):
    return lab.command("docker", "exec", f"{lab.cluster}-control-plane", "sh", "-ceu", script,
                       timeout=timeout)


def parse_receipt(name, output):
    fingerprint = re.search(r"(?:sha256 )?Fingerprint=([0-9A-Fa-f:]+)", output)
    serial = re.search(r"^serial=([0-9A-Fa-f]+)$", output, re.M)
    start = re.search(r"^notBefore=(.+)$", output, re.M)
    end = re.search(r"^notAfter=(.+)$", output, re.M)
    if not all((fingerprint, serial, start, end)):
        raise RuntimeError(f"Could not parse public certificate receipt for {name}")
    extensions = {"keyUsage": "", "extendedKeyUsage": ""}
    active = None
    for line in output.splitlines():
        if line.strip().startswith("X509v3 Key Usage:"):
            active = "keyUsage"
        elif line.strip().startswith("X509v3 Extended Key Usage:"):
            active = "extendedKeyUsage"
        elif line.strip().startswith("X509v3 "):
            active = None
        elif active and line.strip():
            extensions[active] += line.strip()
    if not all(extensions.values()):
        raise RuntimeError(f"Certificate usage flags missing for {name}")
    return {
        "class": name,
        "sha256_fingerprint": fingerprint.group(1).replace(":", "").lower(),
        "serial": serial.group(1).lower().lstrip("0") or "0",
        "not_before": start.group(1),
        "not_after": end.group(1),
        "key_usage": extensions["keyUsage"].replace(", ", ","),
        "extended_key_usage": extensions["extendedKeyUsage"].replace(", ", ","),
    }


def public_receipts(lab):
    receipts = {}
    for name, path in CERTS.items():
        # openssl x509 reads only the public certificate; no key file is opened or emitted.
        output = node(
            lab,
            f"openssl x509 -in {shlex.quote(path)} -noout -fingerprint -sha256 "
            "-serial -startdate -enddate -ext keyUsage,extendedKeyUsage",
        ).stdout
        receipts[name] = parse_receipt(name, output)
    return receipts


def expiry_epoch(value):
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    ).timestamp()


def active_fingerprint(lab, address, port, client_cert, client_key):
    command = (
        "timeout 8 openssl s_client "
        f"-connect {shlex.quote(address)}:{port} -verify_ip {shlex.quote(address)} "
        "-verify_return_error -CAfile /etc/kubernetes/pki/etcd/ca.crt "
        f"-cert {client_cert} -key {client_key} -showcerts </dev/null 2>/dev/null "
        "| openssl x509 -noout -fingerprint -sha256"
    )
    result = node(lab, command, timeout=15)
    match = re.search(r"(?:sha256 )?Fingerprint=([0-9A-Fa-f:]+)", result.stdout)
    if not match:
        raise RuntimeError(f"No active TLS certificate observed on etcd port {port}")
    return match.group(1).replace(":", "").lower()


def restart_static_pod(lab, manifest, container_name):
    script = r'''manifest="$1"
name="$2"
held="/tmp/saf-rotation-$(basename "$manifest").held"
test -f "$manifest"
test ! -e "$held"
before="$(crictl ps --name "$name" -q | head -n 1)"
test -n "$before"
restore() { if test -f "$held"; then mv "$held" "$manifest"; fi; }
trap restore EXIT HUP INT TERM
mv "$manifest" "$held"
gone=0
i=0
while test "$i" -lt 45; do
  if test -z "$(crictl ps --name "$name" -q | head -n 1)"; then gone=1; break; fi
  sleep 1
  i=$((i + 1))
done
test "$gone" -eq 1
mv "$held" "$manifest"
trap - EXIT HUP INT TERM
i=0
while test "$i" -lt 90; do
  after="$(crictl ps --name "$name" -q | head -n 1)"
  if test -n "$after" && test "$after" != "$before"; then
    printf 'restarted\n'
    exit 0
  fi
  sleep 1
  i=$((i + 1))
done
exit 1'''
    result = lab.command(
        "docker", "exec", f"{lab.cluster}-control-plane", "sh", "-ceu", script,
        "sh", manifest, container_name,
        timeout=150,
    )
    return "restarted" in result.stdout


def record_raw(lab, observations):
    (lab.evidence / RAW_FILE).write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n")


def run(lab):
    # Ensure the harness really supplied the one-node, exact-version target expected here.
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    if version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {version}")
    node_version = node(lab, "kubeadm version -o short").stdout.strip()
    if node_version != "v1.36.1":
        lab.block(f"Expected kubeadm v1.36.1, got {node_version}")
    ready_nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if len(ready_nodes) != 1 or ready_nodes[0]["status"]["nodeInfo"]["kubeletVersion"] != version:
        lab.block("Expected exactly one ready-version node in the disposable Kind cluster")

    before = public_receipts(lab)
    required = set(CERTS)

    marker = {"apiVersion": "v1", "kind": "ConfigMap",
              "metadata": {"name": "cert-rotation-before"},
              "data": {"marker": "stored-before-renewal"}}
    lab.create(marker)

    # Detect the coverage gap without putting partially renewed files in service.
    first = node(lab, "kubeadm certs renew etcd-server && kubeadm certs renew apiserver-etcd-client",
                 timeout=90)
    incomplete = public_receipts(lab)
    unchanged = sorted(name for name in required if
                       before[name]["sha256_fingerprint"] == incomplete[name]["sha256_fingerprint"])
    lab.check(
        "red",
        "The live certificate audit detects that the partial renewal omitted the peer class",
        unchanged == ["etcd/peer"],
        {"required_classes": sorted(required), "unchanged_after_partial_renewal": unchanged},
    )
    renewal = node(lab, "kubeadm certs renew etcd-peer", timeout=90)
    after = public_receipts(lab)
    now = time.time()
    per_class = {}
    for name in sorted(required):
        old, new = before[name], after[name]
        per_class[name] = {
            "fingerprint_changed": old["sha256_fingerprint"] != new["sha256_fingerprint"],
            "serial_changed": old["serial"] != new["serial"],
            "expiry_extended": expiry_epoch(new["not_after"]) > expiry_epoch(old["not_after"]),
            "new_certificate_current": expiry_epoch(new["not_before"]) <= now < expiry_epoch(new["not_after"]),
            "usage_flags_preserved": (old["key_usage"], old["extended_key_usage"])
            == (new["key_usage"], new["extended_key_usage"]),
            "extended_key_usage_matches_role": set(part.strip() for part in new["extended_key_usage"].split(",")) == set(EXPECTED_EKU[name].split(",")),
        }
    disk_comparison_ok = all(all(result.values()) for result in per_class.values())
    if set(after) != required or set(before) != required:
        disk_comparison_ok = False
    lab.check(
        "green",
        "The completed kubeadm renewal replaces all three public leaf receipts and preserves their usage flags",
        disk_comparison_ok,
        {"all_required_classes_compared": set(after) == required and set(before) == required,
         "all_fingerprints_and_serials_changed": all(x["fingerprint_changed"] and x["serial_changed"] for x in per_class.values()),
         "all_expiries_extended_and_current": all(x["expiry_extended"] and x["new_certificate_current"] for x in per_class.values()),
         "all_usage_flags_preserved": all(x["usage_flags_preserved"] for x in per_class.values()),
         "all_extended_key_usages_match_roles": all(x["extended_key_usage_matches_role"] for x in per_class.values()),
         "raw_evidence_file": RAW_FILE},
    )

    etcd_restarted = restart_static_pod(lab, "/etc/kubernetes/manifests/etcd.yaml", "etcd")
    apiserver_restarted = restart_static_pod(
        lab, "/etc/kubernetes/manifests/kube-apiserver.yaml", "kube-apiserver"
    )
    deadline = time.monotonic() + 65
    while time.monotonic() < deadline:
        ready = lab.kubectl("get", "--raw=/readyz", timeout=10, allow_failure=True)
        if ready.returncode == 0 and ready.stdout.strip() == "ok":
            break
        time.sleep(1)
    else:
        lab.block("Restarted control plane did not become Ready")

    node_ip = next(value["address"] for value in ready_nodes[0]["status"]["addresses"]
                   if value["type"] == "InternalIP")

    active_server = active_fingerprint(
        lab, "127.0.0.1", 2379, "/etc/kubernetes/pki/etcd/healthcheck-client.crt",
        "/etc/kubernetes/pki/etcd/healthcheck-client.key",
    )
    active_peer = active_fingerprint(
        lab, node_ip, 2380, "/etc/kubernetes/pki/etcd/peer.crt", "/etc/kubernetes/pki/etcd/peer.key"
    )
    active_comparison = {
        "etcd/server": active_server == after["etcd/server"]["sha256_fingerprint"],
        "etcd/peer": active_peer == after["etcd/peer"]["sha256_fingerprint"],
    }

    # The API write/read exercises the restarted apiserver's etcd client path. The
    # manifest reference check ties that running path to the renewed public client cert.
    manifest_refs_client = node(
        lab,
        "grep -F -- '--etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt' "
        "/etc/kubernetes/manifests/kube-apiserver.yaml >/dev/null",
    )
    previous = json.loads(lab.kubectl("get", "configmap", "cert-rotation-before", "-o", "json").stdout)
    retained = previous.get("data") == marker["data"]
    name = "cert-rotation-after"
    payload = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "labels": {"app.kubernetes.io/managed-by": "saf-k8s-lab"}},
        "data": {"marker": "synthetic-post-rotation-readback-v1"},
    }
    lab.create(payload)
    readback = json.loads(lab.kubectl("get", "configmap", name, "-o", "json").stdout)
    data_ok = readback.get("data") == payload["data"]
    positive = (
        etcd_restarted and apiserver_restarted and all(active_comparison.values())
        and manifest_refs_client.returncode == 0 and data_ok and retained
    )
    lab.check(
        "positive",
        "Restarted etcd serves renewed server and peer certs, and the restarted apiserver stores and reads permitted data",
        positive,
        {"etcd_static_pod_restarted": etcd_restarted,
         "apiserver_static_pod_restarted": apiserver_restarted,
         "active_server_and_peer_match_renewed_receipts": active_comparison,
         "apiserver_manifest_references_renewed_client_cert_path": manifest_refs_client.returncode == 0,
         "permitted_api_write_readback": data_ok,
         "preexisting_data_retained": retained,
         "raw_evidence_file": RAW_FILE},
    )

    record_raw(lab, {
        "tested_versions": {"kubernetes": version, "kubeadm": node_version,
                            "node_image": NODE_IMAGE},
        "certificate_receipts_before": before,
        "certificate_receipts_after_partial_renewal": incomplete,
        "certificate_receipts_after": after,
        "disk_receipt_comparisons": per_class,
        "active_etcd_receipts": {"etcd/server": active_server, "etcd/peer": active_peer},
        "active_receipt_comparisons": active_comparison,
        "restart_and_api": {"etcd_static_pod_restarted": etcd_restarted,
                             "apiserver_static_pod_restarted": apiserver_restarted,
                             "apiserver_client_certificate_path_referenced": True,
                             "synthetic_configmap_data_readback": data_ok},
        "renewal_output": first.stdout.strip() + "\n" + renewal.stdout.strip(),
    })
