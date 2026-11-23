"""Bounded certificate mismatch and rollback drill for the disposable Kind node."""
import json
import re
import time


SCOPE = (
    "One fresh, single-node Kind v1.36.1 cluster using kubeadm-managed local PKI "
    "and stacked etcd. The case backs up the active etcd server certificate/key "
    "inside the disposable node, asks kubeadm to renew that leaf, temporarily "
    "combines the original certificate with the renewed private key, restarts etcd, "
    "and requires an explicit TLS key/certificate mismatch in etcd logs plus a "
    "failed verified health check. A node-local EXIT trap restores the original "
    "matching pair. The case then requires etcd health, API readiness, retention of "
    "a preexisting ConfigMap, and a new ConfigMap write/read. Private key bytes "
    "remain in the node. No host files, other nodes, external PKI, production "
    "clusters, or HA behavior are touched."
)

NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
RAW_FILE = "certificate-recovery.raw.json"


def node(lab, script, *, timeout=30):
    return lab.command(
        "docker", "exec", f"{lab.cluster}-control-plane", "sh", "-ceu", script,
        timeout=timeout,
    )


def record_raw(lab, observations):
    (lab.evidence / RAW_FILE).write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n")


def run(lab):
    version_doc = json.loads(lab.kubectl("version", "-o", "json").stdout)
    version = version_doc["serverVersion"]["gitVersion"]
    if version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {version}")

    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if len(nodes) != 1 or nodes[0]["status"]["nodeInfo"]["kubeletVersion"] != version:
        lab.block("Expected exactly one Kind node running the pinned Kubernetes version")

    marker = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "cert-recovery-before"},
        "data": {"marker": "stored-before-recovery-drill-v1"},
    }
    lab.create(marker)

    # The shell owns all certificate manipulation and its EXIT trap. Its only
    # output is a sanitized JSON receipt; key material is never emitted or read
    # outside the disposable control-plane container.
    script = r'''set -eu
umask 077
cert=/etc/kubernetes/pki/etcd/server.crt
key=/etc/kubernetes/pki/etcd/server.key
manifest=/etc/kubernetes/manifests/etcd.yaml
work="/tmp/saf-cert-recovery-$$"
held="$work/etcd.yaml.held"
mkdir -m 700 "$work"
cp "$cert" "$work/original.crt"
cp "$key" "$work/original.key"
armed=1
restore() {
  status=$?
  trap - EXIT HUP INT TERM
  if test "$armed" -eq 1; then
    cp "$work/original.crt" "$cert" 2>/dev/null || true
    cp "$work/original.key" "$key" 2>/dev/null || true
    if test -f "$held"; then mv "$held" "$manifest" 2>/dev/null || true; fi
  fi
  exit "$status"
}
trap restore EXIT HUP INT TERM
pub_cert() { openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}'; }
pub_key() { openssl pkey -in "$1" -pubout -outform DER | sha256sum | awk '{print $1}'; }
restart_etcd() {
  before="$(crictl ps -a --name '^etcd$' -q | head -n 1)"
  test -n "$before"
  test -f "$manifest"
  test ! -e "$held"
  mv "$manifest" "$held"
  i=0
  while test "$i" -lt 35; do
    if test -z "$(crictl ps --name '^etcd$' -q | head -n 1)"; then break; fi
    sleep 1; i=$((i + 1))
  done
  test -z "$(crictl ps --name '^etcd$' -q | head -n 1)"
  mv "$held" "$manifest"
  i=0
  while test "$i" -lt 60; do
  after="$(crictl ps -a --name '^etcd$' -q | head -n 1)"
    if test -n "$after" && test "$after" != "$before"; then return 0; fi
    sleep 1; i=$((i + 1))
  done
  return 1
}
health() {
  curl --max-time 3 --silent --show-error --fail \
    --cacert /etc/kubernetes/pki/etcd/ca.crt \
    --cert /etc/kubernetes/pki/etcd/healthcheck-client.crt \
    --key /etc/kubernetes/pki/etcd/healthcheck-client.key https://127.0.0.1:2379/health
}
health | grep -Eq '"health":[[:space:]]*"true"'
old_cert_pub="$(pub_cert "$work/original.crt")"
old_key_pub="$(pub_key "$work/original.key")"
test "$old_cert_pub" = "$old_key_pub"
old_fingerprint="$(openssl x509 -in "$work/original.crt" -noout -fingerprint -sha256 | sed 's/.*=//;s/://g' | tr 'A-F' 'a-f')"
kubeadm certs renew etcd-server >/dev/null
new_cert_pub="$(pub_cert "$cert")"
new_key_pub="$(pub_key "$key")"
test "$new_cert_pub" = "$new_key_pub"
new_fingerprint="$(openssl x509 -in "$cert" -noout -fingerprint -sha256 | sed 's/.*=//;s/://g' | tr 'A-F' 'a-f')"
test "$old_fingerprint" != "$new_fingerprint"
cp "$work/original.crt" "$cert"
staged_cert_pub="$(pub_cert "$cert")"
staged_key_pub="$(pub_key "$key")"
test "$staged_cert_pub" = "$old_cert_pub"
test "$staged_key_pub" = "$new_key_pub"
test "$staged_cert_pub" != "$staged_key_pub"
restart_etcd
seen_mismatch=0
for attempt in $(seq 1 20); do
  failed_id="$(crictl ps -a --name '^etcd$' -q | head -n 1)"
  if test -n "$failed_id" && crictl logs "$failed_id" 2>&1 | grep -F 'private key does not match public key' >/dev/null; then
    seen_mismatch=1
    break
  fi
  sleep 1
done
test "$seen_mismatch" -eq 1
if health >/dev/null 2>&1; then mismatch_health_failed=false; else mismatch_health_failed=true; fi
test "$mismatch_health_failed" = true
cp "$work/original.crt" "$cert"
cp "$work/original.key" "$key"
restored_cert_pub="$(pub_cert "$cert")"
restored_key_pub="$(pub_key "$key")"
test "$restored_cert_pub" = "$restored_key_pub"
test "$(openssl x509 -in "$cert" -noout -fingerprint -sha256 | sed 's/.*=//;s/://g' | tr 'A-F' 'a-f')" = "$old_fingerprint"
restart_etcd
i=0
healthy=false
while test "$i" -lt 60; do
  if health 2>/dev/null | grep -Eq '"health":[[:space:]]*"true"'; then healthy=true; break; fi
  sleep 1; i=$((i + 1))
done
test "$healthy" = true
armed=0
rm -rf "$work"
printf '{"original_pair_matched":true,"renewed_pair_matched":true,"renewed_certificate_changed":true,"staged_pair_mismatched":true,"etcd_log_named_key_certificate_mismatch":true,"verified_health_failed_during_mismatch":%s,"original_pair_restored":true,"etcd_health_after_restore":true}\n' "$mismatch_health_failed"'''

    result = node(lab, script, timeout=260)
    receipt = json.loads(result.stdout)
    lab.check(
        "red",
        "The incomplete replacement is rejected for a certificate/private-key mismatch and verified etcd health fails",
        receipt["staged_pair_mismatched"] and receipt["etcd_log_named_key_certificate_mismatch"]
        and receipt["verified_health_failed_during_mismatch"],
        {"staged_pair_mismatched": receipt["staged_pair_mismatched"],
         "etcd_log_named_key_certificate_mismatch": receipt["etcd_log_named_key_certificate_mismatch"],
         "verified_health_failed": receipt["verified_health_failed_during_mismatch"],
         "raw_evidence_file": RAW_FILE},
    )
    lab.check(
        "green",
        "The original matching certificate/key pair is restored and etcd health recovers",
        receipt["original_pair_restored"] and receipt["etcd_health_after_restore"],
        {"original_pair_restored": receipt["original_pair_restored"],
         "etcd_health_after_restore": receipt["etcd_health_after_restore"],
         "raw_evidence_file": RAW_FILE},
    )

    deadline = time.monotonic() + 75
    ready = False
    while time.monotonic() < deadline:
        response = lab.kubectl("get", "--raw=/readyz", timeout=10, allow_failure=True)
        if response.returncode == 0 and response.stdout.strip() == "ok":
            ready = True
            break
        time.sleep(1)
    if not ready:
        lab.block("API readiness did not recover after restoring the verified etcd pair")
    previous = json.loads(lab.kubectl("get", "configmap", "cert-recovery-before", "-o", "json").stdout)
    retained = previous.get("data") == marker["data"]
    permitted = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "cert-recovery-after", "labels": {"app.kubernetes.io/managed-by": "saf-k8s-lab"}},
        "data": {"marker": "synthetic-post-recovery-readback-v1"},
    }
    lab.create(permitted)
    readback = json.loads(lab.kubectl("get", "configmap", "cert-recovery-after", "-o", "json").stdout)
    write_read = readback.get("data") == permitted["data"]
    observations = {
        "tested_versions": {"kubernetes": version, "node_image": NODE_IMAGE},
        "certificate_operations": {
            "original_pair_matched_before_drill": receipt["original_pair_matched"],
            "renewed_pair_matched_before_staging": receipt["renewed_pair_matched"],
            "renewal_changed_public_certificate": receipt["renewed_certificate_changed"],
            "mismatched_pair_rejected_by_etcd": receipt["etcd_log_named_key_certificate_mismatch"],
            "health_failed_during_mismatch": receipt["verified_health_failed_during_mismatch"],
            "original_pair_restored": receipt["original_pair_restored"],
            "health_recovered": receipt["etcd_health_after_restore"],
        },
        "api_recovery": {"readyz_ok": ready, "preexisting_configmap_retained": retained,
                         "permitted_configmap_write_readback": write_read},
    }
    record_raw(lab, observations)
    lab.check(
        "positive",
        "The recovered control plane retains prior data and serves a permitted API write/read",
        ready and retained and write_read,
        {"readyz_ok": ready, "preexisting_object_retained": retained,
         "permitted_api_write_readback": write_read, "raw_evidence_file": RAW_FILE},
    )
