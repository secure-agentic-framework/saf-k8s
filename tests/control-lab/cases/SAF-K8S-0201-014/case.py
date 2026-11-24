"""Verify native serving-CSR approval, exact TLS identity and expiry replacement."""
import base64
from datetime import datetime, timezone
from ipaddress import ip_address
import json
from pathlib import Path
import re
import ssl
import subprocess
import time

from fixtures import container, pod, ready

SIGNER = "kubernetes.io/kubelet-serving"
CA = "/etc/kubernetes/pki/ca.crt"
UNRELATED_CA = "/etc/kubernetes/pki/front-proxy-ca.crt"
CERTIFICATE = rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
SERVER_USAGES = {"digital signature", "server auth"}
SERVER_RSA_USAGES = SERVER_USAGES | {"key encipherment"}
SCOPE = (
    "A disposable v1.36.1 control-plane node using native serving TLS bootstrap, "
    "fixture approval of the exact authenticated node and SANs, and controller-manager signing. "
    "Checks pre-approval trust, verified endpoint, pre-expiry replacement, TTL monotonicity, "
    "API-server validated logs, and offline name, CA and expiry rejection."
)


def output(lab, args, *, payload=None, timeout=15):
    # Raw CSR protocol data and public PEM stay outside the retained command logs.
    return subprocess.run(args, input=payload, capture_output=True, env=lab.env, timeout=timeout)


def kube(lab, *args):
    result = output(lab, [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--request-timeout=8s", *args,
    ])
    if result.returncode:
        lab.block("Could not observe the selected certificate or metric on the owned Kubernetes API")
    return result.stdout


def ssl_in_node(lab, node, *args, payload=b""):
    return output(lab, ["docker", "exec", "-i", node, "openssl", *args], payload=payload)


def wait(lab, poll, label, seconds):
    stop = time.monotonic() + seconds
    while time.monotonic() < stop:
        found = poll()
        if found:
            return found
        time.sleep(2)
    lab.block(f"Timed out observing {label}")


def requests(lab, node):
    objects = json.loads(kube(lab, "get", "csr", "-o", "json"))["items"]
    identity = f"system:node:{node}"
    return [item for item in objects if item["spec"]["signerName"] == SIGNER
            and item["spec"]["username"] == identity and "system:nodes" in item["spec"]["groups"]]


def is_pending(item):
    return not item.get("status", {}).get("certificate") and not item.get("status", {}).get("conditions")


def approved_certificate(item):
    status = item.get("status", {})
    if (status.get("certificate") and any(
            row["type"] == "Approved" and row["status"] == "True" for row in status.get("conditions", []))):
        return base64.b64decode(status["certificate"], validate=True)
    return None


def request_identity(lab, node, item):
    data = base64.b64decode(item["spec"]["request"], validate=True)
    result = ssl_in_node(lab, node, "req", "-verify", "-noout", "-subject", "-nameopt", "RFC2253",
                         "-text", payload=data)
    if result.returncode:
        lab.block("The exact fixture serving CSR did not have a valid request signature")
    decoded = result.stdout.decode()
    subject = re.search(r"(?m)^subject\s*=\s*(.+)$", decoded)
    san = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)", decoded)
    if not subject or not san:
        lab.block("The exact fixture serving CSR has no parseable subject or SAN")
    return set(subject[1].split(",")), {name.strip() for name in san[1].split(",")}


def approved_identity(node, candidate, subject, request_sans, expected_sans):
    spec = candidate["spec"]
    return (spec["signerName"] == SIGNER and spec["username"] == f"system:node:{node}"
            and "system:nodes" in spec["groups"] and set(spec["usages"]) in (SERVER_USAGES, SERVER_RSA_USAGES)
            and subject == {f"CN=system:node:{node}", "O=system:nodes"} and request_sans == expected_sans)


def approve(lab, node, candidate, sans):
    subject, request_sans = request_identity(lab, node, candidate)
    matched = approved_identity(node, candidate, subject, request_sans, sans)
    wrong_dns = approved_identity(node, candidate, subject, request_sans | {"DNS:unexpected.test"}, sans)
    lab.check("green", "The controlled approver binds the exact authenticated node, usage and complete SAN set",
              matched and not wrong_dns, {"exact_identity_and_sans": matched, "unexpected_san_denied": not wrong_dns})
    name = candidate["metadata"]["name"]
    uid = candidate["metadata"]["uid"]
    lab.kubectl("certificate", "approve", name)
    cert = wait(lab, lambda: next((value for row in requests(lab, node)
                                  if row["metadata"]["uid"] == uid and (value := approved_certificate(row))), None),
                "the exact approved and signed serving CSR", 30)
    return cert


def handshake(lab, node):
    return ssl_in_node(lab, node, "s_client", "-connect", "127.0.0.1:10250",
                       "-servername", node, "-verify_hostname", node, "-verify_return_error",
                       "-showcerts", "-CAfile", CA)


def trusted_leaf(lab, node, certificate):
    result = handshake(lab, node)
    found = re.search(CERTIFICATE, result.stdout, re.S)
    if result.returncode == 0 and b"Verify return code: 0 (ok)" in result.stdout and found:
        expected = ssl.PEM_cert_to_DER_cert(certificate.decode())
        actual = ssl.PEM_cert_to_DER_cert(found[0].decode())
        return found[0] if actual == expected else None
    return None


def expires(lab, node, certificate):
    response = ssl_in_node(lab, node, "x509", "-enddate", "-noout", payload=certificate + b"\n")
    if response.returncode:
        lab.block("The observed serving certificate did not have a usable expiry")
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(response.stdout.decode().strip().split("=", 1)[1]),
                                  timezone.utc)


def server_ttl(lab, node):
    raw = kube(lab, "get", f"--raw=/api/v1/nodes/{node}/proxy/metrics")
    sample = re.search(rb"(?m)^kubelet_certificate_manager_server_ttl_seconds ([0-9.]+(?:e[+\-]?\d+)?)$", raw)
    return float(sample[1]) if sample else None


def verify_offline(lab, node, leaf, expiry):
    tests = (
        ("wrong_ca", b"unable to get local issuer", ["-CAfile", UNRELATED_CA, "-verify_hostname", node]),
        ("wrong_dns", b"hostname mismatch", ["-CAfile", CA, "-verify_hostname", "unrelated.example.test"]),
        ("expired", b"certificate has expired",
         ["-CAfile", CA, "-verify_hostname", node, "-attime", str(int(expiry.timestamp()) + 1)]),
    )
    for label, error, args in tests:
        result = ssl_in_node(lab, node, "verify", "-purpose", "sslserver", *args, "/dev/stdin", payload=leaf + b"\n")
        lab.check("red", f"The offline verifier rejects the public leaf for {label}",
                  result.returncode != 0 and error in result.stdout + result.stderr,
                  {"expected_validation_failure": result.returncode != 0 and error in result.stdout + result.stderr})


def protected_logs(lab, node):
    marker = "saf-own-certificate-trusted-logs"
    name = "saf-tls-logs"
    lab.create(pod(name, [container("marker", command=["sh", "-c", f"echo {marker}; exec sleep 120"])],
                   nodeName=node, automountServiceAccountToken=False))
    ready(lab, name)
    logs = lab.kubectl("logs", name).stdout.strip()
    return logs == marker


def run(lab):
    node = f"{lab.cluster}-control-plane"
    node_obj = json.loads(kube(lab, "get", "node", node, "-o", "json"))
    addresses = node_obj["status"]["addresses"]
    sans = {f"DNS:{row['address']}" for row in addresses if row["type"] in {"Hostname", "InternalDNS", "ExternalDNS"}}
    sans |= {f"IP Address:{ip_address(row['address'])}" for row in addresses
             if row["type"] in {"InternalIP", "ExternalIP"}}
    if f"DNS:{node}" not in sans or not any(value.startswith("IP Address:") for value in sans):
        lab.block("The fixture must have both the registered DNS and IP SANs")
    # kubeadm may leave a CSR from an earlier invocation. Tie the first
    # decision to a new manager attempt observed on this disposable node.
    known = {row["metadata"]["uid"] for row in requests(lab, node)}
    started = lab.command("docker", "exec", node, "systemctl", "show", "kubelet.service",
                          "--property=InvocationID", "--value").stdout.strip()
    lab.command("docker", "exec", node, "systemctl", "restart", "kubelet.service", timeout=45)
    active = lab.command("docker", "exec", node, "systemctl", "show", "kubelet.service",
                         "--property=InvocationID", "--value").stdout.strip()
    if not active or active == started:
        lab.block("The serving fixture could not observe a new kubelet invocation")
    first = wait(lab, lambda: next((row for row in requests(lab, node)
                                    if is_pending(row) and row["metadata"]["uid"] not in known), None),
                 "a pending serving CSR from the new invocation", 60)
    initial_tls = handshake(lab, node)
    pending_unissued = any(is_pending(row) and row["metadata"]["uid"] == first["metadata"]["uid"]
                          for row in requests(lab, node))
    absent = (initial_tls.returncode != 0 and b"CONNECTED" in initial_tls.stdout
              and b"no peer certificate available" in initial_tls.stdout)
    lab.check("red", "The connected kubelet has no trusted leaf while its native serving CSR remains pending",
              pending_unissued and absent, {"pending_unsigned": pending_unissued, "peer_leaf_absent": absent})
    first_approval_started = datetime.now(timezone.utc).replace(microsecond=0)
    initial_pem = approve(lab, node, first, sans)
    first_leaf = wait(lab, lambda: trusted_leaf(lab, node, initial_pem),
                      "live first leaf signed by the expected CA and identity", 35)
    first_expiry = expires(lab, node, first_leaf)
    starting_ttl = server_ttl(lab, node)
    lab.check("positive", "The signed leaf is served live and the API-server verified kubelet metrics path reports a TTL",
              starting_ttl is not None and 75 < starting_ttl <= 151,
              {"initial_leaf_ca_and_dns_match": bool(first_leaf), "finite_initial_native_ttl": starting_ttl is not None
               and 75 < starting_ttl <= 151})
    verify_offline(lab, node, first_leaf, first_expiry)

    uid = first["metadata"]["uid"]

    def pending_inside_window():
        ttl = server_ttl(lab, node)
        if ttl is None or not 0 < ttl < 75:
            return None
        for row in requests(lab, node):
            meta = row["metadata"]
            submitted = datetime.fromisoformat(meta["creationTimestamp"].replace("Z", "+00:00"))
            if meta["uid"] != uid and meta["uid"] not in known and submitted >= first_approval_started and is_pending(row):
                return row, ttl
        return None

    second, low_ttl = wait(lab, pending_inside_window,
                           "a native replacement CSR and the active certificate's warning window", 145)
    old_still_live = trusted_leaf(lab, node, initial_pem)
    lab.check("red", "The native TTL crosses the rehearsal threshold while the unsigned replacement is pending",
              old_still_live and 0 < low_ttl < 75,
              {"first_cert_still_trusted": bool(old_still_live), "near_expiry_observed": 0 < low_ttl < 75})
    renewed_pem = approve(lab, node, second, sans)
    second_leaf = wait(lab, lambda: trusted_leaf(lab, node, renewed_pem),
                       "live replacement signed by the expected CA and identity", 25)
    replaced_pre_expiry = datetime.now(timezone.utc) < first_expiry
    expires_later = expires(lab, node, second_leaf) > first_expiry
    new_ttl = server_ttl(lab, node)
    was_replaced = second_leaf != first_leaf and replaced_pre_expiry and expires_later and new_ttl is not None and new_ttl > 75
    lab.check("green", "A different signed leaf replaces the first before expiry and resets its native TTL",
              was_replaced, {"renewed_before_expiry": replaced_pre_expiry, "expiry_extended": expires_later,
                             "native_ttl_returned_above_rehearsal_floor": new_ttl is not None and new_ttl > 75})
    remaining = (first_expiry - datetime.now(timezone.utc)).total_seconds()
    if remaining > 0:
        time.sleep(remaining + 1)
    post_expiry = bool(trusted_leaf(lab, node, renewed_pem))
    logs = protected_logs(lab, node)
    lab.check("positive", "After original expiry the replacement remains trusted and the API server retrieves live workload logs",
              post_expiry and logs, {"same_replacement_still_served": post_expiry, "api_server_fetches_expected_logs": logs})
    (lab.evidence / "kubelet-serving-lifecycle.json").write_text(json.dumps({
        "signer": SIGNER, "new_kubelet_invocation_observed": active != started, "first_csr_uid": uid, "renewal_csr_uid": second["metadata"]["uid"],
        "first_ttl": starting_ttl, "pre_renewal_ttl": low_ttl, "post_renewal_ttl": new_ttl,
        "replacement_before_expiry": replaced_pre_expiry, "replacement_trusted_after_original_expiry": post_expiry,
        "verified_api_server_logs": logs,
    }, indent=2) + "\n")
