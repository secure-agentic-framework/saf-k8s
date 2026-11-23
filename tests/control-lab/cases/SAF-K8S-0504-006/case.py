"""Verify SPIRE-issued, independently bundle-checked and renewed local X.509 SVIDs."""
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
WORKLOAD_ID = "spiffe://saf.test/ns/saf-test/sa/saf-workload"
ENTRY_TTL = 120
MAX_VALIDITY = 135
SCOPE = (
    "One Kubernetes v1.36.1 Kind node, SPIRE 1.16.0 with projected token node attestation, and "
    "Kubernetes workload selectors over the authenticated kubelet endpoint. The Workload API "
    "denies issuance before registration, issues a verified short-lived credential to the "
    "registered workload, and delivers an updated lifetime for the same ID to its watcher. "
    "Production availability, mesh integration and cross-trust-domain federation need separate evidence."
)


def check_kubelet_serving_identity(lab):
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if len(nodes) != 1 or nodes[0]["metadata"]["name"] != f"{lab.cluster}-control-plane":
        lab.block("Expected only the harness-owned Kind node")
    node = nodes[0]["metadata"]["name"]
    address = next(item["address"] for item in nodes[0]["status"]["addresses"] if item["type"] == "InternalIP")
    deadline = time.monotonic() + 30
    while True:
        requests = json.loads(lab.kubectl("get", "csr", "-o", "json").stdout)["items"]
        candidates = [
            item for item in requests
            if item["spec"]["signerName"] == "kubernetes.io/kubelet-serving"
            and item["spec"]["username"] == f"system:node:{node}"
        ]
        if candidates:
            break
        if time.monotonic() >= deadline:
            lab.block("The owned node did not create a kubelet serving CSR")
        time.sleep(0.5)
    names = []
    for csr in candidates:
        details = lab.command(
            "openssl", "req", "-noout", "-verify", "-subject", "-nameopt", "RFC2253", "-text",
            payload=base64.b64decode(csr["spec"]["request"]).decode(),
        )
        endpoint_bound = f"IP Address:{address}" in details.stdout
        subject_bound = f"CN=system:node:{node}" in details.stdout
        if not endpoint_bound or not subject_bound or "server auth" not in csr["spec"]["usages"]:
            lab.block("The owned kubelet CSR did not match its authenticated endpoint")
        names.append(csr["metadata"]["name"])
    lab.kubectl("certificate", "approve", *names)
    deadline = time.monotonic() + 30
    while True:
        status = json.loads(lab.kubectl("get", "csr", *names, "-o", "json").stdout)
        requests = status.get("items", [status])
        if all(csr.get("status", {}).get("certificate") for csr in requests):
            break
        if time.monotonic() >= deadline:
            lab.block("The validated fixture kubelet serving requests were not signed")
        time.sleep(0.5)
    lab.check("positive", "The owned kubelet has a cluster-signed serving credential for its actual endpoint",
              True, {"valid_serving_signer": True, "owned_endpoint_in_csr": True})


def _server(lab, *args):
    return lab.kubectl("exec", "spire-server-0", "--", "/opt/spire/bin/spire-server", *args).stdout


def _agent_spiffe_id(lab):
    listing = _server(lab, "agent", "list")
    matches = set(re.findall(r"spiffe://saf\.test/spire/agent/k8s_psat/saf-local/[a-zA-Z0-9-]+", listing))
    if len(matches) != 1:
        lab.block("Expected exactly one locally attested SPIRE agent")
    return matches.pop()


def _register(lab, parent_id):
    _server(lab, "entry", "create", "-parentID", parent_id, "-spiffeID", WORKLOAD_ID,
            "-x509SVIDTTL", str(ENTRY_TTL), "-selector", "k8s:ns:saf-test",
            "-selector", "k8s:sa:saf-workload",
            "-selector", "k8s:pod-label:app:identity-positive",
            "-selector", "k8s:container-name:fetcher")


def _terminal(lab, pod, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        phase = json.loads(lab.kubectl("get", "pod", pod, "-o", "json").stdout)["status"]["phase"]
        if phase in {"Succeeded", "Failed"}:
            return phase
        if time.monotonic() >= deadline:
            lab.kubectl("describe", "pod", pod, allow_failure=True)
            lab.block(f"Owned Workload API fixture {pod} did not reach a terminal phase")
        time.sleep(1)


def _denied(lab, phase, label, claim):
    name = "identity-negative"
    spec = (FIXTURES / "negative.yaml").read_text().replace("app: identity-negative", f"app: {label}")
    lab.kubectl("apply", "-f", "-", payload=spec)
    status = _terminal(lab, name)
    response = lab.kubectl("logs", name, "-c", "fetcher").stdout.lower()
    denied = "permissiondenied" in response and "no identity issued" in response
    lab.check(phase, claim, status == "Failed" and denied,
              {"pod_exit_failed": status == "Failed", "workload_api_permission_denial": denied})
    lab.kubectl("delete", "pod", name, "--wait=true")


def _validate_issued(lab):
    lab.apply(FIXTURES / "positive.yaml")
    status = _terminal(lab, "identity-positive", timeout=80)
    if status != "Succeeded":
        lab.kubectl("logs", "identity-positive", "-c", "fetcher", allow_failure=True)
        lab.kubectl("logs", "identity-positive", "-c", "verifier", allow_failure=True)
        lab.block("The registered workload did not complete its credential verification")
    document = json.loads(lab.kubectl("logs", "identity-positive", "-c", "verifier").stdout)
    expected = {"spiffe_id": WORKLOAD_ID, "trusted_by_local_bundle": True, "valid_now": True,
                "short_lived": True, "local_tls_handshake": True, "private_material_logged": False}
    lab.check("positive", "The issued X.509-SVID has the intended URI and completes bundle-authenticated TLS",
              document == expected, document)
    return document


def _watch_updates(text):
    matches = re.findall(
        r"SPIFFE ID:\s+(\S+)\s+SVID Valid After:\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)[^\n]*\n"
        r"SVID Valid Until:\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)",
        text,
    )
    return [
        (identity, datetime.fromisoformat(start).replace(tzinfo=timezone.utc),
         datetime.fromisoformat(end).replace(tzinfo=timezone.utc))
        for identity, start, end in matches
    ]


def _renewal(lab):
    lab.apply(FIXTURES / "watch.yaml")
    deadline = time.monotonic() + 155
    while True:
        log = lab.kubectl("logs", "identity-watch", "-c", "fetcher", allow_failure=True)
        updates = _watch_updates(log.stdout)
        if (updates and updates[-1][2] > updates[0][2]) or time.monotonic() >= deadline:
            break
        time.sleep(3)
    stable = bool(updates) and all(identity == WORKLOAD_ID for identity, _, _ in updates)
    short = bool(updates) and all(0 < (end - start).total_seconds() <= MAX_VALIDITY
                                  for _, start, end in updates)
    extended = len(updates) > 1 and updates[-1][2] > updates[0][2]
    lab.check("green", "The same registered workload observes automatic SVID renewal",
              stable and short and extended,
              {"spiffe_id_stable": stable, "short_lifetime_retained": short,
               "newer_expiration_received": extended})
    return {"spiffe_id_stable": stable, "short_lifetime_retained": short, "newer_expiration_received": extended}


def run(lab):
    check_kubelet_serving_identity(lab)
    lab.apply(FIXTURES / "spire.yaml")
    result = lab.kubectl("wait", "--for=condition=Ready", "pod/spire-server-0",
                         "--timeout=50s", timeout=60, allow_failure=True)
    if result.returncode != 0:
        lab.kubectl("describe", "pod", "spire-server-0", allow_failure=True)
        lab.kubectl("logs", "spire-server-0", "-c", "server", allow_failure=True)
        lab.block("The test SPIRE server did not start")
    bundle = _server(lab, "bundle", "show", "-format", "pem")
    if "BEGIN CERTIFICATE" not in bundle:
        lab.block("The local SPIRE Server did not provide its public trust bundle")
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "spire-agent-bootstrap"}, "data": {"bundle.pem": bundle},
    })
    lab.apply(FIXTURES / "agent.yaml")
    result = lab.kubectl("rollout", "status", "daemonset/spire-agent", "--timeout=55s",
                         timeout=65, allow_failure=True)
    if result.returncode != 0:
        lab.kubectl("describe", "pods", "-l", "app=spire-agent", allow_failure=True)
        lab.kubectl("logs", "daemonset/spire-agent", "-c", "agent", allow_failure=True)
        lab.block("The test SPIRE agent did not finish attestation")
    parent = _agent_spiffe_id(lab)
    _denied(lab, "red", "identity-positive", "The same selected workload is denied before its registration exists")
    _register(lab, parent)
    issued = _validate_issued(lab)
    _denied(lab, "green", "identity-negative", "An independent unregistered workload still receives no identity")
    renewed = _renewal(lab)
    (lab.evidence / "svid-observations.json").write_text(
        json.dumps({"issued": issued, "renewed": renewed}, indent=2, sort_keys=True) + "\n"
    )
