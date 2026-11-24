"""Policy counterfactuals and live kubeadm worker client certificate renewal."""
import base64
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
from runpy import run_path
import re
import ssl
import subprocess
import tempfile
import time

FIXTURES = Path(__file__).resolve().parent / "fixtures.json"
CLIENT_SIGNER = "kubernetes.io/kube-apiserver-client-kubelet"
SCOPE = "Native kubeadm worker client-certificate bootstrap and renewal with paired rotation-enabled and rotation-disabled workers; first kubeadm control-plane seed replacement, post-expiry Lease and restoration; shortened disposable-fixture certificate lifetime."
CONTROL_PLANE = run_path(str(Path(__file__).with_name("control_plane.py")))
CERTIFICATE_TTL = timedelta(seconds=150)
METRIC_TTL = "kubelet_certificate_manager_client_ttl_seconds"
METRIC_RENEW_ERRORS = "kubelet_certificate_manager_client_expiration_renew_errors"


def policy_findings(policy):
    findings = []
    bootstrap = policy.get("bootstrap", {})
    rotation = policy.get("client_rotation", {})
    signer = policy.get("signer", {})
    if bootstrap.get("bootstrap_identity_group") != "system:bootstrappers":
        findings.append("bootstrap identity is not system:bootstrappers")
    if not bootstrap.get("can_create_and_retrieve_csr"):
        findings.append("bootstrap identity lacks CSR create/retrieve authorization")
    if bootstrap.get("signer_name") != CLIENT_SIGNER:
        findings.append("bootstrap CSR uses the wrong signer")
    if bootstrap.get("approval_path") not in ("automatic", "manual_or_external"):
        findings.append("bootstrap CSR has no approval path")
    if not rotation.get("rotate_certificates"):
        findings.append("client certificate rotation is disabled")
    if rotation.get("renewal_identity_group") != "system:nodes":
        findings.append("renewal identity is not system:nodes")
    if rotation.get("renewal_approval") not in ("automatic", "manual_or_external"):
        findings.append("renewal CSR has no approval path")
    if rotation.get("signer_name") != CLIENT_SIGNER:
        findings.append("renewal CSR uses the wrong signer")
    if not signer.get("controller_manager_signing_enabled"):
        findings.append("controller-manager signing is not enabled")
    if not signer.get("signing_ca_trusted_by_api_server"):
        findings.append("signing CA is not trusted for client authentication")
    return findings


def check_synthetic_fixtures(reporter):
    cases = json.loads(FIXTURES.read_text())["rotation_policy_counterfactual"]
    red = policy_findings(cases["red"])
    reporter.check("red", "Counterfactual detects disabled rotation, wrong signer, missing approval",
                   len(red) >= 4 and any("disabled" in x for x in red)
                   and any("signer" in x for x in red) and any("approval" in x for x in red), red)
    green = policy_findings(cases["green"])
    reporter.check("green", "Documented bootstrap and client renewal policy is accepted",
                   green == [], green)


def node_csrs(lab, node):
    # Cluster-owned bootstrap CSR payloads and metadata stay in memory.
    data = json.loads(kubectl_capture(lab, "get", "certificatesigningrequests", "-o", "json"))
    identity = f"system:node:{node}"
    for item in data["items"]:
        spec = item["spec"]
        if spec["signerName"] != CLIENT_SIGNER:
            continue
        username, groups = spec.get("username", ""), spec.get("groups", [])
        is_bootstrap = "system:bootstrappers" in groups and username.startswith("system:bootstrap:")
        if is_bootstrap:
            request = base64.b64decode(spec["request"], validate=True)
            info = subprocess.run(["openssl", "req", "-noout", "-subject", "-nameopt", "RFC2253"],
                                  input=request, capture_output=True, timeout=5)
            subject = info.stdout.decode().strip().partition("=")[2].strip()
            if info.returncode or set(subject.split(",")) != {f"CN={identity}", "O=system:nodes"}:
                continue
            yield item, True
        elif "system:nodes" in groups and username == identity:
            yield item, False


def worker_certificates(lab, worker):
    bootstrap, renewals = [], []
    identity = f"system:node:{worker}"
    for csr, from_bootstrap in node_csrs(lab, worker):
        status = csr.get("status", {})
        if not status.get("certificate") or not any(
                item["type"] == "Approved" and item["status"] == "True"
                for item in status.get("conditions", [])):
            continue
        certificate = base64.b64decode(status["certificate"], validate=True)
        details, chain_valid = verify_public_certificate(lab, certificate)
        fields = dict(line.split("=", 1) for line in details.stdout.decode().splitlines())
        if set(fields["subject"].strip().split(",")) != {f"CN={identity}", "O=system:nodes"}:
            lab.block("An approved owned request issued a certificate with the wrong node subject")
        expiry = datetime.strptime(fields["notAfter"], "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
        (bootstrap if from_bootstrap else renewals).append(
            (expiry, fields["issuer"], fields["serial"], chain_valid))
    return sorted(bootstrap), sorted(renewals)


def run_capture(args, lab, timeout=8):
    try:
        result = subprocess.run(args, capture_output=True, env=lab.env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        lab.block(f"Owned-cluster read failed: {type(error).__name__}")
    if result.returncode:
        lab.block("Owned-cluster read did not succeed")
    return result.stdout


def kubectl_capture(lab, *args, timeout=20):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               f"--request-timeout={timeout - 2}s", *args]
    return run_capture(command, lab, timeout=timeout)


def client_ca_anchor(lab):
    cached = getattr(lab, "_client_ca_anchor", None)
    if cached is not None:
        return cached
    container = f"{lab.cluster}-control-plane"
    manifest = run_capture(["docker", "exec", container,
                            "cat", "/etc/kubernetes/manifests/kube-apiserver.yaml"], lab)
    text = manifest.decode("utf-8", errors="strict")
    match = re.search(r"--client-ca-file=(/etc/kubernetes/pki/[A-Za-z0-9._-]+)(?:\s|\n)", text)
    if not match:
        lab.block("Could not identify the API server client CA file in the owned control-plane manifest")
    anchor = run_capture(["docker", "exec", container, "cat", match.group(1)], lab)
    if b"-----BEGIN CERTIFICATE-----" not in anchor:
        lab.block("API server client CA anchor was not a public certificate")
    lab._client_ca_anchor = anchor
    return anchor


def verify_public_certificate(lab, certificate):
    """Parse public CSR status data and verify it to the API server client CA."""
    anchor = client_ca_anchor(lab)
    with tempfile.TemporaryDirectory(prefix="saf-k8s-public-cert-") as directory:
        cert_path = Path(directory) / "status-certificate.pem"
        ca_path = Path(directory) / "client-ca.pem"
        cert_path.write_bytes(certificate)
        ca_path.write_bytes(anchor)
        details = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-serial", "-enddate",
             "-nameopt", "RFC2253"], input=certificate, capture_output=True, timeout=5)
        if details.returncode:
            lab.block("The owned public CSR status certificate could not be parsed")
        fields = dict(line.split("=", 1) for line in details.stdout.decode().splitlines())
        # Verify historical leaves inside their original validity window. Actual
        # expiry and continuity are assessed separately using wall time and leases.
        verify_at = min(int(time.time()), int(ssl.cert_time_to_seconds(fields["notAfter"])) - 1)
        verified = subprocess.run(["openssl", "verify", "-attime", str(verify_at), "-purpose", "sslclient",
                                   "-CAfile", str(ca_path), str(cert_path)], capture_output=True, timeout=5)
    if verified.returncode:
        lab.block("Public CSR status certificate did not parse or chain to the API server client CA")
    return details, True


def kubelet_config(lab, node):
    result = kubectl_capture(lab, "get", "--raw", f"/api/v1/nodes/{node}/proxy/configz")
    try:
        return json.loads(result)["kubeletconfig"]
    except (ValueError, KeyError, TypeError):
        lab.block(f"Effective kubelet configz was unavailable for {node}")


def kubelet_metrics(lab, node, *, restarting=False):
    route = f"/api/v1/nodes/{node}/proxy/metrics"
    if restarting:
        command = ["kubectl", "--kubeconfig", str(lab.kubeconfig),
                   "--context", f"kind-{lab.cluster}", "--request-timeout=5s", "get", "--raw", route]
        result = subprocess.run(command, capture_output=True, env=lab.env, timeout=8)
        if result.returncode:
            if any(reason in result.stderr for reason in
                   (b"connection refused", b"ServiceUnavailable", b"connection reset by peer")):
                return {}
            lab.block("The seeded control-plane metric request failed outside the expected restart interval")
        raw = result.stdout.decode()
    else:
        raw = kubectl_capture(lab, "get", "--raw", route).decode()
    values = {}
    for line in raw.splitlines():
        if line.startswith((METRIC_TTL, METRIC_RENEW_ERRORS)) and not line.startswith("#"):
            name, raw = line.split(None, 1)
            if name in (METRIC_TTL, METRIC_RENEW_ERRORS):
                values[name] = float(raw)
    return values


def monitoring_state(lab, node, *, scrape=True):
    config = kubelet_config(lab, node) if scrape else {}
    metrics = kubelet_metrics(lab, node) if scrape else {}
    bootstrap, renewals = worker_certificates(lab, node)
    csr_states = csr_state_counts(lab, node)
    ttl, errors = metrics.get(METRIC_TTL), metrics.get(METRIC_RENEW_ERRORS)
    certificates = bootstrap + renewals
    return {
        "rotate_certificates": config.get("rotateCertificates", False) if scrape else None,
        "client_ttl_seconds": ttl if ttl is None or math.isfinite(ttl) else "non_finite",
        "renew_errors": errors if errors is None or math.isfinite(errors) else "non_finite",
        "csr_states": csr_states,
        "latest_expiry": max((item[0] for item in certificates), default=None),
        "all_chains_valid": bool(certificates) and all(item[3] for item in certificates),
        "lease_renew_time": worker_lease(lab, node),
        "renewal_count": len(renewals),
    }


def csr_state_counts(lab, node):
    counts = dict.fromkeys(("pending", "approved_issued", "approved_unissued", "denied", "failed"), 0)
    for csr, _ in node_csrs(lab, node):
        status = csr.get("status", {})
        conditions = {item.get("type") for item in status.get("conditions", []) if item["status"] == "True"}
        if "Denied" in conditions:
            counts["denied"] += 1
        elif "Failed" in conditions:
            counts["failed"] += 1
        elif "Approved" in conditions:
            counts["approved_issued" if status.get("certificate") else "approved_unissued"] += 1
        else:
            counts["pending"] += 1
    return counts


def worker_lease(lab, worker):
    result = lab.kubectl("-n", "kube-node-lease", "get", "lease", worker,
                         "-o", "jsonpath={.spec.renewTime}", timeout=15)
    return datetime.fromisoformat(result.stdout.strip().replace("Z", "+00:00"))


def wait_for_renewal(lab, worker):
    deadline = time.monotonic() + 170
    first = None
    while time.monotonic() < deadline:
        bootstrap, renewals = worker_certificates(lab, worker)
        first = bootstrap[0] if bootstrap else None
        if first and any(
            first[0] < renewed[0] < first[0] + CERTIFICATE_TTL
            and renewed[1] == first[1] and renewed[2] != first[2]
            for renewed in renewals
        ):
            return first, True
        if first and datetime.now(timezone.utc) >= first[0]:
            break
        time.sleep(2)
    return first, False


def ttl_matches(snapshot):
    ttl, expires = snapshot["client_ttl_seconds"], snapshot["latest_expiry"]
    return (isinstance(ttl, (int, float)) and ttl > 0 and expires is not None
            and abs(ttl - (expires - datetime.now(timezone.utc)).total_seconds()) < 30)


def run(lab):
    check_synthetic_fixtures(lab)
    enabled, disabled, control = [f"{lab.cluster}-{role}" for role in ("worker", "worker2", "control-plane")]
    lab.kubectl("wait", *(f"node/{node}" for node in (enabled, disabled, control)),
                "--for=condition=Ready", "--timeout=45s", timeout=55)
    control_lease = worker_lease(lab, control)
    effective_control_rotation = kubelet_config(lab, control).get("rotateCertificates") is True
    lab.check("positive", "The initial control-plane kubelet reports rotation enabled and an advancing client identity",
              effective_control_rotation and (datetime.now(timezone.utc) - control_lease) < timedelta(seconds=45),
              {"control_plane_rotation_enabled": effective_control_rotation, "fresh_lease": (
                  datetime.now(timezone.utc) - control_lease) < timedelta(seconds=45)})

    _, existing = worker_certificates(lab, control)
    serials_before = {row[2].lower().lstrip("0") for row in existing}
    with CONTROL_PLANE["use_seeded_profile"](lab, control) as state:
        seed, _ = state
        sample = CONTROL_PLANE["observe_seed"](
            lab, control, seed, lambda node: kubelet_metrics(lab, node, restarting=True).get(METRIC_TTL),
        )
        worker, native = exercise_workers(lab, enabled, disabled, control, state, serials_before, sample)
    worker["initial_control_plane"] = native
    (lab.evidence / "kubelet-client-lifecycle.json").write_text(
        json.dumps(worker, indent=2, default=lambda value: value.isoformat()) + "\n")


def exercise_workers(lab, enabled, disabled, control, seed_state, serials_before, sample):
    initial = monitoring_state(lab, enabled)
    comparator = monitoring_state(lab, disabled)
    old_enabled, _ = worker_certificates(lab, enabled)
    old_disabled, _ = worker_certificates(lab, disabled)
    if not old_enabled or not old_disabled:
        lab.block("Both owned workers must have their attributable issued bootstrap certificate")
    baseline_expiry = old_disabled[0][0]
    lab.check("red", "The disabled-rotation worker first enrolls with an API-server-trusted certificate",
              comparator["rotate_certificates"] is False and comparator["all_chains_valid"]
              and comparator["lease_renew_time"] < baseline_expiry,
              {"rotation_disabled": comparator["rotate_certificates"] is False,
               "bootstrap_chain_trusted": comparator["all_chains_valid"], "initial_identity_authenticated":
                   comparator["lease_renew_time"] < baseline_expiry})
    active_monitor = (initial["rotate_certificates"] and initial["all_chains_valid"] and ttl_matches(initial)
                      and initial["csr_states"]["approved_issued"] >= 1 and initial["renew_errors"] == 0)
    lab.check("positive", "The enabled worker reports the expected client certificate TTL and healthy native enrollment",
              active_monitor, {"trusted_chain_and_live_certificate_metric": bool(active_monitor)})

    import concurrent.futures

    def replacement():
        return CONTROL_PLANE["prove_replacement"](lab, control, seed_state, serials_before,
                                                    sample, worker_certificates)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(replacement)
        worker_raw = compare_workers(lab, enabled, disabled, baseline_expiry, initial, comparator)
        native = future.result()

    lab.check("green", "The first control plane installs the exact native client renewal before its seed expires",
              native["pre_expiry"], {"exact_trusted_control_plane_renewal": native["pre_expiry"]})
    expiry = datetime.fromisoformat(native["seed_expiry"])
    fresh = CONTROL_PLANE["wait"](
        lab, lambda: lease_after(lab, control, expiry), "a fresh control-plane lease after seed expiry",
        max(0, (expiry - datetime.now(timezone.utc)).total_seconds()) + 48,
    )
    current = json.loads(kubectl_capture(lab, "get", "node", control, "-o", "json"))
    still_ready = any(row["type"] == "Ready" and row["status"] == "True"
                      for row in current["status"]["conditions"])
    same_node = current["metadata"]["uid"] == native["source_node_uid"]
    lab.check("positive", "The same control-plane node remains Ready and renews its lease after seed expiry",
              fresh > expiry and still_ready and same_node,
              {"control_plane_ready": still_ready, "same_control_plane_node": same_node,
               "lease_after_seed_expiry": fresh > expiry})
    native.update({"lease_after_seed_expiry": fresh.isoformat(), "same_control_plane_node": same_node})
    return worker_raw, native


def lease_after(lab, node, expiry):
    lease = worker_lease(lab, node)
    return lease if lease > expiry + timedelta(seconds=6) else None


def compare_workers(lab, enabled, disabled, baseline_expiry, initial, comparator):
    first, renewed = wait_for_renewal(lab, enabled)
    lab.check("green", "The scoped worker renewal produces a distinct API-server-trusted client certificate before expiry",
              renewed and first is not None, {"trusted_pre_expiry_renewal": renewed})
    comparison_time = max(first[0], baseline_expiry) + timedelta(seconds=12)
    deadline = time.monotonic() + max(0, (comparison_time - datetime.now(timezone.utc)).total_seconds()) + 40
    while time.monotonic() < deadline and worker_lease(lab, enabled) <= comparison_time:
        time.sleep(4)
    after = monitoring_state(lab, enabled)
    # The comparator is intentionally expired. Inspect its cluster-side lifecycle
    # records without requiring its expired kubelet to authorize an inbound scrape.
    comparison = monitoring_state(lab, disabled, scrape=False)
    comparator_stale = comparison["lease_renew_time"] <= baseline_expiry + timedelta(seconds=1)
    no_renewal = comparison["renewal_count"] == 0
    lease_advanced = after["lease_renew_time"] > comparison_time
    expired = datetime.now(timezone.utc) >= baseline_expiry
    lab.check("red", "The disabled worker has actually expired, with no renewal and no fresh lease",
              expired and no_renewal and comparator_stale and lease_advanced,
              {"original_certificate_expired": expired, "no_disabled_worker_renewal": no_renewal,
               "disabled_worker_lease_stale": comparator_stale, "comparison_window_elapsed": lease_advanced})
    monitor_healthy = (after["all_chains_valid"] and after["renewal_count"] >= 1 and ttl_matches(after)
                       and lease_advanced and after["rotate_certificates"] is True)
    allowed = lab.kubectl("get", "node", enabled,
                          "-o", 'jsonpath={.status.conditions[?(@.type=="Ready")].status}').stdout == "True"
    lab.check("positive", "The monitoring signals and fresh lease confirm usable worker identity after the initial expiry",
              monitor_healthy and allowed, {"replacement_and_metric_valid": monitor_healthy,
                                            "enabled_lease_fresh": lease_advanced, "worker_ready": allowed})
    return {
        "enabled_before": initial, "disabled_before": comparator,
        "enabled_after": after, "disabled_cluster_records_after": comparison,
        "enabled_bootstrap_expires_at": first[0], "disabled_bootstrap_expires_at": baseline_expiry,
        "pre_expiry_worker_renewal": renewed, "enabled_lease_after_expiry": lease_advanced,
    }


class StaticReporter:
    def __init__(self):
        self.failed = False

    def check(self, phase, claim, condition, observed):
        print(f"{'PASS' if condition else 'FAIL'} [{phase}] {claim}")
        if not condition:
            print(f"  observed: {observed!r}")
            self.failed = True


if __name__ == "__main__":
    reporter = StaticReporter()
    check_synthetic_fixtures(reporter)
    raise SystemExit(1 if reporter.failed else 0)
