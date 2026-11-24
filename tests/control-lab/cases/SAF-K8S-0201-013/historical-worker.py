"""Policy counterfactuals and live kubeadm worker client certificate renewal."""
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import time

FIXTURES = Path(__file__).resolve().parent / "fixtures.json"
CLIENT_SIGNER = "kubernetes.io/kube-apiserver-client-kubelet"
SCOPE = "Native kubeadm worker client-certificate bootstrap and renewal with paired rotation-enabled and rotation-disabled workers and a shortened certificate lifetime."
CERTIFICATE_TTL = timedelta(seconds=150)


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


def worker_certificates(lab, worker):
    # Returned status certificates are public. Keep the complete response in memory
    # because bootstrap request metadata can include a bootstrap token identifier.
    response = subprocess.run(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--request-timeout=8s", "get", "certificatesigningrequests", "-o", "json"],
        capture_output=True, env=lab.env, timeout=12,
    )
    if response.returncode:
        lab.block("Could not read certificate issuance status from the owned cluster")

    bootstrap, renewals = [], []
    identity = f"system:node:{worker}"
    for csr in json.loads(response.stdout)["items"]:
        spec, status = csr["spec"], csr.get("status", {})
        groups = spec.get("groups", [])
        from_bootstrap = ("system:bootstrappers" in groups
                          and spec.get("username", "").startswith("system:bootstrap:"))
        from_node = "system:nodes" in groups and spec.get("username") == identity
        if spec["signerName"] != CLIENT_SIGNER or not (from_bootstrap or from_node):
            continue
        if not status.get("certificate") or not any(
                item["type"] == "Approved" and item["status"] == "True"
                for item in status.get("conditions", [])):
            continue
        details = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-serial", "-enddate",
             "-nameopt", "RFC2253"],
            input=base64.b64decode(status["certificate"], validate=True),
            capture_output=True, timeout=5,
        )
        if details.returncode:
            lab.block("OpenSSL could not parse a public status certificate")
        fields = dict(line.split("=", 1) for line in details.stdout.decode().splitlines())
        if set(fields["subject"].strip().split(",")) != {f"CN={identity}", "O=system:nodes"}:
            continue
        expires = datetime.strptime(fields["notAfter"], "%b %d %H:%M:%S %Y GMT").replace(
            tzinfo=timezone.utc)
        (bootstrap if from_bootstrap else renewals).append(
            (expires, fields["issuer"], fields["serial"]))
    return sorted(bootstrap), sorted(renewals)


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


def run(lab):
    check_synthetic_fixtures(lab)
    worker = f"{lab.cluster}-worker"
    baseline = f"{lab.cluster}-worker2"
    lab.kubectl("wait", f"node/{worker}", f"node/{baseline}", "--for=condition=Ready",
                "--timeout=45s", timeout=55)
    initial_lease = worker_lease(lab, baseline)
    baseline_certificates, _ = worker_certificates(lab, baseline)
    baseline_expiry = baseline_certificates[0][0] if baseline_certificates else None
    baseline_authenticated = baseline_expiry is not None and initial_lease < baseline_expiry
    lab.check("red", "Rotation-disabled worker received a bootstrap certificate and used its node identity",
              baseline_authenticated, {"bootstrap_worked": baseline_authenticated})
    first, renewed_before_expiry = wait_for_renewal(lab, worker)
    lab.check("green", "Native bootstrap approved and issued the worker client certificate",
              first is not None, {"bootstrap_issued": first is not None})
    lab.check("green", "Native renewal signed a distinct worker client certificate before expiry",
              renewed_before_expiry, {"pre_expiry_renewal": renewed_before_expiry})

    # A fresh lease after the original certificate expires demonstrates continued
    # use of a valid node identity without opening any node credential files.
    initial_expiry = first[0]
    latest_expiry = max(initial_expiry, baseline_expiry)
    deadline = time.monotonic() + max(0, (latest_expiry - datetime.now(timezone.utc)).total_seconds()) + 40
    lease_advanced = False
    while time.monotonic() < deadline:
        lease = worker_lease(lab, worker)
        if lease > latest_expiry + timedelta(seconds=12):
            lease_advanced = True
            break
        time.sleep(4)
    _, baseline_renewals = worker_certificates(lab, baseline)
    baseline_fresh = worker_lease(lab, baseline) > baseline_expiry + timedelta(seconds=1)
    lab.check("red", "Rotation-disabled worker has no renewal and no fresh lease after expiry",
              lease_advanced and not baseline_renewals and not baseline_fresh,
              {"comparison_window_elapsed": lease_advanced,
               "renewal_issued": bool(baseline_renewals), "fresh_lease": baseline_fresh})
    ready = lab.kubectl("get", "node", worker,
                        "-o", 'jsonpath={.status.conditions[?(@.type=="Ready")].status}').stdout == "True"
    lab.check("positive", "Worker remains Ready and writes a fresh lease after bootstrap certificate expiry",
              ready and lease_advanced, {"ready": ready, "fresh_lease": lease_advanced})


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
