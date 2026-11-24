"""Review kubelet node-name inputs and observe an approved Kind enrollment."""
import base64
from datetime import datetime
import json
from pathlib import Path
import subprocess
import time

from lab import NODE_IMAGE


CASE_DIR = Path(__file__).resolve().parent
FIXTURES = CASE_DIR / "fixtures.json"
SCOPE = (
    "Synthetic authorization and provisioning policy checks plus a fresh Kind v1.36.1 "
    "control plane and affirmative kubeadm worker enrollment under a unique approved "
    "DNS node name. Read-only observations cover Node/OS hostname/effective flags, Node "
    "Lease UID and renewal, public kubelet client-certificate identity, signed "
    "native CSR metadata, and declared Node authorizer/NodeRestriction configuration. "
    "The guide covers adoption-specific provisioning and provider checks."
)


def approved_node_name(lab):
    return f"approved-{lab.cluster.rsplit('-', 1)[-1]}"


def prepare_kind(lab, temporary):
    """Set kubeadm's worker name, from which kubeadm generates the hostname override."""
    approved_name = approved_node_name(lab)
    config = f'''kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
    kubeadmConfigPatches:
      - |
        kind: JoinConfiguration
        nodeRegistration:
          name: {approved_name}
'''
    profile = Path(temporary) / "kind-approved-worker.yaml"
    profile.write_text(config, encoding="utf-8")
    return profile


def authorization_findings(document):
    """Check documented authorization posture, not runtime credentials."""
    findings = []
    modes = document.get("authorization_mode", [])
    config = document.get("authorization_configuration", {})
    configured = [item.get("type") for item in config.get("authorizers", [])
                  if isinstance(item, dict)]
    if "Node" not in modes and "Node" not in configured:
        findings.append("Node authorizer is absent from documented API-server authorization")
    if document.get("node_identity_username") != "system:node:<registered-node-name>":
        findings.append("documented kubelet username is not bound to the registered Node name")
    if "system:nodes" not in document.get("node_identity_groups", []):
        findings.append("documented kubelet identity omits system:nodes")
    return findings


def provisioning_findings(policy, observation):
    """Evaluate synthetic name governance against source observations."""
    findings = []
    names = observation.get("registered_node_names", [])
    if not names or any(not isinstance(name, str) or not name for name in names):
        findings.append("registered Node name set is empty or malformed")
    if len(names) != len(set(names)):
        findings.append("registered Node names are not unique")

    allowed = set(policy.get("approved_node_names", []))
    if any(name not in allowed for name in names):
        findings.append("registered Node name is absent from the provisioning approval")

    for item in observation.get("node_sources", []):
        name = item.get("registered_node_name")
        override = item.get("hostname_override")
        if override and override != name:
            findings.append(f"hostname override differs from registered Node name for {name}")
        approval = policy.get("approved_overrides", {}).get(name, {})
        if override and (override != approval.get("value") or not approval.get("reason")):
            findings.append(f"hostname override lacks a matching documented exception for {name}")
        if not override and item.get("hostname") != name:
            findings.append(f"default hostname differs from registered Node name for {name}")
    return findings


def check_fixtures(lab):
    data = json.loads(FIXTURES.read_text(encoding="utf-8"))
    bad_auth = authorization_findings(data["authorization_documents"]["red"])
    lab.check(
        "red", "Synthetic authorization document detects missing Node identity requirements",
        len(bad_auth) == 3, bad_auth,
    )
    good_auth = authorization_findings(data["authorization_documents"]["green"])
    lab.check(
        "green", "Synthetic authorization document records Node authorizer and identity binding",
        good_auth == [], good_auth,
    )

    bad_policy = data["provisioning_cases"]["red"]
    bad_findings = provisioning_findings(bad_policy["policy"], bad_policy["observation"])
    lab.check(
        "red", "Synthetic provisioning policy detects unapproved and duplicate names",
        len(bad_findings) >= 3 and any("unique" in item for item in bad_findings),
        bad_findings,
    )
    good_policy = data["provisioning_cases"]["green"]
    good_findings = provisioning_findings(good_policy["policy"], good_policy["observation"])
    lab.check(
        "green", "Synthetic approved names are consistent and unique",
        good_findings == [], good_findings,
    )


def safe_kubectl(lab, *args, timeout=20):
    """Read an API object in memory without adding its unfiltered JSON to evidence."""
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               f"--request-timeout={timeout - 2}s", *args]
    try:
        result = subprocess.run(command, capture_output=True, env=lab.env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        lab.block(f"Owned-cluster metadata read failed: {type(error).__name__}")
    if result.returncode:
        lab.block("Owned-cluster metadata read failed")
    return result.stdout


def _openssl(data, *args):
    try:
        result = subprocess.run(["openssl", *args], input=data, capture_output=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(type(error).__name__) from error
    if result.returncode:
        raise RuntimeError("OpenSSL could not parse public certificate request metadata")
    if "-verify" in args:
        verified = result.stdout + result.stderr
        if not any(expected in verified.lower() for expected in (b"verify ok", b"verification ok")):
            raise RuntimeError("OpenSSL did not confirm the request signature")
    return result.stdout.decode("utf-8", errors="strict").strip()


def _subject_fields(subject):
    return {field.strip() for field in subject.split(",") if field.strip()}


def certificate_fields(output):
    fields = dict(line.strip().split("=", 1) for line in output.splitlines() if "=" in line)
    return {key.strip().lower(): value.strip() for key, value in fields.items()}


def signed_native_csr(lab, approved_name, active_fingerprint):
    """Return metadata only; CSR and issued-certificate bytes stay in memory."""
    payload = json.loads(safe_kubectl(lab, "get", "certificatesigningrequests", "-o", "json"))
    expected_subject = {f"CN=system:node:{approved_name}", "O=system:nodes"}
    for item in payload.get("items", []):
        spec = item.get("spec", {})
        if spec.get("signerName") != "kubernetes.io/kube-apiserver-client-kubelet":
            continue
        try:
            request = base64.b64decode(spec.get("request", ""), validate=True)
            subject_line = _openssl(request, "req", "-noout", "-subject", "-nameopt", "RFC2253")
            subject = subject_line.partition("=")[2].strip()
        except (ValueError, RuntimeError):
            continue
        if _subject_fields(subject) != expected_subject:
            continue
        try:
            _openssl(request, "req", "-verify", "-noout")
            request_signature_valid = True
        except RuntimeError:
            request_signature_valid = False
        status = item.get("status", {})
        cert_bytes = base64.b64decode(status.get("certificate", ""), validate=True) if status.get("certificate") else b""
        issued = certificate_fields(_openssl(cert_bytes, "x509", "-noout", "-fingerprint",
                                              "-sha256")) if cert_bytes else {}
        conditions = sorted(condition.get("type", "") for condition in status.get("conditions", [])
                            if condition.get("status") == "True")
        meta = item.get("metadata", {})
        return {
            "available": True,
            "name": meta.get("name"),
            "uid": meta.get("uid"),
            "signer_name": spec.get("signerName"),
            "bootstrap_principal": spec.get("username", "").startswith("system:bootstrap:"),
            "request_subject": subject,
            "request_signature_valid": request_signature_valid,
            "conditions": conditions,
            "issued_matches_active_client_certificate": bool(
                active_fingerprint and issued.get("sha256 fingerprint", "").lower()
                == active_fingerprint.lower()),
        }
    return {"available": False}


def effective_overrides(lab, container):
    # Only the selected hostname flag is printed; the rest of argv stays private.
    script = r'''pid=$(systemctl show kubelet.service --property=MainPID --value)
test "${pid:-0}" -gt 0
tr '\000' '\n' < "/proc/$pid/cmdline" | awk '
  previous { print; previous=0; next }
  /^--hostname-override$/ { previous=1; next }
  /^--hostname-override=/ { sub(/^--hostname-override=/, ""); print }
'
'''
    return [line for line in lab.command("docker", "exec", container, "sh", "-ec", script).stdout.splitlines()
            if line]


def node_lease(lab, name, node_uid):
    document = json.loads(safe_kubectl(lab, "-n", "kube-node-lease", "get", "lease", name, "-o", "json"))
    metadata, spec = document["metadata"], document["spec"]
    matches = (metadata["name"] == name == spec.get("holderIdentity")
               and any(ref["kind"] == "Node" and ref["name"] == name and ref["uid"] == node_uid
                       for ref in metadata.get("ownerReferences", [])))
    return {"name": metadata["name"], "uid": metadata["uid"], "holder_identity": spec.get("holderIdentity"),
            "renew_time": spec["renewTime"], "owner_matches_node_uid": matches}


def wait_for_worker_lease(lab, name, node_uid):
    first = node_lease(lab, name, node_uid)
    start = datetime.fromisoformat(first["renew_time"].replace("Z", "+00:00"))
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        observed = node_lease(lab, name, node_uid)
        latest = datetime.fromisoformat(observed["renew_time"].replace("Z", "+00:00"))
        if latest > start and first["uid"] == observed["uid"] and observed["owner_matches_node_uid"]:
            return {"first": first, "renewed": observed}
        time.sleep(1)
    lab.block("The enrolled worker did not renew the case-owned Node Lease with the expected UID")


def kind_enrollment(lab):
    approved_name = approved_node_name(lab)
    containers = {"control-plane": f"{lab.cluster}-control-plane", "worker": f"{lab.cluster}-worker"}
    expected_names = {"control-plane": containers["control-plane"], "worker": approved_name}
    nodes, hostnames, overrides = {}, {}, {}
    for role, container in containers.items():
        lab.kubectl("wait", f"node/{expected_names[role]}", "--for=condition=Ready", "--timeout=120s", timeout=130)
        document = json.loads(safe_kubectl(lab, "get", "node", expected_names[role], "-o", "json"))
        nodes[role] = {key: document["metadata"][key] for key in ("name", "uid")}
        hostnames[role] = lab.command("docker", "exec", container, "hostname").stdout.strip()
        overrides[role] = effective_overrides(lab, container)

    if len({node["uid"] for node in nodes.values()}) != 2:
        lab.block("The owned control plane and authorized worker did not register as distinct Nodes")
    worker_container = containers["worker"]
    cert_output = lab.command(
        "docker", "exec", worker_container, "sh", "-ec",
        "openssl x509 -in /var/lib/kubelet/pki/kubelet-client-current.pem -noout "
        "-subject -issuer -serial -fingerprint -sha256 -nameopt RFC2253",
    ).stdout
    certificate = certificate_fields(cert_output)
    cert_subject = certificate["subject"]
    csr = signed_native_csr(lab, approved_name, certificate["sha256 fingerprint"])
    leases = wait_for_worker_lease(lab, approved_name, nodes["worker"]["uid"])

    apis = json.loads(safe_kubectl(lab, "-n", "kube-system", "get", "pods", "-l", "component=kube-apiserver",
                                  "-o", "json"))["items"]
    if len(apis) != 1:
        lab.block("Expected one API server in the case cluster")
    args = apis[0]["spec"]["containers"][0]["command"]
    selected = {}
    for name in ("authorization-mode", "enable-admission-plugins"):
        prefix = f"--{name}="
        selected[name] = next((arg[len(prefix):].split(",") for arg in args if arg.startswith(prefix)), [])

    expected_subject = {f"CN=system:node:{approved_name}", "O=system:nodes"}
    worker_node_ok = nodes["worker"]["name"] == approved_name
    override_ok = overrides["worker"] == [approved_name]
    hostname_distinct = hostnames["worker"] == worker_container and hostnames["worker"] != approved_name
    baseline_ok = (nodes["control-plane"]["name"] == hostnames["control-plane"] == containers["control-plane"]
                   and not overrides["control-plane"])
    identity_ok = _subject_fields(cert_subject) == expected_subject and bool(certificate["sha256 fingerprint"])
    api_ok = ("Node" in selected["authorization-mode"]
              and "NodeRestriction" in selected["enable-admission-plugins"])
    csr_ok = (csr["available"] and csr["request_signature_valid"] and csr["bootstrap_principal"]
              and "Approved" in csr["conditions"] and "Denied" not in csr["conditions"]
              and csr["issued_matches_active_client_certificate"])
    lab.check("positive", "Approved worker registers under its unique name with the exact effective override",
              worker_node_ok and override_ok and hostname_distinct,
              {"approved_name_matches_node": worker_node_ok, "exact_override": override_ok,
               "container_hostname_is_distinct": hostname_distinct})
    lab.check("positive", "Baseline control plane keeps its container hostname and no explicit override",
              baseline_ok, {"baseline_name_matches_hostname": nodes["control-plane"]["name"] == hostnames["control-plane"],
                            "no_explicit_override": not overrides["control-plane"]})
    lab.check("positive", "The enrolled worker renews its own Lease bound to the Node UID",
              leases["renewed"]["owner_matches_node_uid"],
              {"lease_renewed": True, "lease_owner_matches_node_uid": True})
    lab.check("positive", "The active kubelet client certificate carries the approved node name and group",
              identity_ok, {"subject_and_group_match": identity_ok,
                            "public_fingerprint_present": bool(certificate["sha256 fingerprint"])})
    lab.check("positive", "Node authorization and NodeRestriction are declared by the API server",
              api_ok, {"node_authorizer_enabled": "Node" in selected["authorization-mode"],
                       "node_restriction_enabled": "NodeRestriction" in selected["enable-admission-plugins"]})
    lab.check("positive", "The signed and approved bootstrap CSR issued the active client certificate",
              csr_ok, {"approved_native_bootstrap_csr": bool(csr_ok),
                       "issued_matches_active_certificate": csr.get("issued_matches_active_client_certificate", False)})

    (lab.evidence / "hostname-override-observations.json").write_text(json.dumps({
        "approved_node_name": approved_name,
        "nodes": nodes,
        "container_hostnames": hostnames,
        "effective_hostname_overrides": overrides,
        "leases": leases,
        "worker_public_client_certificate": certificate,
        "matching_native_csr_metadata": csr,
        "api_server_declared_configuration": selected,
    }, indent=2) + "\n", encoding="utf-8")


def run(lab):
    check_fixtures(lab)
    kind_enrollment(lab)


class StaticReporter:
    """Reporter for static synthetic fixture checks; it does not contact a cluster."""

    def __init__(self):
        self.failed = False

    def check(self, phase, claim, condition, observed):
        print(f"{'PASS' if condition else 'FAIL'} [{phase}] {claim}")
        if not condition:
            print(f"  observed: {observed!r}")
            self.failed = True


if __name__ == "__main__":
    reporter = StaticReporter()
    check_fixtures(reporter)
    raise SystemExit(1 if reporter.failed else 0)
