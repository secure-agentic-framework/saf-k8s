"""Verify the secured kubelet listener on the cluster-owned Kind node."""
import json
import re

SCOPE = (
    "One disposable Kubernetes v1.36.1 Kind control-plane node. Measures "
    "the authenticated effective kubelet configuration, native local listeners "
    "and read-only credential-less HTTPS /healthz using a verified certificate "
    "chain. Uses the trusted Kubernetes API proxy for the permitted comparison. "
    "No insecure listeners are enabled."
)


def node_command(lab, node, *args):
    return lab.command("docker", "exec", node, *args).stdout


def listener_exists(lab, node, port):
    return bool(node_command(lab, node, "ss", "-H", "-lnt", f"sport = :{port}").strip())


def run(lab):
    node = f"{lab.cluster}-control-plane"
    proxy = f"/api/v1/nodes/{node}/proxy"
    endpoint = json.loads(lab.kubectl("get", "node", node, "-o", "json").stdout)
    secure_endpoint = endpoint["status"]["daemonEndpoints"]["kubeletEndpoint"]
    if secure_endpoint.get("Port", secure_endpoint.get("port")) != 10250:
        lab.block("The case-owned node does not use the expected secure kubelet port")
    config = json.loads(lab.kubectl("get", f"--raw={proxy}/configz").stdout)["kubeletconfig"]
    certificate = config.get("tlsCertFile")
    if not certificate or re.fullmatch(r"/var/lib/kubelet/pki/[a-zA-Z0-9_.-]+\.crt", certificate) is None:
        lab.block("The owned kubelet did not identify its expected public TLS serving certificate")

    # The serving chain is public. curl still performs identity and chain verification.
    fields = node_command(
        lab, node, "curl", "-q", "--silent", "--show-error", "--max-time", "5",
        "--noproxy", "*", "--cacert", certificate,
        "--resolve", f"{node}:10250:127.0.0.1", "--output", "/dev/null",
        "--write-out", "%{http_code} %{ssl_verify_result}", f"https://{node}:10250/healthz",
    ).split()
    if len(fields) != 2:
        lab.block("curl did not report status and verification receipt")
    rejected = fields == ["401", "0"]
    lab.check("red", "A verified HTTPS kubelet health request has no credentials and is denied",
              rejected, {"http_status": fields[0], "tls_verification_passed": fields[1] == "0"})

    anonymous = config.get("authentication", {}).get("anonymous", {}).get("enabled")
    legacy_port = config.get("readOnlyPort", 0)
    lab.check("green", "The effective kubelet configuration disables anonymous authentication and the read-only port",
              anonymous is False and legacy_port == 0,
              {"anonymous_enabled": anonymous, "read_only_port": legacy_port})
    secure_up = listener_exists(lab, node, 10250)
    legacy_up = listener_exists(lab, node, 10255)
    lab.check("green", "The secure listener serves TCP and the legacy read-only listener is absent",
              secure_up and not legacy_up,
              {"secure_listener_present": secure_up, "legacy_listener_present": legacy_up})

    passed = lab.kubectl("get", f"--raw={proxy}/healthz").stdout.strip() == "ok"
    lab.check("positive", "An authenticated Kubernetes API proxy request reaches the same kubelet health endpoint",
              passed, {"authenticated_health_read": passed})
