"""Compare kubeadm-generated etcd certificate validity with a 720h policy."""
from datetime import datetime, timezone
from pathlib import Path
import re


NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
POLICY_HOURS = 720
POLICY_SECONDS = POLICY_HOURS * 60 * 60
BACKDATE_SECONDS = 5 * 60
DEFAULT_SECONDS = 365 * 24 * 60 * 60
PKI_DIR = "/etc/kubernetes/pki"
CERTIFICATES = {
    "etcd_server": "etcd/server.crt",
    "etcd_peer": "etcd/peer.crt",
    "apiserver_etcd_client": "apiserver-etcd-client.crt",
}
SCOPE = (
    "Compare kubeadm-generated local-etcd server, peer and kube-apiserver etcd-client "
    "leaf certificates in the harness's pinned stock kind v1.36.1 cluster and a second "
    "kind cluster with kubeadm v1beta4 ClusterConfiguration.certificateValidityPeriod=719h55m. "
    "Read public notBefore/notAfter values and verify each certificate to that node's etcd CA. "
    "The 720h organization maximum is an example policy. External CAs, supplied certificates, "
    "external etcd and separately managed issuers are outside this case."
)


def parse_openssl_date(value):
    match = re.fullmatch(r"(?:notBefore|notAfter)=(.+)", value.strip())
    if not match:
        raise ValueError("Unexpected OpenSSL certificate date output")
    parsed = datetime.strptime(match.group(1), "%b %d %H:%M:%S %Y %Z")
    return parsed.replace(tzinfo=timezone.utc)


def inspect_certificate(lab, node, name, filename):
    path = f"{PKI_DIR}/{filename}"
    # Only public certificate metadata and verification status leave the node.
    dates = lab.command("docker", "exec", node, "openssl", "x509", "-in", path,
                        "-noout", "-startdate", "-enddate").stdout.splitlines()
    if len(dates) != 2:
        lab.block(f"Could not read public validity dates for {name}")
    not_before = parse_openssl_date(dates[0])
    not_after = parse_openssl_date(dates[1])
    verification = lab.command("docker", "exec", node, "openssl", "verify", "-purpose", "any",
                               "-CAfile", f"{PKI_DIR}/etcd/ca.crt", path, allow_failure=True)
    trusted = verification.returncode == 0 and verification.stdout.strip() == f"{path}: OK"
    validity_seconds = int((not_after - not_before).total_seconds())
    return {
        "name": name,
        "validity_seconds": validity_seconds,
        "currently_valid": not_before <= datetime.now(timezone.utc) < not_after,
        "trusted_by_local_etcd_ca": trusted,
    }


def profile(lab, node):
    records = [inspect_certificate(lab, node, key, filename)
               for key, filename in CERTIFICATES.items()]
    return {record["name"]: record for record in records}


def assert_expected_node_image(lab, node):
    result = lab.command("docker", "inspect", "--format", "{{.Config.Image}}", node).stdout.strip()
    if result != NODE_IMAGE:
        lab.block(f"Expected pinned v1.36.1 node image for {node}")


def run(lab):
    baseline_node = f"{lab.cluster}-control-plane"
    assert_expected_node_image(lab, baseline_node)
    baseline = profile(lab, baseline_node)
    baseline_default = all(
        item["validity_seconds"] == DEFAULT_SECONDS + BACKDATE_SECONDS
        and item["validity_seconds"] > POLICY_SECONDS
        for item in baseline.values()
    )
    lab.check(
        "red",
        "Stock kubeadm-generated etcd leaves exceed the example 720h maximum",
        baseline_default,
        {name: {**item, "over_720h": item["validity_seconds"] > POLICY_SECONDS}
         for name, item in baseline.items()},
    )

    custom_cluster = f"{lab.cluster}-short"
    existing = lab.command("kind", "get", "clusters").stdout.splitlines()
    if custom_cluster in existing:
        lab.block("The case-owned comparison cluster name is already in use")
    custom_owned = True
    try:
        lab.command("kind", "create", "cluster", "--name", custom_cluster,
                    "--image", NODE_IMAGE,
                    "--kubeconfig", str(lab.kubeconfig.parent / "short-kubeconfig"),
                    "--wait", "90s", "--config", str(Path(__file__).with_name("short-profile.yaml")),
                    timeout=480)
        custom_node = f"{custom_cluster}-control-plane"
        assert_expected_node_image(lab, custom_node)
        configured = profile(lab, custom_node)

        cap_enforced = all(
            item["validity_seconds"] == POLICY_SECONDS
            and item["currently_valid"] and item["trusted_by_local_etcd_ca"]
            for item in configured.values()
        )
        lab.check(
            "green",
            "The backdate-adjusted kubeadm setting produces currently valid, etcd-CA-trusted in-cap server, peer and apiserver client certificates",
            cap_enforced,
            {"policy_hours": POLICY_HOURS, "configured_duration": "719h55m",
             "issuance_backdate_seconds": BACKDATE_SECONDS, "certificates": configured},
        )

        kubeconfig = str(lab.kubeconfig.parent / "short-kubeconfig")
        readiness = lab.command("kubectl", "--kubeconfig", kubeconfig,
                                "--context", f"kind-{custom_cluster}",
                                "--request-timeout=15s", "get", "--raw=/readyz",
                                timeout=20, allow_failure=True)
        ready = readiness.stdout.strip() if readiness.returncode == 0 else ""
        positive = (
            ready == "ok"
            and all(item["currently_valid"] and item["trusted_by_local_etcd_ca"]
                    for item in baseline.values())
            and all(item["currently_valid"] and item["trusted_by_local_etcd_ca"]
                    for item in configured.values())
        )
        lab.check(
            "positive",
            "Both observed profiles retain valid etcd-CA trust and the configured cluster API reports ready",
            positive,
            {"configured_api_ready": ready == "ok",
             "baseline_certificates_current_and_trusted": all(
                 item["currently_valid"] and item["trusted_by_local_etcd_ca"]
                 for item in baseline.values()),
             "configured_certificates_current_and_trusted": all(
                 item["currently_valid"] and item["trusted_by_local_etcd_ca"]
                 for item in configured.values())},
        )
    finally:
        if custom_owned:
            lab.command("kind", "delete", "cluster", "--name", custom_cluster,
                        "--kubeconfig", str(lab.kubeconfig.parent / "short-kubeconfig"),
                        timeout=90)
