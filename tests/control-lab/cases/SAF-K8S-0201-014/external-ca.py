"""Verify an owned kubelet's configured serving certificate over TLS."""
import json
from pathlib import Path
import re
import ssl
import subprocess

NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
MOUNT = "/etc/kubernetes/saf-kubelet-tls"
SCOPE = (
    "One disposable kind control plane with a dedicated synthetic CA and CA-issued kubelet "
    "serving certificate. An ordinary TLS handshake verifies the live chain and node DNS name. "
    "Local public certificate fixtures exercise an unrelated CA, name mismatch and expiration."
)


def openssl(*args, data=None):
    return subprocess.run(["openssl", *map(str, args)], input=data, capture_output=True, timeout=25)


def require(lab, *args):
    result = openssl(*args)
    if result.returncode:
        lab.block(f"Could not prepare the synthetic TLS fixture with openssl {args[0]}")
    return result.stdout


def prepare_kind(lab, temporary: Path) -> Path:
    shared = temporary / "serving"
    shared.mkdir(mode=0o700)
    root_config = temporary / "root.conf"
    root_config.write_text("[req]\ndistinguished_name=dn\n[dn]\n[extensions]\n"
                           "basicConstraints=critical,CA:TRUE\n"
                           "keyUsage=critical,keyCertSign,cRLSign\n")
    root_key = temporary / "root-key.pem"
    require(lab, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "5", "-sha256",
            "-config", root_config, "-extensions", "extensions",
            "-subj", "/CN=SAF Synthetic Kubelet Serving CA", "-keyout", root_key,
            "-out", shared / "ca.pem")
    root_key.chmod(0o600)
    other_key = temporary / "comparison-key.pem"
    require(lab, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "5", "-sha256",
            "-config", root_config, "-extensions", "extensions",
            "-subj", "/CN=SAF Unrelated Synthetic CA", "-keyout", other_key,
            "-out", shared / "other-ca.pem")
    other_key.unlink()

    node = f"{lab.cluster}-control-plane"
    request = temporary / "serving.csr"
    leaf_key = shared / "node-key.pem"
    require(lab, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={node}",
            "-keyout", leaf_key, "-out", request)
    leaf_key.chmod(0o600)
    leaf_conf = temporary / "leaf.conf"
    leaf_conf.write_text("[extensions]\nbasicConstraints=critical,CA:FALSE\n"
                         "keyUsage=critical,digitalSignature,keyEncipherment\n"
                         f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{node}\n")
    require(lab, "x509", "-req", "-in", request, "-CA", shared / "ca.pem",
            "-CAkey", root_key, "-set_serial", "1", "-sha256", "-days", "2",
            "-extfile", leaf_conf, "-extensions", "extensions", "-out", shared / "node.pem")
    root_key.unlink()
    config = temporary / "kind.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
kubeadmConfigPatches:
- |
  apiVersion: kubelet.config.k8s.io/v1beta1
  kind: KubeletConfiguration
  serverTLSBootstrap: false
  tlsCertFile: {MOUNT}/node.pem
  tlsPrivateKeyFile: {MOUNT}/node-key.pem
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(shared))}
    containerPath: {MOUNT}
    readOnly: true
""")
    return config


def node_openssl(lab, node, *args, data=None):
    return subprocess.run(["docker", "exec", "-i", node, "openssl", *map(str, args)],
                          input=data, capture_output=True, env=lab.env, timeout=20)


def offline_rejections(lab, node, leaf):
    remote_leaf = f"{MOUNT}/node.pem"
    other = node_openssl(lab, node, "verify", "-purpose", "sslserver",
                         "-CAfile", f"{MOUNT}/other-ca.pem", remote_leaf)
    lab.check("red", "A separate synthetic trust anchor cannot verify the public serving certificate",
              other.returncode != 0 and b"unable to get local issuer" in other.stdout + other.stderr,
              {"unrelated_root_rejected": other.returncode != 0,
               "issuer_reason_present": b"unable to get local issuer" in other.stdout + other.stderr})
    ca = f"{MOUNT}/ca.pem"
    name = node_openssl(lab, node, "verify", "-purpose", "sslserver", "-CAfile", ca,
                        "-verify_hostname", "unrelated-node.example.test", remote_leaf)
    lab.check("red", "An unrelated DNS identity fails the offline SAN check",
              name.returncode != 0 and b"hostname mismatch" in name.stdout + name.stderr,
              {"name_mismatch_rejected": name.returncode != 0})
    expiry = require(lab, "x509", "-in", leaf, "-enddate", "-noout").decode().strip().split("=", 1)[1]
    after_expiry = int(ssl.cert_time_to_seconds(expiry)) + 30
    invalid = node_openssl(lab, node, "verify", "-attime", after_expiry,
                           "-purpose", "sslserver", "-verify_hostname", node,
                           "-CAfile", ca, remote_leaf)
    lab.check("red", "The public serving certificate fails validation after expiry",
              invalid.returncode != 0 and b"certificate has expired" in invalid.stdout + invalid.stderr,
              {"expired_certificate_rejected": invalid.returncode != 0})


def run(lab):
    root = lab.kubeconfig.parent
    node = f"{lab.cluster}-control-plane"
    leaf = root / "serving" / "node.pem"
    offline_rejections(lab, node, leaf)
    peer = node_openssl(lab, node, "s_client", "-connect", "127.0.0.1:10250",
                        "-servername", node, "-verify_hostname", node,
                        "-verify_return_error", "-showcerts",
                        "-CAfile", f"{MOUNT}/ca.pem", data=b"")
    chain_verified = peer.returncode == 0 and b"Verify return code: 0 (ok)" in peer.stdout
    lab.check("green", "The owned kubelet completes a TLS handshake under the expected CA and DNS identity",
              chain_verified, {"trusted_chain_and_dns": chain_verified})
    certificate = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                            peer.stdout, re.S)
    if certificate is None:
        lab.block("The verified peer returned no public serving certificate")
    exact = ssl.PEM_cert_to_DER_cert(certificate.group().decode()) == ssl.PEM_cert_to_DER_cert(leaf.read_text())
    freshness = openssl("x509", "-noout", "-checkend", "86400", data=certificate.group() + b"\n")
    lab.check("positive", "The live peer presents the intended leaf with at least a day of validity",
              exact and freshness.returncode == 0,
              {"expected_leaf_present": exact, "fresh_for_one_day": freshness.returncode == 0})
