"""Create solely owned Kind peer infrastructure and verify its private path."""
from contextlib import contextmanager
import ipaddress
import json
import re
from urllib.parse import urlsplit

NODE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NS = "saf-test"


@contextmanager
def owned_peer(lab, image):
    name = lab.cluster + "-tls-peer"
    root = lab.kubeconfig.parent / "owned-tls-peer"
    root.mkdir()
    kubeconfig = root / "kubeconfig"
    config = root / "kind.json"
    config.write_text(json.dumps({
        "kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4",
        "networking": {"apiServerAddress": "127.0.0.1", "podSubnet": "10.246.0.0/16",
                       "serviceSubnet": "10.102.0.0/16"},
        "nodes": [{"role": "control-plane"}],
    }))

    def peer(*args, timeout=45, **kwargs):
        return lab.command("kubectl", "--kubeconfig", str(kubeconfig), "--context", "kind-" + name,
                           "--namespace", NS, f"--request-timeout={timeout - 5}s",
                           *args, timeout=timeout, **kwargs)

    if name in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("Peer name is already in use")
    try:
        lab.command("kind", "create", "cluster", "--name", name, "--image", NODE,
                    "--config", str(config), "--kubeconfig", str(kubeconfig),
                    "--wait", "100s", timeout=170)
        endpoint = json.loads(peer("config", "view", "--minify", "-o", "json").stdout
                              )["clusters"][0]["cluster"]["server"]
        node = name + "-control-plane"
        mapping = lab.command("docker", "port", node, "6443/tcp").stdout.strip()
        if not re.fullmatch(r"127\.0\.0\.1:\d+", mapping) or urlsplit(endpoint).netloc != mapping:
            lab.block("The peer API does not identify its owned loopback endpoint")
        cluster_uid = peer("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout.strip()
        source_uid = lab.kubectl("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout.strip()
        if not cluster_uid or source_uid == cluster_uid:
            lab.block("The peer and source cluster identities must be different")
        fmt = '{{json (index .NetworkSettings.Networks "kind")}}'
        remote = json.loads(lab.command("docker", "inspect", "--format", fmt, node).stdout)
        source = json.loads(lab.command("docker", "inspect", "--format", fmt,
                                        lab.cluster + "-control-plane").stdout)
        addr = ipaddress.IPv4Address(remote["IPAddress"])
        if remote["NetworkID"] != source["NetworkID"] or addr == ipaddress.IPv4Address(source["IPAddress"]):
            lab.block("The owned peer is not reachable on the expected test bridge")
        if addr.is_global or addr.is_loopback or addr.is_link_local:
            lab.block("The peer endpoint is not a private owned bridge address")
        peer("create", "namespace", NS)
        lab.command("kind", "load", "docker-image", image, "--name", name, timeout=120)
        yield peer, str(addr)
    finally:
        lab.command("kind", "delete", "cluster", "--name", name, "--kubeconfig", str(kubeconfig),
                    timeout=80)
