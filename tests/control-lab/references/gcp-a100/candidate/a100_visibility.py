"""Observe controlled loss of the exact A100 scrape source in a private monitor."""

import argparse
import hashlib
from ipaddress import IPv4Address
import json
import math
from pathlib import Path
import secrets
import shutil
import sys

import a100_readiness as readiness
import live_catch_hold as device
from visibility_transition import VisibilityBlocked, checkpoint, exercise


class CaseNamespace:
    """Send all fixture operations to the newly created namespace."""

    def __init__(self, binary, kubeconfig, namespace):
        self.binary = binary
        self.kubeconfig = kubeconfig
        self.namespace = namespace

    def kubectl(self, *args, timeout=20, **kwargs):
        return device.run_cmd([self.binary, "--kubeconfig", str(self.kubeconfig), "-n", self.namespace,
                               f"--request-timeout={timeout - 5}s", *args], timeout=timeout, **kwargs)

    def create(self, manifest):
        self.kubectl("create", "-f", "-", input_bytes=json.dumps(manifest).encode())


def verified_source(args, profile, binary):
    workload, _, _ = device.ensure_pod_profile(binary, args.kubeconfig, profile)
    pod, gpu, model, driver = device.nvidia_device(binary, args.kubeconfig,
                                                  args.podresources_binary, profile)
    node = workload["spec"]["nodeName"]
    if node != pod["spec"]["nodeName"] or (model, driver) != (profile["hardware"]["model"],
                                                            profile["hardware"]["driver"]):
        raise readiness.Blocked("The A100 node, model, or driver differs from the reviewed source")
    node_info = device.kube_json(binary, args.kubeconfig, "get", "node", node, "-o", "json")
    if readiness.sha(node_info["metadata"]["uid"]) != profile["kubernetes"]["node_uid_sha256"]:
        raise readiness.Blocked("The live node UID differs from the readiness profile")
    exporter, container, status = device.find_exporter(binary, args.kubeconfig, args.exporter_selector, node)
    exporter_ref = readiness.sha(exporter["metadata"]["uid"])
    expected = profile["exporter"]
    if (exporter_ref, container["image"], status["imageID"]) != (expected["pod_uid_sha256"],
                                                               expected["image"], expected["image_id"]):
        raise readiness.Blocked("The exporter identity or immutable image differs from preflight")
    address = str(IPv4Address(exporter["status"]["podIP"]))
    labels = {"namespace": device.WORKLOAD_NS, "pod": device.WORKLOAD_POD,
              "container": device.WORKLOAD_CONTAINER, "pod_uid": workload["metadata"]["uid"], "UUID": gpu}
    forward = readiness.start_forward(binary, args.kubeconfig, device.OBS_NS,
                                       exporter["metadata"]["name"], args.exporter_port, 9400)
    try:
        direct = readiness.exporter_samples(args.exporter_port, labels)["value"]
    finally:
        readiness.stop_forward(forward)
    if not math.isfinite(direct) or direct < 0:
        raise readiness.Blocked("The joined live framebuffer metric is invalid")
    return f"{address}:9400", labels, exporter_ref, direct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "profile", "podresources-binary", "support-review", "evidence-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--exporter-selector", required=True)
    parser.add_argument("--exporter-port", type=int, required=True)
    args = parser.parse_args()
    if not all(p.is_absolute() and p.is_file() for p in
               (args.kubeconfig, args.profile, args.podresources_binary, args.support_review)):
        parser.error("Pass absolute existing input paths")
    if not args.evidence_dir.is_absolute() or not 1024 <= args.exporter_port <= 65535:
        parser.error("Pass an absolute new evidence path and a nonprivileged loopback port")
    if hashlib.sha256(args.podresources_binary.read_bytes()).hexdigest() != readiness.PODRESOURCES_FIXTURE:
        raise readiness.Blocked("The PodResources binary differs from the reviewed fixture")
    binary = shutil.which("kubectl")
    if not binary:
        raise readiness.Blocked("kubectl is unavailable")
    profile = device.read_profile(args.profile)
    support = json.loads(args.support_review.read_text())
    expected = {
        "schema": "saf-a100-metric-support-review-v1",
        "status": "reviewed-supported",
        "metric": readiness.METRIC,
        "device_model": profile["hardware"]["model"],
        "driver": profile["hardware"]["driver"],
        "exporter_image_digest": profile["exporter"]["image_id"].split("sha256:")[-1],
    }
    if any(support.get(key) != value for key, value in expected.items()):
        raise readiness.Blocked("The current device and exporter lack matching reviewed metric support")

    args.evidence_dir.mkdir(mode=0o700)
    namespace = "saf-a100-visibility-" + secrets.token_hex(6)
    case = CaseNamespace(binary, args.kubeconfig, namespace)
    validated = verified_source(args, profile, binary)
    created = False
    try:
        case.kubectl("create", "namespace", namespace)
        created = True
        outcome = exercise(case, args.evidence_dir, validated, lambda: verified_source(args, profile, binary))
    finally:
        # Only this exact namespace was successfully created by the case.
        if created:
            case.kubectl("delete", "namespace", namespace, "--wait=true", "--timeout=60s", timeout=65)
    checkpoint(args.evidence_dir, "visibility.json", {
        "schema": "saf-a100-live-visibility-route-v2", "status": "passed", "source": "live_a100_dcgm_exporter",
        "hardware_model": profile["hardware"]["model"], "driver": profile["hardware"]["driver"],
        "profile_captured_at_utc": profile["captured_at_utc"], "case_namespace_deleted": True, **outcome})


if __name__ == "__main__":
    try:
        main()
    except (readiness.Blocked, VisibilityBlocked, ValueError, KeyError) as error:
        sys.exit(str(error))
