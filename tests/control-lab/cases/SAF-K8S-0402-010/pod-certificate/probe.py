"""Check native Pod certificate issuance and refresh in the owned v1.37 cluster."""
from datetime import datetime
import json
from pathlib import Path
from runpy import run_path
import subprocess
import time


HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-0402-010-pcr"
WORKLOAD = "authorized-workload"
SIGNER = "podcert-test-signer"
ACCOUNT = "pod-workload"
SIGNER_NAME = "identity.example.test/pod-workload"
COLLECTION = f"/apis/certificates.k8s.io/v1/namespaces/{NAMESPACE}/podcertificaterequests"
REFRESH_TIMEOUT = 22 * 60
FINAL_CHECKS = {
    "initial_projection_valid", "initial_key_certificate_match", "initial_chain_valid",
    "initial_public_metadata_valid", "renewal_observed", "projected_generation_changed",
    "public_certificate_metadata_changed", "renewed_key_certificate_match",
    "renewed_chain_valid", "renewed_public_metadata_valid", "public_key_changed",
}


def get(lab, *args):
    return json.loads(lab.kubectl("get", *args, "-o", "json").stdout)


def identities(lab):
    node = get(lab, "node", f"{lab.cluster}-control-plane")
    spec = get(lab, "pod", "-n", "kube-system", f"kube-apiserver-{lab.cluster}-control-plane")["spec"]
    flags = spec["containers"][0]["command"]
    ready = {
        "pinned_kubelet": node["status"]["nodeInfo"]["kubeletVersion"] == "v1.37.0",
        "pinned_api_server": get_version(lab) == "v1.37.0",
        "node_authorizer": any(flag.startswith("--authorization-mode=") and "Node" in flag.split("=", 1)[1].split(",")
                               for flag in flags),
        "node_restriction": any(flag.startswith("--enable-admission-plugins=")
                                and "NodeRestriction" in flag.split("=", 1)[1].split(",") for flag in flags),
        "stable_api": any(item["name"] == "podcertificaterequests"
                          for item in json.loads(lab.kubectl(
                              "get", "--raw", "/apis/certificates.k8s.io/v1").stdout)["resources"]),
    }
    lab.check("positive", "The owned v1.37 node and API support the intended PCR admission path",
              all(ready.values()), ready)
    return node["metadata"]


def get_version(lab):
    return json.loads(lab.kubectl("version", "-o", "json").stdout)["serverVersion"]["gitVersion"]


def fixtures(node, image, peer_node_ip):
    *documents, signer = json.loads((HERE / "manifests.json").read_text())
    container = signer["spec"]["containers"][0]
    container["env"] = [{"name": key, "value": node[field]}
                        for key, field in (("EXPECTED_NODE_NAME", "name"), ("EXPECTED_NODE_UID", "uid"))]
    for document in [*documents, signer]:
        if document["kind"] == "Pod":
            document["spec"]["containers"][0]["image"] = image
    workload = next(item for item in documents
                    if item.get("kind") == "Pod" and item.get("metadata", {}).get("name") == WORKLOAD)
    workload["spec"]["volumes"].append({"name": "peer-trust", "projected": {"sources": [{
        "clusterTrustBundle": {"signerName": "domain-b.fixture.invalid/pod-workload",
                                "labelSelector": {"matchLabels": {"saf-k8s.example/peer-root": "domain-b"}},
                                "path": "domain-b.pem", "optional": True}}]}})
    workload["spec"]["containers"].append({
        "name": "peer-client", "image": image, "imagePullPolicy": "Never",
        "command": ["python", "/opt/fixture/peer_client.py"],
        "env": [{"name": "PEER_NODE_IP", "value": peer_node_ip}],
        "volumeMounts": [
            {"name": "pod-identity", "mountPath": "/var/run/pod-identity", "readOnly": True},
            {"name": "peer-trust", "mountPath": "/var/run/peer-trust", "readOnly": True}],
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                             "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi"}}})
    return documents, signer


def create(lab, document):
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "name", payload=json.dumps(document))


def in_memory_requests(lab, node, pod_uid, account_uid):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "--request-timeout=15s", "get", "--raw", COLLECTION]
    result = subprocess.run(command, env=lab.env, capture_output=True, timeout=20)
    if result.returncode:
        lab.block("The isolated Pod certificate request API query failed")
    observations = {}
    for item in json.loads(result.stdout)["items"]:
        spec, status = item["spec"], item.get("status", {})
        if spec.get("podName") != WORKLOAD or spec.get("signerName") != SIGNER_NAME:
            continue
        expected_uid = (spec.get("podUID"), spec.get("serviceAccountUID"), spec.get("nodeUID"))
        identity_ok = expected_uid == (pod_uid, account_uid, node["uid"]) and (
            spec.get("nodeName"), spec.get("serviceAccountName")
        ) == (node["name"], ACCOUNT)
        issued = any(c["type"] == "Issued" and c["status"] == "True" for c in status.get("conditions", []))
        if not issued:
            observations[item["metadata"]["uid"]] = (identity_ok, False)
        else:
            before, after, hint = (datetime.fromisoformat(status[field].replace("Z", "+00:00"))
                                   for field in ("notBefore", "notAfter", "beginRefreshAt"))
            lifetime = (after - before).total_seconds()
            within = (hint - before).total_seconds() >= 600 and (after - hint).total_seconds() >= 600
            observations[item["metadata"]["uid"]] = (identity_ok, lifetime == 3600 and within)
    return observations


def verifier_events(lab):
    result = lab.kubectl("-n", NAMESPACE, "logs", f"pod/{WORKLOAD}", "-c", "verifier",
                         allow_failure=True, timeout=15)
    if result.returncode:
        return []
    events = []
    for line in result.stdout.splitlines():
        event = json.loads(line)
        if not isinstance(event, dict):
            lab.block("The verifier emitted unexpected metadata")
        events.append(event)
    return events


def wait_for_unissued_request(lab, node, pod_uid, account_uid):
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        observed = in_memory_requests(lab, node, pod_uid, account_uid)
        if observed:
            status = get(lab, "pod", "-n", NAMESPACE, WORKLOAD)["status"]
            matched = len(observed) == 1 and set(observed.values()) == {(True, False)}
            pending = status["phase"] == "Pending"
            lab.check("red", "Without the fixture signer, the matching request is unissued and the Pod stays Pending",
                      matched and pending, {"one_matching_unissued_request": matched, "pod_pending": pending})
            return next(iter(observed))
        time.sleep(2)
    lab.block("The owned workload did not create its initial certificate request")


def wait_for_projection(lab, node, pod_uid, account_uid, first_request, peer):
    start = time.monotonic()
    observations = {}
    initial = False
    while time.monotonic() - start < REFRESH_TIMEOUT:
        signer = get(lab, "pod", "-n", NAMESPACE, SIGNER)["status"]
        if signer.get("phase") == "Failed":
            diagnostics = lab.kubectl("-n", NAMESPACE, "logs", f"pod/{SIGNER}", "-c", "signer",
                                      allow_failure=True, timeout=15).stdout.splitlines()
            last = diagnostics[-1] if diagnostics else "no diagnostic"
            lab.block(f"The fixture signer stopped with a sanitized outcome: {last}")
        for container_status in signer.get("containerStatuses", []):
            reason = container_status.get("state", {}).get("waiting", {}).get("reason")
            if reason in {"CreateContainerConfigError", "ErrImageNeverPull"}:
                lab.block(f"The fixture signer could not start: {reason}")
        observations.update(in_memory_requests(lab, node, pod_uid, account_uid))
        peer.observe_peer_results()
        events = verifier_events(lab)
        if not initial and any(item == {"initial_projection": True} for item in events):
            first_issued = observations.get(first_request) == (True, True)
            lab.check("green", "The authorized signer issues the expected one-hour certificate and kubelet projects it",
                      first_issued, {"initial_projection": True, "expected_api_identity_and_lifetime": first_issued})
            initial = True
        final = next((item for item in events if set(item) == FINAL_CHECKS), None)
        if final:
            if not all(value is True for value in final.values()):
                lab.block("The projection verifier did not observe a complete certificate refresh")
            refreshed = any(uid != first_request and value == (True, True)
                            for uid, value in observations.items())
            unchanged = get(lab, "pod", "-n", NAMESPACE, WORKLOAD)["metadata"]["uid"] == pod_uid
            lab.check("positive", "The same Pod sees a new valid key and certificate from a distinct issued request",
                      initial and refreshed and unchanged,
                      {"same_pod": unchanged, "distinct_api_issuance": refreshed, "projection": final})
            if not peer.observe_peer_results():
                peer.wait_peer_results()
            return
        if not initial and time.monotonic() - start > 120:
            lab.block("The owned workload did not observe an initial certificate within two minutes")
        time.sleep(5)
    lab.block("Kubelet refresh was not observed within the fixture window")


def run(lab):
    node = identities(lab)
    image = f"saf-podcert-fixture:{lab.cluster}"
    if lab.command("docker", "image", "inspect", image, allow_failure=True).returncode == 0:
        lab.block("Expected an unused local fixture image name")
    lab.command("docker", "build", "--tag", image, str(HERE), timeout=480)
    peer = None
    try:
        lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=120)
        Peer = run_path(str(HERE.parent / "peer_case.py"))["PeerRun"]
        peer = Peer.create(lab, image, lab.kubeconfig.parent / "peer-kubeconfig")
        peer.bootstrap()
        documents, signer = fixtures(node, image, peer.peer_ip)
        for document in documents:
            create(lab, document)
        pod_uid = get(lab, "pod", "-n", NAMESPACE, WORKLOAD)["metadata"]["uid"]
        account_uid = get(lab, "serviceaccount", "-n", NAMESPACE, ACCOUNT)["metadata"]["uid"]
        pending_request = wait_for_unissued_request(lab, node, pod_uid, account_uid)
        create(lab, signer)
        peer.publish_a_root_and_start_server()
        wait_for_projection(lab, node, pod_uid, account_uid, pending_request, peer)
        if not peer.observe_peer_results():
            peer.wait_peer_results()
    finally:
        try:
            if peer is not None:
                peer.cleanup()
        finally:
            lab.command("docker", "image", "rm", image, timeout=90)
    lab.check("positive", "The lab removes its local fixture image tag", True, {"removed": True})
