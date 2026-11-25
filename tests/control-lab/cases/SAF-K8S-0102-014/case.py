"""Serial all-role kubeadm certificate adoption on one owned three-node Kind fixture."""
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import re
import shlex
import subprocess
import time

import yaml

SCOPE = (
    "Serial kubeadm renewal of each etcd member's server, peer, and API-server client "
    "certificates on three isolated control-plane nodes. Verify a real member pause, "
    "quorum and native storage continuity, then observe active server and peer "
    "leaves and a local API storage read before advancing. Issuer policy, scheduling "
    "and managed or external etcd paths are separate adopter evidence."
)
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
ETCD_IMAGE = "registry.k8s.io/etcd:3.6.8-0"
NODES = ("control-plane", "control-plane2", "control-plane3")
CERTS = {
    "etcd/server": "/etc/kubernetes/pki/etcd/server.crt",
    "etcd/peer": "/etc/kubernetes/pki/etcd/peer.crt",
    "apiserver-etcd-client": "/etc/kubernetes/pki/apiserver-etcd-client.crt",
}
TARGETS = {"etcd/server": "etcd-server", "apiserver-etcd-client": "apiserver-etcd-client",
           "etcd/peer": "etcd-peer"}
ORDER = tuple(TARGETS)
EXPECTED_EKU = {
    "etcd/server": {"TLS Web Server Authentication", "TLS Web Client Authentication"},
    "etcd/peer": {"TLS Web Server Authentication", "TLS Web Client Authentication"},
    "apiserver-etcd-client": {"TLS Web Client Authentication"},
}
MEMBER_ORDER = ("member-1", "member-2", "member-3")


def _run(lab, argv, *, timeout=25, input_text=None, allow_failure=False):
    """Capture bounded fixture output in memory; never append it to commands.log."""
    try:
        result = subprocess.run(argv, input=input_text, text=True, capture_output=True,
                                env=lab.env, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("A bounded three-member fixture command did not complete")
    if result.returncode and not allow_failure:
        lab.block("A bounded three-member fixture command failed")
    return result


def _kubectl(lab, *args, timeout=25, input_text=None, allow_failure=False):
    return _run(lab, ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                      f"kind-{lab.cluster}", f"--request-timeout={timeout - 5}s", *args],
                timeout=timeout, input_text=input_text, allow_failure=allow_failure)


def _node(lab, node, script, *, timeout=30, allow_failure=False):
    if node not in {f"{lab.cluster}-{suffix}" for suffix in NODES}:
        lab.block("Refused a node command outside the exact three-node fixture map")
    return _run(lab, ["docker", "exec", node, "sh", "-ceu", script], timeout=timeout,
                allow_failure=allow_failure)


def _json(result):
    try:
        return json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return {}


def _pods_by_node(lab, component, *, allow_failure=False):
    rows = _json(_kubectl(lab, "-n", "kube-system", "get", "pods", "-l",
                          f"component={component}", "-o", "json", allow_failure=allow_failure)).get("items", [])
    mapping = {}
    for row in rows:
        name = row.get("spec", {}).get("nodeName")
        if name in mapping:
            lab.block("More than one static Pod for a role was mapped to a node")
        mapping[name] = row
    return mapping


def _container_id(pod):
    statuses = pod.get("status", {}).get("containerStatuses", [])
    return statuses[0].get("containerID", "") if len(statuses) == 1 else ""


def _ready(pod):
    return (pod.get("status", {}).get("phase") == "Running"
            and len(pod.get("status", {}).get("containerStatuses", [])) == 1
            and pod["status"]["containerStatuses"][0].get("ready") is True)


def _cert_receipt(lab, container, role):
    path = shlex.quote(CERTS[role])
    command = (f"openssl x509 -in {path} -noout -fingerprint -sha256 -serial -startdate "
               "-enddate -ext keyUsage,extendedKeyUsage")
    output = _node(lab, container, command).stdout
    fingerprint = re.search(r"(?:sha256 )?Fingerprint=([0-9A-Fa-f:]+)", output)
    serial = re.search(r"^serial=([0-9A-Fa-f]+)$", output, re.M)
    start = re.search(r"^notBefore=(.+)$", output, re.M)
    end = re.search(r"^notAfter=(.+)$", output, re.M)
    ext = {"keyUsage": "", "extendedKeyUsage": ""}
    active = None
    for line in output.splitlines():
        if line.strip().startswith("X509v3 Key Usage:"):
            active = "keyUsage"
        elif line.strip().startswith("X509v3 Extended Key Usage:"):
            active = "extendedKeyUsage"
        elif line.strip().startswith("X509v3 "):
            active = None
        elif active and line.strip():
            ext[active] += line.strip()
    if not all((fingerprint, serial, start, end, ext["keyUsage"], ext["extendedKeyUsage"])):
        lab.block("A public certificate role receipt was incomplete")
    return {"fingerprint": fingerprint.group(1).replace(":", "").lower(),
            "serial": serial.group(1).lower().lstrip("0") or "0",
            "not_before": start.group(1), "not_after": end.group(1),
            "key_usage": ext["keyUsage"].replace(", ", ","),
            "extended_key_usage": ext["extendedKeyUsage"].replace(", ", ",")}


def _public_inventory(lab, member_map):
    return {member: {role: _cert_receipt(lab, row["container"], role) for role in ORDER}
            for member, row in member_map.items()}


def _epoch(value):
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc).timestamp()


def _member_command(lab, member_pod, *args, endpoint="https://127.0.0.1:2379", allow_failure=False):
    return _kubectl(lab, "-n", "kube-system", "exec", member_pod, "-c", "etcd", "--",
                    "etcdctl", f"--endpoints={endpoint}",
                    "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
                    "--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt",
                    "--key=/etc/kubernetes/pki/etcd/healthcheck-client.key", *args,
                    timeout=15, allow_failure=allow_failure)


def _member_state(lab, member_map, live_etcd, surviving=None):
    available = [node for node in member_map if node in live_etcd and _ready(live_etcd[node])]
    if surviving is not None:
        available = [node for node in available if node != surviving]
    if not available:
        return {"member_count": 0, "membership_unchanged": False,
                "healthy_endpoint_count": 0, "leader_present": False}
    endpoint = sorted(available)[0]
    pod = live_etcd[endpoint]["metadata"]["name"]
    members_json = _json(_member_command(lab, pod, "member", "list", "--write-out=json", allow_failure=surviving is not None))
    members = members_json.get("members", [])
    seen = {str(row.get("ID")): row for row in members}
    expected = {str(row["member_id"]): (row["member_name"], row["peer_url"])
                for row in member_map.values()}
    membership_ok = (len(seen) == 3 and set(seen) == set(expected)
                     and not any(row.get("isLearner") is True for row in members)
                     and all(seen[mid].get("name") == name
                             and peer in seen[mid].get("peerURLs", [])
                             for mid, (name, peer) in expected.items()))
    statuses = []
    leader_ids = set()
    for node, row in member_map.items():
        if node not in available:
            continue
        address = f"https://{row['ip']}:2379"
        health = _json(_member_command(lab, pod, "endpoint", "health", "--write-out=json",
                                       endpoint=address, allow_failure=surviving is not None))
        status = _json(_member_command(lab, pod, "endpoint", "status", "--write-out=json",
                                       endpoint=address, allow_failure=surviving is not None))
        health_rows = health if isinstance(health, list) else [health]
        status_rows = status if isinstance(status, list) else [status]
        healthy = (len(health_rows) == 1 and health_rows[0].get("health") is True
                   and not health_rows[0].get("errors"))
        leader = (len(status_rows) == 1 and status_rows[0].get("Status", {}).get("leader")
                  == status_rows[0].get("Status", {}).get("header", {}).get("member_id"))
        status_leader = status_rows[0].get("Status", {}).get("leader") if status_rows else None
        if status_leader:
            leader_ids.add(str(status_leader))
        statuses.append({"healthy": healthy, "leader_present": bool(status_leader),
                         "local_is_leader": leader})
    survivor_ids = {member_map[node]["member_id"] for node in available}
    consensus_leader = len(leader_ids) == 1 and leader_ids <= survivor_ids
    return {"member_count": len(members), "membership_unchanged": membership_ok,
            "healthy_endpoint_count": sum(row["healthy"] for row in statuses),
            "expected_healthy_endpoint_count": len(available),
            "leader_present": consensus_leader,
            "single_consistent_leader": consensus_leader,
            "membership_leader_statuses": statuses}


def _manifest_restart(lab, container, manifest, role, during=None):
    manifest = shlex.quote(manifest)
    held = shlex.quote(f"/tmp/saf-roll-{role}.held")
    original = _node(lab, container, f"cat {manifest}").stdout
    document = yaml.safe_load(original)
    if document.get("kind") != "Pod" or document.get("metadata", {}).get("name") != role:
        lab.block("The exact held static manifest did not identify the expected role")
    annotations = document["metadata"].setdefault("annotations", {})
    marker = "saf.example/fixture-certificate-refresh"
    if marker in annotations:
        lab.block("The reviewed static role already carried a fixture refresh marker")
    annotations[marker] = "renewed-role-v1"
    replacement = json.dumps(document, indent=2) + "\n"
    expected_hash = hashlib.sha256(replacement.encode()).hexdigest()
    before = _node(lab, container, f"crictl ps --name {role} -q").stdout.strip()
    if not before:
        lab.block("No running container was found before pausing its static manifest")
    _node(lab, container, f"test -f {manifest}; test ! -e {held}; mv {manifest} {held}")
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if not _node(lab, container, f"crictl ps --name {role} -q").stdout.strip():
                break
            time.sleep(1)
        else:
            lab.block("The affected static role did not stop while its manifest was held")
        if during:
            during()
    except BaseException:
        _node(lab, container, f"test -f {held}; mv {held} {manifest}")
        raise
    next_file = shlex.quote(f"/tmp/saf-roll-{role}.next")
    atomic_refresh = (f"umask 077; test -f {held}; test ! -e {next_file}; "
                      f"cat > {next_file}; chmod --reference={held} {next_file}; "
                      f"mv {next_file} {manifest}; sha256sum {manifest}")
    refreshed = _run(lab, ["docker", "exec", "-i", container, "sh", "-ceu", atomic_refresh],
                     input_text=replacement, allow_failure=True)
    if refreshed.returncode or refreshed.stdout.split()[0:1] != [expected_hash]:
        _node(lab, container, f"test -f {held}; mv {held} {manifest}")
        lab.block("The reviewed static manifest did not restore atomically")
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        after = _node(lab, container, f"crictl ps --name {role} -q").stdout.strip()
        if after and after != before:
            _node(lab, container, f"test -f {manifest}; rm {held}; test ! -e {held}")
            return True
        time.sleep(1)
    containers = _node(lab, container, f"crictl ps -a --name {role}", allow_failure=True)
    recent = _node(lab, container, f"crictl ps -a --name {role} -q | head -n 1", allow_failure=True).stdout.strip()
    logs = ""
    if re.fullmatch(r"[a-f0-9]{6,64}", recent):
        result = _node(lab, container, f"crictl logs --tail=35 {recent}", allow_failure=True)
        logs = result.stdout + result.stderr
    kubelet = _node(lab, container,
                    "journalctl -u kubelet --no-pager -n 50 --output=cat", allow_failure=True)
    diagnostics = {"role": role, "manifest_path": manifest, "restored_manifest_hash_verified": True,
                   "containers": containers.stdout[-3000:],
                   "last_container_log": logs[-6000:], "last_kubelet_events": kubelet.stdout[-6000:]}
    (lab.evidence / f"static-{role}-restart-diagnostics.json").write_text(json.dumps(diagnostics,indent=2)+"\n")
    return False


def _wait_static_pod(lab, component, node_name, old_id, timeout=75):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pod = _pods_by_node(lab, component).get(node_name)
        if pod and _ready(pod) and _container_id(pod) != old_id:
            return pod
        time.sleep(1)
    lab.block("The restarted node-local static Pod did not become Ready with a new container")


def _api_ready(lab):
    result = _kubectl(lab, "get", "--raw=/readyz", timeout=10, allow_failure=True)
    return result.returncode == 0 and result.stdout.strip() == "ok"


def _api_marker(lab, name):
    payload = {"apiVersion": "v1", "kind": "ConfigMap",
               "metadata": {"name": name, "namespace": "saf-test"},
               "data": {"marker": "synthetic-0102-014-roll-v1"}}
    existing = _kubectl(lab, "-n", "saf-test", "get", "configmap", name, "-o", "json",
                         allow_failure=True)
    if existing.returncode:
        created = _kubectl(lab, "create", "-f", "-", "-o", "json", input_text=json.dumps(payload),
                           allow_failure=True)
        if created.returncode:
            return False
    readback = _json(_kubectl(lab, "-n", "saf-test", "get", "configmap", name, "-o", "json",
                              allow_failure=True))
    return readback.get("data") == payload["data"]


def _tls_leaf_fingerprint(lab, source, ip, port, client_cert, client_key, ca):
    command = ["docker", "exec", source, "timeout", "8", "openssl", "s_client", "-showcerts",
               "-connect", f"{ip}:{port}", "-verify_return_error", "-verify_ip", ip,
               "-tls1_2", "-CAfile", ca, "-cert", client_cert, "-key", client_key]
    result = _run(lab, command, timeout=12, allow_failure=True)
    transcript = (result.stdout + "\n" + result.stderr).lower()
    cert = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                     result.stdout, re.S)
    if not cert or result.returncode != 0:
        return None
    try:
        der = base64.b64decode(re.sub(r"\s+", "", cert.group(1)), validate=True)
    except (ValueError, binascii.Error):
        return None
    verified = "verification: ok" in transcript or "verify return code: 0 (ok)" in transcript
    return hashlib.sha256(der).hexdigest() if verified else None


def _live_server(lab, member, row):
    return _tls_leaf_fingerprint(
        lab, row["container"], row["ip"], 2379,
        "/etc/kubernetes/pki/etcd/healthcheck-client.crt",
        "/etc/kubernetes/pki/etcd/healthcheck-client.key",
        "/etc/kubernetes/pki/etcd/ca.crt")


def _live_peer(lab, source_row, target_row):
    return _tls_leaf_fingerprint(
        lab, source_row["container"], target_row["ip"], 2380,
        "/etc/kubernetes/pki/etcd/peer.crt", "/etc/kubernetes/pki/etcd/peer.key",
        "/etc/kubernetes/pki/etcd/ca.crt")


def run(lab):
    version = _json(_kubectl(lab, "version", "-o", "json")).get("serverVersion", {}).get("gitVersion")
    nodes = _json(_kubectl(lab, "get", "nodes", "-o", "json")).get("items", [])
    by_name = {row.get("metadata", {}).get("name"): row for row in nodes}
    expected_nodes = {f"{lab.cluster}-{suffix}" for suffix in NODES}
    if version != "v1.36.1" or set(by_name) != expected_nodes:
        lab.block("Expected exactly three pinned v1.36.1 Kind control-plane nodes")
    if any(not any(c.get("type") == "Ready" and c.get("status") == "True"
                   for c in by_name[name].get("status", {}).get("conditions", []))
           for name in expected_nodes):
        lab.block("A fixture control-plane Node was not Ready")
    addresses = {}
    for name in expected_nodes:
        ips = [row.get("address") for row in by_name[name].get("status", {}).get("addresses", [])
               if row.get("type") == "InternalIP"]
        if len(ips) != 1:
            lab.block("A fixture node did not have exactly one InternalIP")
        addresses[name] = ips[0]

    etcd_pods = _pods_by_node(lab, "etcd")
    api_pods = _pods_by_node(lab, "kube-apiserver")
    if set(etcd_pods) != expected_nodes or set(api_pods) != expected_nodes:
        lab.block("Expected one etcd and one API-server Pod on each mapped node")
    member_map = {}
    for ordinal, node_name in zip(MEMBER_ORDER, sorted(expected_nodes)):
        pod = etcd_pods[node_name]
        spec = pod.get("spec", {})
        containers = spec.get("containers", [])
        if (not _ready(pod) or len(containers) != 1 or containers[0].get("image") != ETCD_IMAGE):
            lab.block("A mapped etcd Pod was not the expected ready image")
        command = containers[0].get("command", [])
        def flag(name):
            values = [arg.split("=", 1)[1] for arg in command if arg.startswith(f"--{name}=")]
            if len(values) != 1:
                lab.block("An etcd manifest option was absent or ambiguous")
            return values[0]
        peer_urls = flag("initial-advertise-peer-urls").split(",")
        if peer_urls != [f"https://{addresses[node_name]}:2380"]:
            lab.block("A peer URL did not match the exact node InternalIP")
        member_map[node_name] = {"ordinal": ordinal, "container": node_name,
                                 "ip": addresses[node_name], "pod": pod["metadata"]["name"],
                                 "member_name": flag("name"), "peer_url": peer_urls[0],
                                 "pod_uid": pod["metadata"].get("uid")}
    # Bind manifest observations to the authenticated etcd membership result.
    first_pod = etcd_pods[sorted(expected_nodes)[0]]["metadata"]["name"]
    member_rows = _json(_member_command(lab, first_pod, "member", "list", "--write-out=json")).get("members", [])
    if len(member_rows) != 3:
        lab.block("Authenticated etcd membership did not report exactly three members")
    for row in member_map.values():
        matches = [item for item in member_rows if item.get("name") == row["member_name"]
                   and row["peer_url"] in item.get("peerURLs", [])]
        if len(matches) != 1:
            lab.block("Node, etcd Pod, peer URL and member identity were not one-to-one")
        row["member_id"] = str(matches[0].get("ID"))

    kubeadm_versions = {node: _node(lab, node, "kubeadm version -o short").stdout.strip()
                        for node in sorted(expected_nodes)}
    if set(kubeadm_versions.values()) != {"v1.36.1"}:
        lab.block("A mapped control-plane node did not run kubeadm v1.36.1")
    if any(not _ready(api_pods[node]) for node in expected_nodes):
        lab.block("A mapped API-server Pod was not Ready at baseline")
    baseline_state = _member_state(lab, member_map, etcd_pods)
    ca_fingerprints = {}
    for node, row in member_map.items():
        out = _node(lab, row["container"],
                    "openssl x509 -in /etc/kubernetes/pki/etcd/ca.crt -noout -fingerprint -sha256").stdout
        match = re.search(r"Fingerprint=([0-9A-Fa-f:]+)", out)
        ca_fingerprints[node] = match.group(1).replace(":", "").lower() if match else ""
    before = _public_inventory(lab, member_map)
    now = time.time()
    baseline_cert_policy = all(
        set(before[node][role]["extended_key_usage"].split(",")) == EXPECTED_EKU[role]
        and _epoch(before[node][role]["not_before"]) <= now < _epoch(before[node][role]["not_after"])
        for node in member_map for role in ORDER)
    baseline_api_ready = _api_ready(lab)
    baseline_marker = _api_marker(lab, "roll-baseline")
    baseline_ok = (baseline_state["member_count"] == 3 and baseline_state["membership_unchanged"]
                   and baseline_state["healthy_endpoint_count"] == 3 and baseline_state["leader_present"]
                   and len(set(ca_fingerprints.values())) == 1 and baseline_cert_policy
                   and baseline_api_ready and baseline_marker)
    lab.check("positive", "Exactly three mapped healthy members and role-correct fixture leaves establish baseline",
              baseline_ok,
              {"pinned_kubeadm_nodes": len(kubeadm_versions), "member_count": baseline_state["member_count"],
               "membership_unchanged": baseline_state["membership_unchanged"],
               "healthy_endpoints": baseline_state["healthy_endpoint_count"],
               "leader_present": baseline_state["leader_present"],
               "shared_etcd_ca": len(set(ca_fingerprints.values())) == 1,
               "all_nine_role_leaves_current_and_usage_correct": baseline_cert_policy,
               "api_ready": baseline_api_ready, "api_marker_readback": baseline_marker})

    completed = []
    for index, node_name in enumerate(sorted(member_map), start=1):
        target = member_map[node_name]
        # Fresh inventory is read before each member, then compared in-memory.
        step_before = _public_inventory(lab, member_map)
        etcd_pods = _pods_by_node(lab, "etcd")
        api_pods = _pods_by_node(lab, "kube-apiserver")
        prior_state = _member_state(lab, member_map, etcd_pods)
        if (prior_state["healthy_endpoint_count"] != 3 or not prior_state["leader_present"]
                or not prior_state["membership_unchanged"] or not _api_ready(lab)):
            lab.block("Pre-step quorum, membership or API gate failed")
        old_etcd_id = _container_id(etcd_pods[node_name])
        old_api_id = _container_id(api_pods[node_name])
        if not old_etcd_id or not old_api_id:
            lab.block("Target static Pod container IDs were not observable before renewal")
        renew = " && ".join(f"kubeadm certs renew {TARGETS[role]}" for role in ORDER)
        _node(lab, target["container"], renew, timeout=90)
        step_after = _public_inventory(lab, member_map)
        role_results = {}
        for role in ORDER:
            old, new = step_before[node_name][role], step_after[node_name][role]
            role_results[role] = {
                "fingerprint_changed": old["fingerprint"] != new["fingerprint"],
                "serial_changed": old["serial"] != new["serial"],
                "expiry_extended": _epoch(new["not_after"]) > _epoch(old["not_after"]),
                "new_leaf_current": _epoch(new["not_before"]) <= time.time() < _epoch(new["not_after"]),
                "usage_preserved": old["key_usage"] == new["key_usage"]
                    and old["extended_key_usage"] == new["extended_key_usage"],
                "role_eku_correct": set(new["extended_key_usage"].split(",")) == EXPECTED_EKU[role],
            }
        other_unchanged = all(step_before[node][role]["fingerprint"] == step_after[node][role]["fingerprint"]
                              for node in member_map if node != node_name for role in ORDER)
        if not all(all(values.values()) for values in role_results.values()) or not other_unchanged:
            lab.block("Selective renewal did not change only this member's three valid role leaves")
        lab.check("green", "One member's three kubeadm leaves renew without changing another member",
                  True, {"member": target["ordinal"], "three_roles_changed_and_current": True,
                         "role_usage_preserved": True, "other_members_unchanged": other_unchanged})

        survivors = sorted(n for n in member_map if n != node_name)
        peer_source = member_map[survivors[0]]

        def observe_stopped_etcd():
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                current = _pods_by_node(lab, "etcd", allow_failure=True)
                state = _member_state(lab, member_map, current, surviving=node_name)
                unavailable = _node(lab, peer_source["container"],
                    f"timeout 4 openssl s_client -connect {target['ip']}:2379 </dev/null",
                    allow_failure=True)
                refused = unavailable.returncode != 0 and "connection refused" in unavailable.stderr.lower()
                consensus = (state["healthy_endpoint_count"] == 2 and state["leader_present"]
                             and state["membership_unchanged"])
                if refused and consensus and _api_ready(lab) and _api_marker(lab, f"roll-{index}-etcd"):
                    lab.check("red", "The paused member's listener is unavailable while its two survivors retain quorum and native API writes",
                              True, {"member": target["ordinal"], "paused_listener_refuses_connection": True,
                                     "two_healthy_survivors": True, "surviving_leader": True,
                                     "existing_membership": True, "native_api_write_read": True})
                    return
                time.sleep(2)
            lab.block("Unable to observe actual target unavailability with two-member quorum and API continuity")

        def rotate_member_etcd():
            if not _manifest_restart(lab, target["container"], "/etc/kubernetes/manifests/etcd.yaml",
                                     "etcd", during=observe_stopped_etcd):
                lab.block("Target etcd manifest restart did not complete")
            # Kubelet uses the node-local API for mirror Pod operations.
            # Wait for the new local etcd TLS listener without a mirror Pod.
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                healthy = _json(_member_command(
                    lab, peer_source["pod"], "endpoint", "health", "--write-out=json",
                    endpoint=f"https://{target['ip']}:2379", allow_failure=True))
                if (isinstance(healthy, list) and len(healthy) == 1
                        and healthy[0].get("health") is True and not healthy[0].get("errors")
                        and _live_server(lab, node_name, target)
                        == step_after[node_name]["etcd/server"]["fingerprint"]
                        and _live_peer(lab, peer_source, target)
                        == step_after[node_name]["etcd/peer"]["fingerprint"]):
                    return
                time.sleep(1)
            lab.block("The renewed etcd listener did not adopt the expected server leaf")

        # Temporarily stop only this API server so kubelet mirror calls fail
        # quickly while its local etcd is absent. The other APIs serve clients.
        if not _manifest_restart(lab, target["container"], "/etc/kubernetes/manifests/kube-apiserver.yaml",
                                 "kube-apiserver", during=rotate_member_etcd):
            lab.block("Target API-server manifest restart did not complete")
        _wait_static_pod(lab, "etcd", node_name, old_etcd_id)
        etcd_pods = _pods_by_node(lab, "etcd")
        state = _member_state(lab, member_map, etcd_pods)
        server_fp = _live_server(lab, node_name, target)
        peer_fp = _live_peer(lab, peer_source, target)
        live_ok = (state["healthy_endpoint_count"] == 3 and state["leader_present"]
                   and state["membership_unchanged"]
                   and server_fp == step_after[node_name]["etcd/server"]["fingerprint"]
                   and peer_fp == step_after[node_name]["etcd/peer"]["fingerprint"]
                   and _api_marker(lab, f"roll-{index}-etcd"))
        lab.check("positive", "Etcd returns with unchanged membership and renewed active server/peer leaves",
                  live_ok,
                  {"member": target["ordinal"], "two_survivors_healthy_before_return": True,
                   "all_three_healthy_after_return": state["healthy_endpoint_count"] == 3,
                   "leader_present": state["leader_present"],
                   "membership_unchanged": state["membership_unchanged"],
                   "active_server_matches_file": server_fp == step_after[node_name]["etcd/server"]["fingerprint"],
                   "active_peer_matches_file": peer_fp == step_after[node_name]["etcd/peer"]["fingerprint"],
                   "api_marker_readback": True})

        _wait_static_pod(lab, "kube-apiserver", node_name, old_api_id)
        api_pods = _pods_by_node(lab, "kube-apiserver")
        state = _member_state(lab, member_map, etcd_pods)
        manifest_ok = _node(lab, target["container"],
                            "grep -F -- '--etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt' "
                            "/etc/kubernetes/manifests/kube-apiserver.yaml >/dev/null",
                            allow_failure=True).returncode == 0
        target_read = _node(lab, target["container"],
            f"kubectl --kubeconfig=/etc/kubernetes/admin.conf --server=https://{target['ip']}:6443 "
            f"--request-timeout=5s -n saf-test get configmap roll-{index}-etcd -o json",
            allow_failure=True)
        local_storage_read = (_json(target_read).get("data") == {"marker": "synthetic-0102-014-roll-v1"})
        api_ok = (local_storage_read and all(_ready(api_pods.get(node, {})) for node in expected_nodes)
                  and state["healthy_endpoint_count"] == 3 and state["leader_present"]
                  and state["membership_unchanged"] and _api_ready(lab)
                  and manifest_ok and _api_marker(lab, f"roll-{index}-api"))
        lab.check("positive", "Target API-server adopts the renewed client path with cluster API and etcd continuity",
                  api_ok,
                  {"member": target["ordinal"], "all_api_server_pods_ready": all(_ready(api_pods.get(n, {})) for n in expected_nodes),
                   "all_three_etcd_endpoints_healthy": state["healthy_endpoint_count"] == 3,
                   "leader_present": state["leader_present"], "membership_unchanged": state["membership_unchanged"],
                   "api_ready": _api_ready(lab), "renewed_client_path_referenced": manifest_ok,
                   "target_api_exact_storage_read": local_storage_read,
                   "api_marker_readback": True})
        completed.append(target["ordinal"])

    final_pods = _pods_by_node(lab, "etcd")
    final_state = _member_state(lab, member_map, final_pods)
    final_receipts = _public_inventory(lab, member_map)
    retained = _json(_kubectl(lab, "-n", "saf-test", "get", "configmap", "roll-baseline", "-o", "json")).get("data")
    final_cert_policy = all(
        _epoch(final_receipts[node][role]["not_before"]) <= time.time()
        < _epoch(final_receipts[node][role]["not_after"])
        and set(final_receipts[node][role]["extended_key_usage"].split(",")) == EXPECTED_EKU[role]
        for node in member_map for role in ORDER)
    final_api_ready = _api_ready(lab)
    retained_ok = retained == {"marker": "synthetic-0102-014-roll-v1"}
    final_ok = (completed == list(MEMBER_ORDER) and final_state["member_count"] == 3
                and final_state["healthy_endpoint_count"] == 3 and final_state["leader_present"]
                and final_state["membership_unchanged"] and final_api_ready
                and retained_ok and final_cert_policy)
    lab.check("positive", "All three members finish renewed, healthy, and serving retained API data",
              final_ok,
              {"members_completed_serially": len(completed) == 3,
               "all_members_retained": final_state["member_count"] == 3,
               "all_three_endpoints_healthy": final_state["healthy_endpoint_count"] == 3,
               "leader_present": final_state["leader_present"],
               "membership_unchanged": final_state["membership_unchanged"],
               "all_nine_leaves_current_and_role_correct": final_cert_policy,
               "api_ready_and_retained_marker": final_api_ready and retained_ok,
               "decision_clock_tested": False})
