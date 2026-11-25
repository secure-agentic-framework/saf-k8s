"""Maintenance-free, read-only telemetry fixture for SAF-K8S-0102-012."""
import json
import re
import socket
import subprocess
import time
from urllib.request import urlopen
import uuid

ETCD_IMAGE = "gcr.io/etcd-development/etcd:v3.6.8@sha256:397189418d1a00e500c0605ad18d1baf3b541a1004d768448c367e48071622e5"
NAMESPACE = "saf-etcd-health-" + uuid.uuid4().hex[:8]
MEMBERS = ("etcd-0", "etcd-1", "etcd-2")
ENDPOINTS = tuple("http://%s.etcd.%s.svc.cluster.local:2379" % (m, NAMESPACE) for m in MEMBERS)
PEER_FAMILY = "etcd_network_peer_round_trip_time_seconds_bucket"
# etcd v3.6.8 publishes the first RoundTripper RTT observation after its 5s timer.
INITIAL_PEER_OBSERVATION_SECONDS = 6


def kubectl(lab, *args, payload=None, timeout=45, allow_failure=False):
    return lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                       "kind-" + lab.cluster, *args, payload=payload, timeout=timeout,
                       allow_failure=allow_failure)


def resource(lab, body):
    kubectl(lab, "create", "-f", "-", "-o", "json",
            payload=json.dumps(body, sort_keys=True, separators=(",", ":")))


def service():
    return {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "etcd", "namespace": NAMESPACE},
        "spec": {"clusterIP": "None", "publishNotReadyAddresses": True,
                 "selector": {"app": "etcd"},
                 "ports": [{"name": "client", "port": 2379, "targetPort": 2379},
                           {"name": "peer", "port": 2380, "targetPort": 2380}]},
    }


def statefulset():
    peer_urls = ["http://%s.etcd.%s.svc.cluster.local:2380" % (name, NAMESPACE)
                 for name in MEMBERS]
    client_url = "http://$(POD_NAME).etcd.%s.svc.cluster.local:2379" % NAMESPACE
    args = ["--name=$(POD_NAME)", "--data-dir=/etcd-data",
            "--listen-client-urls=http://0.0.0.0:2379", "--advertise-client-urls=" + client_url,
            "--listen-peer-urls=http://0.0.0.0:2380",
            "--initial-advertise-peer-urls=http://$(POD_NAME).etcd.%s.svc.cluster.local:2380" % NAMESPACE,
            "--initial-cluster=" + ",".join("%s=%s" % row for row in zip(MEMBERS, peer_urls)),
            "--initial-cluster-state=new", "--initial-cluster-token=saf-0102-012-scratch"]
    return {
        "apiVersion": "apps/v1", "kind": "StatefulSet",
        "metadata": {"name": "etcd", "namespace": NAMESPACE},
        "spec": {"serviceName": "etcd", "replicas": 3, "podManagementPolicy": "Parallel",
                 "selector": {"matchLabels": {"app": "etcd"}},
                 "template": {"metadata": {"labels": {"app": "etcd"}},
                              "spec": {"terminationGracePeriodSeconds": 20,
                                       "containers": [{"name": "etcd", "image": ETCD_IMAGE,
                                                       "imagePullPolicy": "IfNotPresent",
                                                       "command": ["/usr/local/bin/etcd"], "args": args,
                                                       "env": [{"name": "POD_NAME", "valueFrom": {
                                                           "fieldRef": {"fieldPath": "metadata.name"}}}],
                                                       "ports": [{"name": "client", "containerPort": 2379},
                                                                 {"name": "peer", "containerPort": 2380}],
                                                       "readinessProbe": {"exec": {"command": [
                                                           "/usr/local/bin/etcdctl", "--endpoints=http://127.0.0.1:2379",
                                                           "endpoint", "health"]}, "initialDelaySeconds": 2,
                                                                          "periodSeconds": 2, "timeoutSeconds": 2,
                                                                          "failureThreshold": 15},
                                                       "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                                                                     "limits": {"cpu": "500m", "memory": "256Mi"}},
                                                       "volumeMounts": [{"name": "data", "mountPath": "/etcd-data"}]}],
                                       "volumes": [{"name": "data", "emptyDir": {"sizeLimit": "512Mi"}}]}}},
    }


def create_and_check_fixture(lab):
    resource(lab, {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}})
    resource(lab, service())
    resource(lab, statefulset())
    kubectl(lab, "-n", NAMESPACE, "rollout", "status", "statefulset/etcd", "--timeout=180s",
            timeout=190)
    pods = json.loads(kubectl(lab, "-n", NAMESPACE, "get", "pods", "-l", "app=etcd", "-o", "json").stdout)
    names = sorted(row.get("metadata", {}).get("name", "") for row in pods.get("items", []))
    if names != list(MEMBERS):
        lab.block("The owned passive etcd fixture did not have exactly three members")


def status_for_member(lab, member):
    pod = "pod/" + member
    result = kubectl(lab, "-n", NAMESPACE, "exec", pod, "-c", "etcd", "--",
                     "/usr/local/bin/etcdctl", "--endpoints=http://127.0.0.1:2379",
                     "--dial-timeout=2s", "--command-timeout=5s", "endpoint", "status", "--write-out=json",
                     timeout=10)
    rows = json.loads(result.stdout)
    if len(rows) != 1 or rows[0].get("Status", {}).get("errors"):
        lab.block("A passive per-member etcd status observation failed")
    return rows[0]["Status"]


def open_local_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def metric_lines_for_member(lab, member):
    port = open_local_port()
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", "kind-" + lab.cluster,
            "-n", NAMESPACE, "port-forward", "--address=127.0.0.1", "pod/" + member,
            "%d:2379" % port]
    proc = subprocess.Popen(args, env=lab.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 8
        body = None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                lab.block("Could not establish the local-only etcd metrics forward")
            try:
                with urlopen("http://127.0.0.1:%d/metrics" % port, timeout=3) as response:
                    if response.status != 200:
                        lab.block("The passive etcd metrics endpoint returned an unexpected status")
                    body = response.read(4_000_000).decode("utf-8", errors="strict")
                break
            except (OSError, TimeoutError):
                time.sleep(0.2)
        if body is None:
            lab.block("The bounded passive etcd metrics scrape timed out")
        allowed = ("etcd_server_has_leader", "etcd_server_proposals_committed_total",
                   "etcd_server_proposals_applied_total", "etcd_mvcc_db_total_size_in_bytes",
                   "etcd_server_quota_backend_bytes", "etcd_disk_wal_fsync_duration_seconds_bucket",
                   "etcd_disk_backend_commit_duration_seconds_bucket", PEER_FAMILY)
        return [line for line in body.splitlines()
                if any(line.startswith(name + "{") or line.startswith(name + " ") for name in allowed)]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()


def label_value(line, label):
    match = re.search(r'(?:^|[,\{])%s="([^"]+)"' % re.escape(label), line)
    return match.group(1) if match else None


def observe_passively(lab):
    statuses = {member: status_for_member(lab, member) for member in MEMBERS}
    ids = {member: int(statuses[member]["header"]["member_id"]) for member in MEMBERS}
    cluster_ids = {str(statuses[member]["header"]["cluster_id"]) for member in MEMBERS}
    leaders = {int(statuses[member]["leader"]) for member in MEMBERS}
    if (len(set(ids.values())) != 3 or len(cluster_ids) != 1 or len(leaders) != 1
            or next(iter(leaders), "") not in set(ids.values())):
        lab.block("The passive sample did not observe three distinct members of one cluster and one leader")
    raw = {"member_status": {}, "metric_lines": {}}
    coverage = {}
    prom_series = []
    time.sleep(INITIAL_PEER_OBSERVATION_SECONDS)
    for member in MEMBERS:
        lines = metric_lines_for_member(lab, member)
        peer_labels = {label_value(line, "To") for line in lines
                       if line.startswith(PEER_FAMILY + "{") and label_value(line, "le") == "+Inf"}
        observed_to = {int(label, 16) for label in peer_labels
                       if label and re.fullmatch(r"[0-9A-Fa-f]{1,16}", label)}
        expected_to = set(ids.values()) - {ids[member]}
        coverage[member] = observed_to == expected_to and len(peer_labels) == len(expected_to)
        raw["member_status"][member] = {
            "scraped_pod": member,
            "member_id_hex": format(ids[member], "x"),
            "cluster_id": str(statuses[member]["header"]["cluster_id"]),
            "leader_id_hex": format(int(statuses[member]["leader"]), "016x"),
            "version": statuses[member].get("version", ""),
        }
        raw["metric_lines"][member] = lines
        for line in lines:
            match = re.fullmatch(r"([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([^\s]+)", line)
            if not match:
                lab.block("A filtered etcd metric sample did not parse")
            metric, rendered_labels, value = match.groups()
            labels = dict(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"', rendered_labels or ""))
            labels.update({"job": "etcd", "cluster": "fixture-three", "instance": member})
            label_text = ",".join('%s="%s"' % item for item in sorted(labels.items()))
            prom_series.append({"series": "%s{%s}" % (metric, label_text),
                                "values": "%sx8" % value})
    (lab.evidence / "etcd-peer-telemetry-raw.json").write_text(json.dumps({
        "scope": "one read-only scrape per owned synthetic member; no fault injection or etcd writes",
        "expected_peer_count_per_member": 2,
        "member_id_to_target_and_peer_labels": raw,
    }, indent=2, sort_keys=True) + "\n")
    valid = all(coverage.values())
    lab.check("positive", "Three passive etcd samples cover each member's exact two remote peer IDs",
              valid, {"member_sample_count": len(MEMBERS),
                      "each_member_has_two_expected_peer_ids": valid,
                      "single_cluster_and_leader": True})
    return {"input_series": prom_series, "quorum_observed": len(statuses) == 3 and len(leaders) == 1}


def quorum_rule_tests():
    """Synthetic PromQL inputs; custom inventory/quorum metrics are not etcd-native."""
    def s(metric, instance, value, cluster="fixture-three"):
        return {"series": '%s{job="etcd",cluster="%s",instance="%s"}' % (metric, cluster, instance),
                "values": value}

    def expected(name, minute, labels=None):
        return {"alertname": name, "eval_time": "%dm" % minute,
                "exp_alerts": [] if labels is None else [{"exp_labels": labels}]}

    cluster = {"job": "etcd", "cluster": "fixture-three"}
    return [
        {"name": "synthetic-three-member-healthy-quorum-and-scrapes",
         "input_series": [*[s("etcd_expected_member", member, "1x5") for member in MEMBERS],
                          *[s("up", member, "1x5") for member in MEMBERS],
                          {"series": 'etcd_expected_cluster{job="etcd",cluster="fixture-three"}', "values": "1x5"},
                          {"series": 'etcd_cluster_quorum_available{job="etcd",cluster="fixture-three"}', "values": "1x5"}],
         "alert_rule_test": [expected("EtcdMemberScrapeUnknown", 3),
                             expected("EtcdQuorumUnknown", 3), expected("EtcdQuorumUnavailable", 3)]},
        {"name": "synthetic-confirmed-quorum-loss-known-scrapes",
         "input_series": [*[s("etcd_expected_member", member, "1x5") for member in MEMBERS],
                          *[s("up", member, "1x5") for member in MEMBERS],
                          {"series": 'etcd_expected_cluster{job="etcd",cluster="fixture-three"}', "values": "1x5"},
                          {"series": 'etcd_cluster_quorum_available{job="etcd",cluster="fixture-three"}', "values": "0x5"}],
         "alert_rule_test": [expected("EtcdQuorumUnavailable", 1),
                             expected("EtcdQuorumUnavailable", 3, cluster),
                             expected("EtcdQuorumUnknown", 3), expected("EtcdMemberScrapeUnknown", 3)]},
        {"name": "synthetic-unknown-member-scrape-does-not-claim-quorum-loss",
         "input_series": [*[s("etcd_expected_member", member, "1x5") for member in MEMBERS],
                          s("up", MEMBERS[0], "1x5"), s("up", MEMBERS[1], "1x5"),
                          {"series": 'etcd_expected_cluster{job="etcd",cluster="fixture-three"}', "values": "1x5"}],
         "alert_rule_test": [expected("EtcdMemberScrapeUnknown", 1),
                             expected("EtcdMemberScrapeUnknown", 3,
                                      {**cluster, "instance": MEMBERS[2]}),
                             expected("EtcdQuorumUnknown", 3, cluster),
                             expected("EtcdQuorumUnavailable", 3)]},
    ]


def passive_peer_promtool_test(observation):
    """Promtool receives the actual one-pass peer series plus derived topology inventory."""
    series = []
    for member in MEMBERS:
        labels = {"job": "etcd", "cluster": "fixture-three", "instance": member}
        label_text = ",".join('%s="%s"' % item for item in sorted(labels.items()))
        series.extend([
            {"series": "up{%s}" % label_text, "values": "1x8"},
            {"series": "etcd_expected_peer_count{%s}" % label_text, "values": "2x8"},
        ])
    series.extend(observation["input_series"])
    series.extend([
        {"series": 'etcd_expected_cluster{job="etcd",cluster="fixture-three"}', "values": "1x8"},
        {"series": 'etcd_cluster_quorum_available{job="etcd",cluster="fixture-three"}',
         "values": "1x8" if observation["quorum_observed"] else "0x8"},
    ])
    return {"name": "passive-three-member-peer-and-derived-quorum-profile",
            "input_series": series,
            "alert_rule_test": [
                {"alertname": name, "eval_time": "7m", "exp_alerts": []}
                for name in ("EtcdTelemetryUnavailable", "EtcdNoLeader", "EtcdPeerTelemetryUnavailable",
                             "EtcdMemberScrapeUnknown", "EtcdQuorumUnknown", "EtcdQuorumUnavailable")
            ]}


def cleanup(lab):
    result = kubectl(lab, "delete", "namespace/" + NAMESPACE, "--ignore-not-found=true",
                     timeout=45, allow_failure=True)
    if result.returncode:
        lab.block("The owned passive etcd namespace cleanup could not be confirmed")
