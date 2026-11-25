"""Read passive etcd signals and execute alert rules using offline promtool."""
import json
from pathlib import Path
import re
import shutil
import tempfile

HERE = Path(__file__).parent
ETCD_IMAGE = "registry.k8s.io/etcd:3.6.8-0"
PROM_IMAGE = (
    "docker.io/prom/prometheus:v3.5.0@sha256:"
    "63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
)
SCOPE = (
    "Native readiness, endpoint status and passive metrics on one healthy v1.36.1 kind etcd "
    "member. Prometheus evaluates the actual sample for leadership and quota and separately "
    "checks labeled synthetic lag, missing telemetry and latency. Expected peer census is a separate "
    "synthetic input tested against missing, incomplete and present histogram telemetry."
)
CERTS = "/etc/kubernetes/pki/etcd"
METRICS = {
    "leader": "etcd_server_has_leader",
    "size": "etcd_mvcc_db_total_size_in_bytes",
    "quota": "etcd_server_quota_backend_bytes",
    "committed": "etcd_server_proposals_committed_total",
    "applied": "etcd_server_proposals_applied_total",
}
DISK_HISTOGRAMS = {
    "wal": "etcd_disk_wal_fsync_duration_seconds_bucket",
    "backend": "etcd_disk_backend_commit_duration_seconds_bucket",
}
PEER_HISTOGRAM = "etcd_network_peer_round_trip_time_seconds_bucket"
TARGET = {"job": "etcd", "instance": "fixture-a", "cluster": "saf-lab"}


def member_observations(lab):
    node = f"{lab.cluster}-control-plane"
    etcd_pod = f"pod/etcd-{node}"
    pods = json.loads(lab.kubectl("-n", "kube-system", "get", "pods", "-l",
                                 "component=etcd", "-o", "json").stdout)["items"]
    if len(pods) != 1:
        lab.block("Expected exactly one passive etcd member")
    etcd = next(item for item in pods[0]["spec"]["containers"] if item["name"] == "etcd")
    if etcd["image"] != ETCD_IMAGE or not pods[0]["spec"].get("hostNetwork"):
        lab.block("Expected kubeadm's pinned local etcd profile")
    endpoint = "https://127.0.0.1:2379"
    status = json.loads(lab.kubectl(
        "-n", "kube-system", "exec", etcd_pod, "-c", "etcd", "--", "etcdctl",
        f"--endpoints={endpoint}", f"--cacert={CERTS}/ca.crt",
        f"--cert={CERTS}/healthcheck-client.crt", f"--key={CERTS}/healthcheck-client.key",
        "--dial-timeout=2s", "--command-timeout=5s", "endpoint", "status", "--write-out=json",
    ).stdout)
    if len(status) != 1 or status[0]["Status"].get("errors"):
        lab.block("Expected one healthy etcd status reply")

    base = ["docker", "exec", node, "curl", "--fail", "--silent", "--show-error",
            "--max-time", "6", "--cacert", f"{CERTS}/ca.crt",
            "--cert", f"{CERTS}/healthcheck-client.crt",
            "--key", f"{CERTS}/healthcheck-client.key"]
    ready = lab.command(*base, endpoint + "/readyz").stdout.strip()

    # Capture only allowlisted sample names and values. Credentials stay on the node.
    selected = "|".join([*METRICS.values(), *DISK_HISTOGRAMS.values(), PEER_HISTOGRAM])
    exposition = lab.command(
        "docker", "exec", node, "sh", "-c",
        'curl --fail --silent --show-error --max-time 6 --cacert "$1" --cert "$2" --key "$3" "$4" > /tmp/saf-etcd-health-metrics || exit; '
        'grep -E "$5" /tmp/saf-etcd-health-metrics; result=$?; rm -f /tmp/saf-etcd-health-metrics; exit "$result"',
        "saf-metrics", f"{CERTS}/ca.crt", f"{CERTS}/healthcheck-client.crt",
        f"{CERTS}/healthcheck-client.key", endpoint + "/metrics",
        f"^({selected})([{{ ]|$)",
    ).stdout
    measurements = {}
    for name, metric in METRICS.items():
        values = re.findall(rf"(?m)^{re.escape(metric)}\s+([^\s]+)", exposition)
        if len(values) != 1:
            lab.block(f"Expected one scalar metric sample for {metric}")
        measurements[name] = int(float(values[0]))
    disk = {name: bool(re.search(rf"(?m)^{re.escape(metric)}\{{", exposition))
            for name, metric in DISK_HISTOGRAMS.items()}
    lab.check(
        "positive", "The passive member exposes real readiness, leader, quota, progress and disk metrics",
        ready == "ok" and all(disk.values()) and measurements["leader"] == 1
        and 0 <= measurements["size"] < measurements["quota"]
        and measurements["committed"] >= measurements["applied"],
        {"ready": ready == "ok", "leader_present": measurements["leader"] == 1,
         "db_below_quota": measurements["size"] < measurements["quota"],
         "apply_progress_available": measurements["committed"] >= measurements["applied"],
         "disk_histograms": disk, "peer_samples_present": PEER_HISTOGRAM in exposition},
    )
    return measurements


def series(metric, values, labels=TARGET):
    label = ",".join(f'{key}="{value}"' for key, value in labels.items())
    return {"series": f"{metric}{{{label}}}", "values": str(values)}


def assertion(alert, minute, labels=None):
    return {"alertname": alert, "eval_time": f"{minute}m",
            "exp_alerts": [] if labels is None else [{"exp_labels": labels}]}


def offline_cases(actual):
    tests = [{
        "name": "passive-leader-quota-and-local-apply-sample",
        "input_series": [series("up", "1x8"), *(
            series(metric, f"{actual[name]}x8") for name, metric in METRICS.items()
        )],
        "alert_rule_test": [assertion(name, 7) for name in (
            "EtcdTelemetryUnavailable", "EtcdNoLeader", "EtcdStorageQuotaPressure", "EtcdMemberApplyLag",
        )],
    }]
    cases = [
        ("EtcdTelemetryUnavailable", [series("up", "0x8")], TARGET),
        ("EtcdNoLeader", [series(METRICS["leader"], "0x8")], TARGET),
        ("EtcdStorageQuotaPressure",
         [series(METRICS["size"], "96x8"), series(METRICS["quota"], "100x8")], TARGET),
        ("EtcdMemberApplyLag",
         [series(METRICS["committed"], "1800x8"), series(METRICS["applied"], "100x8")], TARGET),
        ("EtcdMemberReplicationLag", [
            series(METRICS["committed"], "100x8"),
            series(METRICS["committed"], "1800x8", {**TARGET, "instance": "fixture-b"}),
        ], TARGET),
    ]
    for alert, family, options in (
        ("EtcdHighWalLatency", DISK_HISTOGRAMS["wal"], {}),
        ("EtcdHighBackendLatency", DISK_HISTOGRAMS["backend"], {}),
        ("EtcdSlowPeer", PEER_HISTOGRAM, {"To": "fixture-b"}),
    ):
        labels = {key: TARGET[key] for key in ("cluster", "instance")} | options
        buckets = [series(family, rate, {**TARGET, **options, "le": bound})
                   for bound, rate in (("0.1", "0x8"), ("1", "0+100x8"), ("+Inf", "0+100x8"))]
        cases.append((alert, buckets, labels))
    for alert, samples, labels in cases:
        tests.append({"name": f"synthetic-{alert}", "input_series": samples,
                      "alert_rule_test": [assertion(alert, 1), assertion(alert, 7, labels)]})

    # This expected-peer inventory series is synthetic test input, not an etcd
    # native metric. It distinguishes a valid singleton's absent peer family
    # from missing telemetry on a target that should observe remote peers.
    expected_peers = "etcd_expected_peer_count"
    tests.extend([
        {"name": "synthetic-singleton-peer-family-not-applicable",
         "input_series": [series("up", "1x8"), series(expected_peers, "0x8")],
         "alert_rule_test": [assertion("EtcdPeerTelemetryUnavailable", 3)]},
        {"name": "synthetic-expected-peers-but-peer-family-missing",
         "input_series": [series("up", "1x8"), series(expected_peers, "1x8")],
         "alert_rule_test": [assertion("EtcdPeerTelemetryUnavailable", 1),
                             assertion("EtcdPeerTelemetryUnavailable", 3, TARGET)]},
        {"name": "synthetic-expected-peers-with-incomplete-peer-coverage",
         "input_series": [series("up", "1x8"), series(expected_peers, "2x8"),
                           series(PEER_HISTOGRAM, "0x8", {**TARGET, "To": "fixture-b", "le": "+Inf"})],
         "alert_rule_test": [assertion("EtcdPeerTelemetryUnavailable", 3, TARGET)]},
        {"name": "synthetic-expected-peers-with-peer-family-present",
         "input_series": [series("up", "1x8"), series(expected_peers, "1x8"),
                           *[series(PEER_HISTOGRAM, "0x8", {**TARGET, "To": "fixture-b", "le": bound})
                             for bound in ("0.1", "1", "+Inf")]],
         "alert_rule_test": [assertion("EtcdPeerTelemetryUnavailable", 3)]},
    ])
    return tests


def run(lab):
    sample = member_observations(lab)
    tests = offline_cases(sample)
    with tempfile.TemporaryDirectory(prefix="saf-etcd-promtool-") as temp:
        root = Path(temp).resolve()
        root.chmod(0o755)
        shutil.copyfile(HERE / "alerts.yml", root / "alerts.yml")
        command = [
            "docker", "run", "--rm", "--network=none",
            "--mount", f"type=bind,source={root},target=/assessment,readonly",
            "--entrypoint=/bin/promtool", PROM_IMAGE, "test", "rules",
        ]
        baseline = {"rule_files": [], "evaluation_interval": "1m", "tests": [tests[2], tests[-3]]}
        active = {"rule_files": ["alerts.yml"], "evaluation_interval": "1m", "tests": tests}
        (root / "baseline.yml").write_text(json.dumps(baseline, indent=2) + "\n")
        (root / "with-rules.yml").write_text(json.dumps(active, indent=2) + "\n")
        missing = lab.command(*command, "/assessment/baseline.yml", allow_failure=True, timeout=90)
        expected_failure = (missing.returncode != 0 and "EtcdNoLeader" in missing.stderr
                            and "EtcdPeerTelemetryUnavailable" in missing.stderr and "FAILED" in missing.stderr)
        lab.check("red", "Expected leader-loss and missing-peer alerts are absent with no rules loaded",
                  expected_failure, expected_failure)
        enabled = lab.command(*command, "/assessment/with-rules.yml", allow_failure=True, timeout=90)
        lab.check("green", "Promtool distinguishes known fault and peer inventory fixtures from positive comparisons",
                  enabled.returncode == 0,
                  {"healthy_inputs": 1, "synthetic_comparisons": len(tests) - 1,
                   "rule_engine_passed": enabled.returncode == 0})
