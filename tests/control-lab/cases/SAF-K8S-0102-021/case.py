"""Check the etcd expiry inventory and exercise an isolated Prometheus rule."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import tempfile


HERE = Path(__file__).parent
PROM_IMAGE = (
    "docker.io/prom/prometheus:v3.5.0@sha256:"
    "63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
)
LEAD_SECONDS = 30 * 24 * 60 * 60
CERTIFICATES = {
    "etcd-server": "/etc/kubernetes/pki/etcd/server.crt",
    "etcd-peer": "/etc/kubernetes/pki/etcd/peer.crt",
    "apiserver-etcd-client": "/etc/kubernetes/pki/apiserver-etcd-client.crt",
}
METRIC = "saf_etcd_certificate_time_to_expiry_seconds"
SCOPE = (
    "On the harness's pinned kubeadm v1.36.1 kind control-plane node, inspect only public "
    "notAfter values and etcd-CA verification for etcd-server, etcd-peer and "
    "apiserver-etcd-client. Evaluate a case-owned Prometheus expiry rule with one healthy "
    "observed inventory sample and controlled synthetic samples around an example 30-day "
    "lead time and a five-minute per-role missing-series hold. The metric is a synthetic telemetry contract, not a claim that kubeadm "
    "exports this Prometheus metric. No private key, notification route, production cluster, "
    "external etcd, externally managed certificate, or real alert delivery is tested."
)


def parse_expiry(value):
    match = re.fullmatch(r"notAfter=(.+)", value.strip())
    if not match:
        raise ValueError("Unexpected OpenSSL certificate date output")
    parsed = datetime.strptime(match.group(1), "%b %d %H:%M:%S %Y %Z")
    return parsed.replace(tzinfo=timezone.utc)


def inspect_inventory(lab, node):
    now = datetime.now(timezone.utc)
    records = {}
    for name, path in CERTIFICATES.items():
        date_output = lab.command(
            "docker", "exec", node, "openssl", "x509", "-in", path,
            "-noout", "-enddate",
        ).stdout.strip()
        expiry = parse_expiry(date_output)
        verification = lab.command(
            "docker", "exec", node, "openssl", "verify", "-purpose", "any",
            "-CAfile", "/etc/kubernetes/pki/etcd/ca.crt", path,
            allow_failure=True,
        )
        trusted = verification.returncode == 0 and verification.stdout.strip() == f"{path}: OK"
        remaining = int((expiry - now).total_seconds())
        records[name] = {
            "not_after_utc": expiry.isoformat(),
            "remaining_seconds": remaining,
            "currently_valid": remaining > 0,
            "trusted_by_local_etcd_ca": trusted,
        }
    return records


def sample(metric, certificate, values):
    return {
        "series": f'{metric}{{certificate="{certificate}",cluster="synthetic-kind"}}',
        "values": values,
    }


def alert_test(alert, minute, expected_certificate=None):
    expected = [] if expected_certificate is None else [{
        "exp_labels": {
            "certificate": expected_certificate,
            "cluster": "synthetic-kind",
            "severity": "warning",
        },
    }]
    return {"alertname": alert, "eval_time": f"{minute}m",
            "exp_alerts": expected}


def test_groups(inventory):
    healthy_series = [
        sample(METRIC, name, f'{record["remaining_seconds"]}x8')
        for name, record in inventory.items()
    ]
    groups = [{
        "name": "observed-public-certificate-inventory",
        "input_series": healthy_series,
        "alert_rule_test": [alert_test("EtcdCertificateExpirySoon", 7),
                            alert_test("EtcdCertificateTelemetryMissing", 7)],
    }]
    for certificate in CERTIFICATES:
        for label, remaining, expected in (
            ("one-second-beyond-lead", LEAD_SECONDS + 1, None),
            ("at-lead-boundary", LEAD_SECONDS, certificate),
            ("expired", -1, certificate),
        ):
            values = [
                sample(METRIC, name, f'{remaining if name == certificate else LEAD_SECONDS + 1}x8')
                for name in CERTIFICATES
            ]
            groups.append({
                "name": f"synthetic-{certificate}-{label}",
                "input_series": values,
                "alert_rule_test": [alert_test("EtcdCertificateExpirySoon", 1, expected)],
            })
        groups.append({
            "name": f"synthetic-missing-{certificate}",
            "input_series": [sample(METRIC, name, f"{LEAD_SECONDS + 1}x8")
                             for name in CERTIFICATES if name != certificate],
            "alert_rule_test": [
                alert_test("EtcdCertificateTelemetryMissing", 4),
                alert_test("EtcdCertificateTelemetryMissing", 6, certificate),
            ],
        })
    return groups


def run(lab):
    node = f"{lab.cluster}-control-plane"
    actual = inspect_inventory(lab, node)
    complete = set(actual) == set(CERTIFICATES)
    lab.check(
        "positive",
        "The exact kubeadm server, peer and API-server-client public certificate inventory is current and etcd-CA trusted",
        complete and all(item["currently_valid"] and item["trusted_by_local_etcd_ca"]
                         for item in actual.values()),
        actual,
    )

    tests = test_groups(actual)
    first_synthetic = tests[2]
    with tempfile.TemporaryDirectory(prefix="saf-etcd-expiry-promtool-") as temp:
        root = Path(temp).resolve()
        root.chmod(0o755)
        shutil.copyfile(HERE / "alerts.yml", root / "alerts.yml")
        command = [
            "docker", "run", "--rm", "--network=none",
            "--mount", f"type=bind,source={root},target=/assessment,readonly",
            "--entrypoint=/bin/promtool", PROM_IMAGE, "test", "rules",
        ]
        red_file = {
            "rule_files": [], "evaluation_interval": "1m",
            "tests": [first_synthetic],
        }
        green_file = {
            "rule_files": ["alerts.yml"], "evaluation_interval": "1m",
            "tests": tests,
        }
        (root / "without-rules.yml").write_text(json.dumps(red_file, indent=2) + "\n")
        (root / "with-rules.yml").write_text(json.dumps(green_file, indent=2) + "\n")
        red = lab.command(*command, "/assessment/without-rules.yml",
                          allow_failure=True, timeout=90)
        red_output = red.stdout + red.stderr
        expected_red = (red.returncode != 0
                        and "EtcdCertificateExpirySoon" in red_output
                        and "FAILED" in red_output)
        lab.check(
            "red",
            "A synthetic certificate exactly at lead time fails the expected alert assertion when no rule is loaded",
            expected_red,
            {"exit_code": red.returncode,
             "expected_alert_assertion_failure": expected_red},
        )
        green = lab.command(*command, "/assessment/with-rules.yml",
                            allow_failure=True, timeout=90)
        lab.check(
            "green",
            "The rule stays quiet beyond the lead time and fires for each required role at the boundary and after expiry, plus sustained missing telemetry",
            green.returncode == 0,
            {"exit_code": green.returncode,
             "healthy_inventory": 1,
             "synthetic_test_groups": len(tests) - 1,
             "rule_engine_passed": green.returncode == 0},
        )
