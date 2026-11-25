"""Check the etcd expiry inventory and exercise an isolated Prometheus rule."""
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import math
from pathlib import Path
import re
import shutil
import threading
import tempfile


HERE = Path(__file__).parent
ROUTE_SPEC = importlib.util.spec_from_file_location("alert_route", HERE / "alert_route.py")
alert_route = importlib.util.module_from_spec(ROUTE_SPEC)
ROUTE_SPEC.loader.exec_module(alert_route)
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
FIXTURE_CLUSTER = "synthetic-kind"
FIXTURE_MEMBER = "control-plane-0"
MAX_SCRAPE_BYTES = 4096
SCRAPE_TIMEOUT_SECONDS = 2
MAX_SAMPLE_AGE_SECONDS = 120
MAX_FUTURE_SKEW_SECONDS = 5
VALUE_TOLERANCE_SECONDS = 5
REQUIRED_SERIES = {
    (FIXTURE_CLUSTER, FIXTURE_MEMBER, certificate) for certificate in CERTIFICATES
}
SCOPE = (
    "On the harness's pinned kubeadm v1.36.1 kind control-plane node, inspect only public "
    "notAfter values and etcd-CA verification for etcd-server, etcd-peer and "
    "apiserver-etcd-client. Scrape those exact role observations from a single loopback "
    "reference exporter, validate labels and timestamps, and evaluate a healthy Prometheus "
    "sample and controlled synthetic samples around an example 30-day "
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
            "measured_at_utc": now.isoformat(),
            "remaining_seconds": remaining,
            "currently_valid": remaining > 0,
            "trusted_by_local_etcd_ca": trusted,
        }
    return records


def stable_inventory_observation(records):
    return {
        "certificate_types": list(CERTIFICATES),
        "inventory_complete": set(records) == set(CERTIFICATES),
        "certificates": {
            name: {
                "not_after_measured": bool(record["not_after_utc"]),
                "currently_valid": record["currently_valid"],
                "trusted_by_local_etcd_ca": record["trusted_by_local_etcd_ca"],
            }
            for name, record in records.items()
        },
        "all_certificates_current_and_trusted": (
            set(records) == set(CERTIFICATES)
            and all(record["not_after_utc"]
                    and record["currently_valid"]
                    and record["trusted_by_local_etcd_ca"]
                    for record in records.values())
        ),
        "raw_evidence_file": "certificate-inventory.raw.json",
    }


def write_raw_inventory(lab, records):
    # The artifact contains public notAfter and calculated remaining-time values only.
    path = lab.evidence / "certificate-inventory.raw.json"
    path.write_text(json.dumps({"certificates": records}, indent=2) + "\n")


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


def render_reference_metrics(inventory, cluster=FIXTURE_CLUSTER, member=FIXTURE_MEMBER,
                             measured_at=None):
    """Reference-only exporter for this fixture's already inspected public leaves."""
    timestamp_ms = int((measured_at or datetime.now(timezone.utc)).timestamp() * 1000)
    rows = []
    for certificate, record in inventory.items():
        rows.append(
            f'{METRIC}{{cluster="{cluster}",member="{member}",'
            f'certificate="{certificate}"}} {record["remaining_seconds"]} {timestamp_ms}'
        )
    return ("\n".join(rows) + "\n").encode("ascii")


class _ReferenceExporterHandler(BaseHTTPRequestHandler):
    body = b""

    def setup(self):
        self.request.settimeout(SCRAPE_TIMEOUT_SECONDS)
        super().setup()

    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, format, *args):
        return


def reference_exporter_scrape(inventory):
    """Serve one bounded loopback scrape with one synchronous server thread."""
    measured_at = datetime.fromisoformat(
        next(iter(inventory.values()))["measured_at_utc"]
    )
    handler = type("CaseReferenceExporterHandler", (_ReferenceExporterHandler,), {
        "body": render_reference_metrics(inventory, measured_at=measured_at),
    })
    with HTTPServer(("127.0.0.1", 0), handler) as server:
        server.timeout = SCRAPE_TIMEOUT_SECONDS
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=SCRAPE_TIMEOUT_SECONDS)
        try:
            connection.request("GET", "/metrics")
            with connection.getresponse() as response:
                if response.status != 200:
                    raise ValueError("Reference scrape did not return metrics")
                body = response.read(MAX_SCRAPE_BYTES + 1)
                if len(body) > MAX_SCRAPE_BYTES:
                    raise ValueError("Reference scrape exceeded the byte limit")
                scraped_at = datetime.now(timezone.utc)
        finally:
            connection.close()
            thread.join(timeout=SCRAPE_TIMEOUT_SECONDS + 1)
        if thread.is_alive():
            raise TimeoutError("Reference exporter thread did not stop")
    return body, measured_at, scraped_at


def parse_bounded_scrape(body, inventory, *, now):
    """Strict parser for the tiny exposition contract; rejects ambiguity and staleness."""
    if not isinstance(body, bytes) or len(body) > MAX_SCRAPE_BYTES:
        raise ValueError("Scrape missing or over size bound")
    rows = {}
    pattern = re.compile(r'^' + re.escape(METRIC) + r'\{([^{}]*)\}\s+'
                         r'([^\s]+)\s+(\d+)\s*$')
    for raw_line in body.decode("ascii", errors="strict").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(METRIC):
            continue
        match = pattern.fullmatch(line)
        if not match:
            raise ValueError("Malformed bridge metric line")
        labels = {}
        for item in match.group(1).split(","):
            pair = re.fullmatch(r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"\\]*)"', item)
            if not pair:
                raise ValueError("Malformed bridge labels")
            key, value = pair.groups()
            if key in labels:
                raise ValueError("Duplicate bridge label")
            labels[key] = value
        if set(labels) != {"cluster", "member", "certificate"}:
            raise ValueError("Bridge labels are incomplete or unexpected")
        key = (labels["cluster"], labels["member"], labels["certificate"])
        if key in rows:
            raise ValueError("Duplicate bridge series")
        value = float(match.group(2))
        if not math.isfinite(value) or value < 0:
            raise ValueError("Bridge value is not a finite nonnegative expiry interval")
        age = now.timestamp() - int(match.group(3)) / 1000
        if age > MAX_SAMPLE_AGE_SECONDS or age < -MAX_FUTURE_SKEW_SECONDS:
            raise ValueError("Bridge sample is stale or future dated")
        rows[key] = value

    if set(rows) != REQUIRED_SERIES:
        raise ValueError("Bridge series do not match the expected member and role inventory")
    normalized = []
    for certificate in CERTIFICATES:
        key = (FIXTURE_CLUSTER, FIXTURE_MEMBER, certificate)
        if key not in rows or certificate not in inventory:
            raise ValueError("Bridge series has no matching measured public certificate")
        value = rows[key]
        if abs(value - inventory[certificate]["remaining_seconds"]) > VALUE_TOLERANCE_SECONDS:
            raise ValueError("Exporter value differs from measured public certificate expiry")
        normalized.append({
            "series": (f'{METRIC}{{cluster="{FIXTURE_CLUSTER}",member="{FIXTURE_MEMBER}",'
                       f'certificate="{certificate}"}}'),
            "values": f"{int(value)}x8",
        })
    return normalized


def bridge_parser_rejection_checks(body, inventory, measured_at):
    """Negative parser fixtures; all bytes and labels are synthetic case data."""
    lines = body.decode("ascii").splitlines()
    role_line = lines[0]
    stale_ms = int((measured_at.timestamp() - MAX_SAMPLE_AGE_SECONDS - 1) * 1000)
    stale_body = "\n".join(
        re.sub(r"\s+\d+$", f" {stale_ms}", line) for line in lines
    ).encode("ascii")
    extras = {
        "missing_role_rejected": "\n".join(lines[1:]).encode("ascii"),
        "missing_member_rejected": b"",
        "extra_role_rejected": (body + role_line.replace(
            'certificate="etcd-server"', 'certificate="unexpected-role"'
        ).encode("ascii") + b"\n"),
        "duplicate_role_rejected": (body + role_line.encode("ascii") + b"\n"),
        "unexpected_member_rejected": (body + role_line.replace(
            f'member="{FIXTURE_MEMBER}"', 'member="unexpected-member"'
        ).encode("ascii") + b"\n"),
        "stale_sample_rejected": stale_body,
        "wrong_expiry_value_rejected": ("\n".join([
            re.sub(r"} \S+ (\d+)$", r"} 0 \1", role_line), *lines[1:]
        ])).encode("ascii"),
    }
    outcomes = {}
    for name, candidate in extras.items():
        try:
            parse_bounded_scrape(candidate, inventory, now=measured_at)
        except (ValueError, UnicodeError):
            outcomes[name] = True
        else:
            outcomes[name] = False
    return outcomes


def test_groups(healthy_series):
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
    write_raw_inventory(lab, actual)
    complete = set(actual) == set(CERTIFICATES)
    stable_observation = stable_inventory_observation(actual)
    lab.check(
        "positive",
        "The exact kubeadm server, peer and API-server-client public certificate inventory is current and etcd-CA trusted",
        complete and stable_observation["all_certificates_current_and_trusted"],
        stable_observation,
    )

    scrape_body, measured_at, scraped_at = reference_exporter_scrape(actual)
    parsed_series = parse_bounded_scrape(scrape_body, actual, now=scraped_at)
    rejection_checks = bridge_parser_rejection_checks(scrape_body, actual, measured_at)
    lab.check(
        "positive",
        "The loopback reference exporter scrape matches the measured case inventory and is fresh",
        len(parsed_series) == len(REQUIRED_SERIES)
        and all(rejection_checks.values()),
        {"exact_member_role_coverage": len(parsed_series) == len(REQUIRED_SERIES),
         "sample_freshness_checked": True,
         "value_correlated_to_public_certificate_inventory": True,
         **rejection_checks},
    )

    tests = test_groups(parsed_series)
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

    alert_route.run(lab)
