"""Exercise offline advisory integrity, expiry quarantine, and exact enrichment."""
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
from tempfile import TemporaryDirectory

from lab import NAMESPACE


HERE = Path(__file__).resolve().parent
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
WORKER_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
BUNDLE_SHA256 = "99b0a2d0515a4551e9038413265e1c0b972ccf20f294e6ed38c03327cc29917b"
JOB_NAME = "saf-1004-004-offline-fixture"
CONFIG_NAME = "saf-1004-004-offline-fixture"
AS_OF = "2026-11-21T12:00:00Z"
SCOPE = (
    "Offline, synthetic threat-intelligence fixture processing in a disposable Kubernetes v1.36.1 Kind cluster. "
    "Verifies SHA-256 pin quarantine, expiry quarantine, exact advisory enrichment for one approved mock "
    "observation, quiet package-version/image-digest near misses, and one case-owned HTTPS source with pinned local "
    "trust and fixed public synthetic bytes. A separate tokenless Job reads the official Kubernetes JSON feed with "
    "standard certificate and hostname validation. It verifies and records source and publication metadata. "
    "A local fixed-route counterfactual adds one bounded 503-to-200 retry over the same pinned synthetic bundle. "
    "Deployed ingestion freshness, coverage, threat-sharing and SIEM/SOAR decisions require adopter evidence."
)


def load(name):
    return (HERE / "fixtures" / name).read_bytes()


def expected_enrichment():
    observation = json.loads(load("observations.json"))[0]
    return {
        "observation_id": observation["observation_id"],
        "asset_ref": observation["asset_ref"],
        "match": {"image_digest": observation["image_digest"],
                  "package": observation["package"], "version": observation["version"]},
        "enrichment": {
            "bundle_id": "SYNTH-BUNDLE-1004-004-01",
            "source_id": "SYNTH-SOURCE-LOCAL-ONLY",
            "advisory_id": "SYNTH-ADVISORY-1004-004-001",
            "severity": "synthetic-high",
            "fixed_version": "1.0.1",
        },
    }


def establish_transport_fixture(lab):
    host = f"saf-1004-004-feed.{NAMESPACE}.svc.cluster.local"
    with TemporaryDirectory(prefix="saf-feed-tls-", dir=lab.kubeconfig.parent) as workdir:
        root = Path(workdir)
        ca_key, ca, other_key, other = (root / name for name in ("ca.key", "ca.crt", "wrong.key", "wrong.crt"))
        key, csr, cert, extensions = (root / name for name in ("server.key", "server.csr", "server.crt", "server.ext"))
        extensions.write_text(f"subjectAltName=DNS:{host}\n"
                              "basicConstraints=critical,CA:FALSE\n"
                              "keyUsage=critical,digitalSignature,keyEncipherment\n"
                              "extendedKeyUsage=serverAuth\n"
                              "authorityKeyIdentifier=keyid,issuer\n")
        ca_defaults = ("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                       "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                       "-addext", "subjectKeyIdentifier=hash")
        commands = (
            (*ca_defaults, "-subj", "/CN=SAF fixture feed CA", "-keyout", str(ca_key), "-out", str(ca)),
            (*ca_defaults, "-subj", "/CN=SAF unrelated fixture CA", "-keyout", str(other_key), "-out", str(other)),
            ("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={host}",
             "-keyout", str(key), "-out", str(csr)),
            ("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
             "-CAcreateserial", "-days", "2", "-sha256", "-extfile", str(extensions), "-out", str(cert)),
        )
        try:
            for command in commands:
                subprocess.run(command, env=lab.env, capture_output=True, check=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            lab.block("Could not generate the case-owned HTTPS trust fixture")
        for private in (key, ca_key, other_key):
            private.chmod(0o600)
        lab.kubectl("create", "secret", "tls", "saf-1004-004-feed-tls",
                    "--cert=" + str(cert), "--key=" + str(key), "-o", "name")
        return ca.read_text(), other.read_text()


def verify_official_feed(lab):
    name = "saf-1004-004-official-metadata"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "immutable": True, "data": {"official_feed.py": load("official_feed.py").decode()}})
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 38,
                         "template": {"spec": {
                             "restartPolicy": "Never", "automountServiceAccountToken": False,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                 "seccompProfile": {"type": "RuntimeDefault"}},
                             "containers": [{
                                 "name": "metadata-reader", "image": WORKER_IMAGE,
                                 "command": ["python", "-B", "/case/official_feed.py"],
                                 "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                               "limits": {"cpu": "200m", "memory": "80Mi"}},
                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                     "readOnlyRootFilesystem": True,
                                                     "capabilities": {"drop": ["ALL"]}},
                                 "volumeMounts": [{"name": "code", "mountPath": "/case", "readOnly": True}],
                             }],
                             "volumes": [{"name": "code", "configMap": {"name": name}}],
                         }}}})
    lab.kubectl("wait", "job/" + name, "--for=condition=complete", "--timeout=45s", timeout=54)
    raw = lab.kubectl("logs", "job/" + name, timeout=15).stdout
    (lab.evidence / "official-feed-metadata.raw.json").write_text(raw)
    try:
        observed = json.loads(raw)
    except json.JSONDecodeError as error:
        lab.block(f"The official feed worker did not return its bounded metadata report: {error}")
    if observed.get("read_status") == "unavailable":
        lab.block("The owned Job could not retrieve the reviewed official HTTPS endpoint")
    source = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
    projection = observed.get("projection", {})
    matches = (observed.get("source") == source
               and observed.get("ssl_default_verification") is True
               and observed.get("http_status") == 200 and observed.get("media_type") == "application/json"
               and 0 < observed.get("body_bytes", 0) <= 2 * 1024 * 1024
               and projection.get("version") == "https://jsonfeed.org/version/1.1"
               and projection.get("unique_records", 0) > 0)
    lab.check("positive", "A tokenless Job reads the official HTTPS advisory feed and validates publication metadata",
              matches, {"source": source, "verified_https": observed.get("ssl_default_verification"),
                        "status": observed.get("http_status"), "schema_and_time_checks": bool(projection),
                        "nonempty_unique_records": projection.get("unique_records", 0) > 0})


def run(lab):
    trusted_ca, unrelated_ca = establish_transport_fixture(lab)
    ca_sha256 = hashlib.sha256(trusted_ca.encode()).hexdigest()
    token = secrets.token_urlsafe(32)
    with TemporaryDirectory(prefix="saf-feed-auth-", dir=lab.kubeconfig.parent) as workdir:
        token_file = Path(workdir) / "token"
        token_file.write_text(token)
        token_file.chmod(0o600)
        lab.kubectl("create", "secret", "generic", "saf-1004-004-feed-auth",
                    "--from-file=token=" + str(token_file), "-o", "name")
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIG_NAME, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control-1004-004": "synthetic-fixture"}},
        "data": {
            "worker.py": load("worker.py").decode(),
            "feed_server.py": load("feed_server.py").decode(),
            "https_worker.py": load("https_worker.py").decode(),
            "approved-bundle.json": load("approved-bundle.json").decode(),
            "damaged-bundle.json": load("damaged-bundle.json").decode(),
            "observations.json": load("observations.json").decode(),
            "tls-ca.crt": trusted_ca,
            "wrong-ca.crt": unrelated_ca,
        },
    })
    lab.create({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "saf-1004-004-feed", "namespace": NAMESPACE,
                     "labels": {"app": "saf-1004-004-feed",
                                "saf-k8s.example/control-1004-004": "synthetic-fixture"}},
        "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "fsGroup": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "feed", "image": WORKER_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "/case/feed_server.py"],
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "ports": [{"name": "https", "containerPort": 8443}],
                "readinessProbe": {"tcpSocket": {"port": 8443}, "periodSeconds": 1,
                                   "timeoutSeconds": 1, "failureThreshold": 30},
                "volumeMounts": [
                    {"name": "fixture", "mountPath": "/case", "readOnly": True},
                    {"name": "tls", "mountPath": "/tls", "readOnly": True},
                    {"name": "auth", "mountPath": "/auth", "readOnly": True},
                ],
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "48Mi"}},
            }],
            "volumes": [
                {"name": "fixture", "configMap": {"name": CONFIG_NAME, "defaultMode": 292}},
                {"name": "tls", "secret": {"secretName": "saf-1004-004-feed-tls", "defaultMode": 288}},
                {"name": "auth", "secret": {"secretName": "saf-1004-004-feed-auth", "defaultMode": 288}},
            ],
        },
    })
    lab.create({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "saf-1004-004-feed", "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control-1004-004": "synthetic-fixture"}},
        "spec": {"type": "ClusterIP", "selector": {"app": "saf-1004-004-feed"},
                 "ports": [{"name": "https", "port": 443, "targetPort": 8443}]},
    })
    lab.kubectl("wait", "pod/saf-1004-004-feed", "--for=condition=Ready", "--timeout=90s", timeout=100)
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": JOB_NAME, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control-1004-004": "synthetic-fixture"}},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 90,
            "template": {
                "metadata": {"labels": {"saf-k8s.example/control-1004-004": "synthetic-fixture"}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": "offline-fixture-worker", "image": WORKER_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/case/worker.py"],
                        "env": [
                            {"name": "EXPECTED_BUNDLE_SHA256", "value": BUNDLE_SHA256},
                            {"name": "CASE_AS_OF", "value": AS_OF},
                        ],
                        "securityContext": {"allowPrivilegeEscalation": False,
                                             "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}},
                        "volumeMounts": [{"name": "fixture", "mountPath": "/case", "readOnly": True}],
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "250m", "memory": "64Mi"}},
                    }],
                    "volumes": [{"name": "fixture", "configMap": {"name": CONFIG_NAME,
                                                                       "defaultMode": 292}}],
                },
            },
        },
    })
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": "saf-1004-004-https-intake", "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control-1004-004": "synthetic-fixture"}},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 60,
            "template": {
                "metadata": {"labels": {"saf-k8s.example/control-1004-004": "synthetic-fixture"}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "fsGroup": 65532,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": "https-intake", "image": WORKER_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/case/https_worker.py"],
                        "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                                {"name": "EXPECTED_CA_SHA256", "value": ca_sha256}],
                        "securityContext": {"allowPrivilegeEscalation": False,
                                             "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}},
                        "volumeMounts": [{"name": "fixture", "mountPath": "/case", "readOnly": True},
                                         {"name": "auth", "mountPath": "/auth", "readOnly": True}],
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "100m", "memory": "48Mi"}},
                    }],
                    "volumes": [{"name": "fixture", "configMap": {"name": CONFIG_NAME,
                                                                          "defaultMode": 292}},
                                {"name": "auth", "secret": {"secretName": "saf-1004-004-feed-auth",
                                                                "defaultMode": 288}}],
                },
            },
        },
    })
    lab.kubectl("wait", "job/saf-1004-004-https-intake", "--for=condition=complete",
                "--timeout=90s", timeout=100)
    intake_raw = lab.kubectl("logs", "job/saf-1004-004-https-intake").stdout.strip()
    (lab.evidence / "https-intake.raw.json").write_text(intake_raw + "\n")
    try:
        intake = json.loads(intake_raw)
    except json.JSONDecodeError as error:
        lab.block(f"HTTPS intake worker returned no machine-readable result ({error})")
    approved_http = intake["approved_fetch"]
    approved_eval = intake["approved_evaluator"]
    modified_eval = intake["modified_evaluator"]
    expired_eval = intake["expired_evaluator"]
    lab.check(
        "green",
        "Pinned in-cluster HTTPS source feeds the existing evaluator; changed and expired bytes quarantine and wrong trust fails closed",
        intake["ready"] is True and intake["ca_sha256_matches_independent_pin"] is True
        and approved_http["tls_verified"] is True and approved_http["status"] == 200
        and approved_http["sha256"] == BUNDLE_SHA256
        and approved_eval["accepted"] is True and approved_eval["enrichment_count"] == 1
        and approved_eval["quiet_ids"] == ["OBS-SYNTH-NEARMISS-VERSION", "OBS-SYNTH-NEARMISS-IMAGE"]
        and modified_eval == {"accepted": False, "reason": "digest_mismatch", "enrichment_count": 0}
        and expired_eval == {"accepted": False, "reason": "expired"}
        and intake["wrong_ca_certificate_rejected"] is True,
        {"ca_sha256_matches_independent_pin": intake["ca_sha256_matches_independent_pin"],
         "approved_fetch": approved_http, "approved_evaluator": approved_eval,
         "modified_evaluator": modified_eval, "expired_evaluator": expired_eval,
         "wrong_ca_certificate_rejected": intake["wrong_ca_certificate_rejected"]},
    )
    unavailable = intake["unavailable_source"]
    lab.check(
        "red",
        "An authenticated synthetic source outage returns bounded 503 metadata and suppresses enrichment",
        unavailable["unauthenticated_status"] == 401
        and unavailable["unauthenticated_body_bytes"] == 0
        and unavailable["authenticated_ready_status"] == 200
        and unavailable["authenticated_ready_sha256"] == BUNDLE_SHA256
        and unavailable["authenticated_ready_evaluator"] == {
            "accepted": True, "reason": None, "enrichment_count": 1}
        and unavailable["authenticated_status"] == 503
        and unavailable["authenticated_body_bytes"] == 0
        and unavailable["retry_after_seconds"] == "30"
        and unavailable["evaluator"] == {"accepted": False, "reason": "source_unavailable",
                                          "enrichment_count": 0},
        unavailable,
    )
    lab.kubectl("wait", f"job/{JOB_NAME}", "--for=condition=complete", "--timeout=120s", timeout=130)
    raw = lab.kubectl("logs", f"job/{JOB_NAME}").stdout.strip()
    (lab.evidence / "ingestion.raw.json").write_text(raw + "\n")
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as error:
        lab.block(f"Fixture worker returned no machine-readable result ({error})")

    baseline = result["baseline_unpinned"]
    lab.check("red", "An unpinned bundle is quarantined with no enrichment",
              baseline["accepted"] is False and baseline["quarantine_reason"] == "missing_digest_pin"
              and baseline["enrichments"] == [],
              {"accepted": baseline["accepted"], "reason": baseline["quarantine_reason"],
               "enrichment_count": len(baseline["enrichments"])})

    damaged = result["damaged"]
    lab.check("red", "A bundle changed after pinning is quarantined with no enrichment",
              damaged["accepted"] is False and damaged["quarantine_reason"] == "digest_mismatch"
              and damaged["enrichments"] == [],
              {"accepted": damaged["accepted"], "reason": damaged["quarantine_reason"],
               "enrichment_count": len(damaged["enrichments"]),
               "observed_sha256": damaged["bundle_sha256"]})

    expired = result["expired"]
    lab.check("red", "A correctly pinned but expired bundle is quarantined",
              expired["accepted"] is False and expired["quarantine_reason"] == "expired"
              and expired["enrichments"] == [],
              {"accepted": expired["accepted"], "reason": expired["quarantine_reason"],
               "enrichment_count": len(expired["enrichments"]),
               "bundle_sha256": expired["bundle_sha256"]})

    approved = result["approved"]
    lab.check("green", "The approved synthetic observation receives exact defensive enrichment",
              approved["accepted"] is True and approved["enrichments"] == [expected_enrichment()],
              approved["enrichments"])
    lab.check("positive", "Package-version and image-digest near misses remain quiet",
              approved["quiet_observation_ids"] == ["OBS-SYNTH-NEARMISS-VERSION",
                                                     "OBS-SYNTH-NEARMISS-IMAGE"],
              approved["quiet_observation_ids"])
    verify_official_feed(lab)

    recovery = intake["bounded_recovery"]
    lab.check(
        "positive",
        "One bounded local 503 produces no enrichment, then one retry of the same pinned bytes recovers one exact match",
        recovery == {
            "attempt_count": 2, "first_status": 503, "first_body_bytes": 0,
            "retry_after_seconds": "1", "first_accepted": False,
            "first_reason": "source_unavailable", "first_enrichment_count": 0,
            "second_status": 200,
            "second_body_bytes": len(load("approved-bundle.json")),
            "second_sha256": BUNDLE_SHA256,
            "second_evaluator": {"accepted": True, "reason": None,
                                 "enrichments": [expected_enrichment()]},
            "recovered": True,
        }, recovery)
