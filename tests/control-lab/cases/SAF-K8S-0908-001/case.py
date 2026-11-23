"""Verify that a real per-principal limit protects a case-owned predictor path."""
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
NS = "saf-test"
AUDIENCE = "saf-scoped-inference"
ALPHA = "fixture-inference-alpha"
BETA = "fixture-inference-beta"
VERIFIER = "fixture-inference-verifier"
BASELINE = "fixture-inference-baseline"
ENFORCED = "fixture-inference-governed"
PREDICTOR = "fixture-synthetic-predictor"
CODE = "fixture-inference-code"
TLS = "fixture-inference-tls"
TRUST = "fixture-inference-trust"
RBAC = "rbac.authorization.k8s.io/v1"
IMAGE = "docker.io/library/python:3.13.2-alpine"
MANIFEST = {
    "aarch64": "91f983b2a023903433f6227b6c6056cedda4a335f1348d4ffbede021ab11602b",
    "arm64": "91f983b2a023903433f6227b6c6056cedda4a335f1348d4ffbede021ab11602b",
    "x86_64": "8a34ebceda7d48c11d6ec7f322807032f1f152ef121ea7f628cbd72643affd57",
    "amd64": "8a34ebceda7d48c11d6ec7f322807032f1f152ef121ea7f628cbd72643affd57",
}
SCOPE = (
    "Real Kubernetes TokenReview authenticates two temporary pod identities to a fixture TLS "
    "gateway. A bounded quota refuses one ordinary request before the independent synthetic "
    "predictor and emits a minimal attributed event. The other identity remains within its "
    "budget. This demonstrates the named serving safeguard and event path."
)


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def prerequisites(lab):
    for account in (ALPHA, BETA, VERIFIER):
        create(lab, "ServiceAccount", account, automountServiceAccountToken=False)
    create(lab, "ClusterRole", VERIFIER, RBAC, rules=[
        {"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]},
    ])
    create(lab, "ClusterRoleBinding", VERIFIER, RBAC,
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": VERIFIER},
           subjects=[{"kind": "ServiceAccount", "name": VERIFIER, "namespace": NS}])
    key, cert = (lab.kubeconfig.parent/"inference.key", lab.kubeconfig.parent/"inference.crt")
    names = ",".join(f"DNS:{name}.{NS}.svc" for name in (BASELINE, ENFORCED))
    lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", f"/CN={ENFORCED}.{NS}.svc", "-addext", "subjectAltName="+names,
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash", "-keyout", str(key), "-out", str(cert))
    lab.kubectl("create", "secret", "tls", TLS, "--key="+str(key), "--cert="+str(cert), "-o", "name")
    create(lab, "ConfigMap", TRUST, immutable=True, data={"ca.crt": cert.read_text()})
    create(lab, "ConfigMap", CODE, immutable=True,
           data={"inference_fixture.py": (HERE/"inference_fixture.py").read_text()})


def load_runtime(lab):
    engine = lab.command("docker", "info", "--format", "{{.Architecture}}", timeout=20).stdout.strip()
    digest = MANIFEST.get(engine)
    if digest is None:
        lab.block("No verified inference fixture Python manifest matches the Docker architecture")
    pinned = f"{IMAGE}@sha256:{digest}"
    cached = f"saf-k8s-fixture/python:3.13.2-{digest[:12]}"

    def image_id(reference):
        result = lab.command("docker", "image", "inspect", "--format", "{{.Id}}",
                             reference, timeout=20, allow_failure=True)
        return result.stdout.strip() if result.returncode == 0 else None

    expected = image_id(pinned)
    if not expected:
        lab.command("docker", "pull", pinned, timeout=900)
        expected = image_id(pinned)
    present = image_id(cached)
    if not expected or (present and present != expected):
        lab.block("The local fixture tag does not identify the verified Python image")
    if not present:
        lab.command("docker", "image", "tag", pinned, cached, timeout=20)
    if image_id(cached) != expected:
        lab.block("Could not validate the exact local Python fixture image")
    lab.command("kind", "load", "docker-image", cached, "--name", lab.cluster, timeout=120)
    return cached


def workload(lab, image, name, mode=None):
    mounts = [{"name": "code", "mountPath": "/fixture", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": CODE}}]
    is_gateway = mode in {"baseline", "enforced"}
    port = 8443 if is_gateway else 8080
    if mode:
        command = ["python", "/fixture/inference_fixture.py", "serve", mode]
        account = VERIFIER if is_gateway else "default"
        if is_gateway:
            mounts.append({"name": "tls", "mountPath": "/certificate", "readOnly": True})
            volumes.append({"name": "tls", "secret": {"secretName": TLS, "defaultMode": 0o440}})
    else:
        account = name
        command = ["sleep", "300"]
        mounts.extend([{"name": "identity", "mountPath": "/identity", "readOnly": True},
                       {"name": "trust", "mountPath": "/trust", "readOnly": True}])
        volumes.extend([{"name": "identity", "projected": {"sources": [{"serviceAccountToken": {
                                "path": "token", "audience": AUDIENCE, "expirationSeconds": 600}}]}},
                        {"name": "trust", "configMap": {"name": TRUST}}])
    unit = container("fixture", image=image, imagePullPolicy="Never", command=command, volumeMounts=mounts)
    if mode:
        unit["readinessProbe"] = {"tcpSocket": {"port": port}, "periodSeconds": 1}
    request = pod(name, [unit], automountServiceAccountToken=is_gateway, serviceAccountName=account,
                  volumes=volumes, securityContext={"fsGroup": 65534})
    request["metadata"]["labels"] = {"app": name}
    lab.create(request)
    if mode:
        create(lab, "Service", name, spec={"selector": {"app": name}, "ports": [{"port": port}]})


def calls(lab, caller, gateway, token=True):
    credential = "use-projected-token" if token else "no-credential"
    result = lab.kubectl("exec", caller, "--", "python", "/fixture/inference_fixture.py",
                         "probe", f"{gateway}.{NS}.svc", credential, timeout=18)
    return json.loads(result.stdout)


def events(lab, source):
    return [json.loads(line) for line in lab.kubectl("logs", "pod/"+source).stdout.splitlines() if line]


def worked(reply):
    return reply == {"status": 200, "decision": "approved", "result": "synthetic-label"}


def run(lab):
    image = load_runtime(lab)
    prerequisites(lab)
    for name, mode in ((PREDICTOR, "predictor"), (BASELINE, "baseline"), (ENFORCED, "enforced"),
                       (ALPHA, None), (BETA, None)):
        workload(lab, image, name, mode)
    for name in (PREDICTOR, BASELINE, ENFORCED, ALPHA, BETA):
        ready(lab, name)

    prior = [calls(lab, ALPHA, BASELINE) for _ in range(3)]
    baseline = {"all_three_ordinary_requests_reach_predictor": all(map(worked, prior)),
                "predictor_records_the_three_targets": events(lab, PREDICTOR) == [
                    {"event": "prediction", "fixture_mode": "baseline"}] * 3}
    lab.check("red", "Without the quota the same principal can invoke the predictor three times",
              all(baseline.values()), baseline)

    measured = [calls(lab, ALPHA, ENFORCED) for _ in range(3)]
    rejected_at = time.monotonic()
    emitted = events(lab, ENFORCED)
    signal = {"event": "quota-reached", "principal": f"system:serviceaccount:{NS}:{ALPHA}",
              "route": "predict", "status": 429}
    green = {"two_ordinary_requests_still_work": all(map(worked, measured[:2])),
             "third_returns_scoped_quota_signal": measured[2].get("status") == 429
             and measured[2].get("decision") == "quota-reached" and measured[2]["result"] is None
             and 0 < measured[2].get("retry_after", 0) <= 20,
             "one_minimal_attributed_alert": [row for row in emitted if row["event"]=="quota-reached"] == [signal],
             "refused_request_never_reaches_predictor": sum(
                 item["fixture_mode"]=="enforced" for item in events(lab, PREDICTOR)) == 2}
    lab.check("green", "The real authenticated quota stops forwarding and emits the expected event",
              all(green.values()), green)

    other = calls(lab, BETA, ENFORCED)
    unauthenticated = calls(lab, ALPHA, ENFORCED, token=False)
    wait = max(0, rejected_at+measured[2]["retry_after"]-time.monotonic())
    time.sleep(wait)
    restored = calls(lab, ALPHA, ENFORCED)
    positive = {"independent_approved_principal_keeps_access": worked(other),
                "credential_required": unauthenticated["status"] == 401,
                "original_principal_recovers_after_window": worked(restored),
                "only_two_additional_predictions_forwarded": sum(
                    item["fixture_mode"]=="enforced" for item in events(lab, PREDICTOR)) == 4}
    lab.check("positive", "An independent approved principal can still reach the predictor",
              all(positive.values()), positive)
    (lab.evidence / "inference-serving-observations.json").write_text(json.dumps({
        "baseline": baseline, "enforced": green, "positive": positive, "event": signal,
    }, indent=2) + "\n")
