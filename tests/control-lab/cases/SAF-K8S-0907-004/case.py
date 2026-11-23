"""Live TokenReview and named-store authorization case for an owned Kind fixture."""
import importlib.util
import json
from pathlib import Path

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
NS = "saf-test"
AUDIENCE = "saf-feature-store"
READER = "fixture-feature-reader"
VERIFIER = "fixture-feature-verifier"
IMAGE_CONFIG = "fixture-feature-store-code"
TRUST = "fixture-feature-store-trust"
TLS_SECRET = "fixture-feature-store-tls"
BASELINE = "fixture-feature-store-baseline"
SCOPED = "fixture-feature-store-scoped"
CLIENT = "fixture-feature-store-reader"
RBAC = "rbac.authorization.k8s.io/v1"
SCOPE = (
    "A named ServiceAccount presents a short-lived projected token for the feature-store audience. "
    "Both owned TLS gateways call live Kubernetes TokenReview; a coarse authenticated baseline "
    "reads two fixed synthetic groups while a scoped gateway allows only one named group across "
    "separate online and offline read paths. Rows retain status, returned fixed values, group, "
    "store, and definition version. The Kubernetes API also enforces object-specific rights on "
    "separate immutable backing ConfigMaps. Evidence contains no bearer tokens."
)


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind,
                       "metadata": {"name": name}, **fields})


def runtime_image(lab):
    # The shared runner owns image setup; do not substitute a local copy.
    runner = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_k8s_runtime", runner)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load paired runtime helper: {runner}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_runtime(lab)


def prerequisites(lab):
    create(lab, "ServiceAccount", READER, automountServiceAccountToken=False)
    for name in (BASELINE, SCOPED):
        create(lab, "ServiceAccount", name, automountServiceAccountToken=True)
    create(lab, "ClusterRole", VERIFIER, RBAC, rules=[{
        "apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]
    }])
    create(lab, "ClusterRoleBinding", VERIFIER, RBAC,
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": VERIFIER},
           subjects=[{"kind": "ServiceAccount", "name": name, "namespace": NS}
                     for name in (BASELINE, SCOPED)])
    feature_data = json.loads((HERE / "feature_data.json").read_text())
    for store in ("online", "offline"):
        for group, definition in feature_data.items():
            create(lab, "ConfigMap", f"{group}-{store}", immutable=True, data={
                "feature.json": json.dumps({"definition_version": definition["definition_version"],
                                            "result": definition[store]})
            })
        for gateway in (BASELINE, SCOPED):
            role = f"{gateway}-{store}"
            groups = feature_data if gateway == BASELINE else ("fixture-customer-profile",)
            create(lab, "Role", role, RBAC, rules=[{
                "apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"],
                "resourceNames": [f"{group}-{store}" for group in groups],
            }])
            create(lab, "RoleBinding", role, RBAC,
                   roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role},
                   subjects=[{"kind": "ServiceAccount", "name": gateway, "namespace": NS}])
    key, cert = lab.kubeconfig.parent / "feature-store.key", lab.kubeconfig.parent / "feature-store.crt"
    dns_names = ",".join(f"DNS:{name}.{NS}.svc" for name in (BASELINE, SCOPED))
    lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", f"/CN={SCOPED}.{NS}.svc", "-addext", "subjectAltName=" + dns_names,
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                "-keyout", str(key), "-out", str(cert))
    lab.kubectl("create", "secret", "tls", TLS_SECRET, "--key=" + str(key), "--cert=" + str(cert),
                "-o", "name")
    create(lab, "ConfigMap", TRUST, immutable=True, data={"ca.crt": cert.read_text()})
    create(lab, "ConfigMap", IMAGE_CONFIG, immutable=True,
           data={"feature_store_fixture.py": (HERE / "feature_store_fixture.py").read_text()})


def launch(lab, image, name, mode=None):
    volumes = [{"name": "code", "configMap": {"name": IMAGE_CONFIG}}]
    mounts = [{"name": "code", "mountPath": "/fixture", "readOnly": True}]
    if mode:
        account = name
        command = ["python", "/fixture/feature_store_fixture.py", "serve", mode]
        volumes.append({"name": "tls", "secret": {"secretName": TLS_SECRET, "defaultMode": 0o440}})
        mounts.append({"name": "tls", "mountPath": "/certificate", "readOnly": True})
        port = 8443
    else:
        account = READER
        command = ["sleep", "3600"]
        volumes.extend([
            {"name": "identity", "projected": {"sources": [{"serviceAccountToken": {
                "path": "token", "audience": AUDIENCE, "expirationSeconds": 600}}]}},
            {"name": "trust", "configMap": {"name": TRUST}},
        ])
        mounts.extend([{"name": "identity", "mountPath": "/identity", "readOnly": True},
                       {"name": "trust", "mountPath": "/trust", "readOnly": True}])
        port = None
    unit = container("fixture", image=image, imagePullPolicy="Never", command=command,
                     volumeMounts=mounts)
    if mode:
        unit["readinessProbe"] = {"tcpSocket": {"port": port}, "periodSeconds": 1}
    request = pod(name, [unit], serviceAccountName=account,
                  automountServiceAccountToken=bool(mode), volumes=volumes,
                  securityContext={"fsGroup": 65534})
    request["metadata"]["labels"] = {"app": name}
    lab.create(request)
    if mode:
        create(lab, "Service", name, spec={"selector": {"app": name},
               "ports": [{"port": 8443, "targetPort": 8443}]})


def request(lab, group, store, version, gateway=SCOPED, credential="token"):
    result = lab.kubectl("exec", CLIENT, "--", "python", "/fixture/feature_store_fixture.py",
                         "probe", f"{gateway}.{NS}.svc", group, store, version, credential, timeout=20)
    return json.loads(result.stdout)


def body(row):
    return row["body"]


def read_ok(row, group, store, version):
    value = body(row)
    return (row["http_status"] == 200 and value.get("decision") == "allowed"
            and value.get("group") == group and value.get("store") == store
            and value.get("definition_version") == version and value.get("result") is not None)


def gateway_events(lab, name):
    lines = lab.kubectl("logs", "pod/" + name).stdout.splitlines()
    return [json.loads(line) for line in lines if line.startswith("{") and '"event":"feature-read"' in line]


def run(lab):
    image = runtime_image(lab)
    prerequisites(lab)
    launch(lab, image, BASELINE, "baseline")
    launch(lab, image, SCOPED, "scoped")
    launch(lab, image, CLIENT)
    for name in (BASELINE, SCOPED, CLIENT):
        ready(lab, name)
    for gateway in (BASELINE, SCOPED):
        lab.kubectl("exec", CLIENT, "--", "python", "/fixture/feature_store_fixture.py",
                    "ready", f"{gateway}.{NS}.svc", timeout=27)

    group_a, group_b = "fixture-customer-profile", "fixture-device-health"
    baseline_rows = [
        request(lab, group_a, "offline", "profile-v1", BASELINE),
        request(lab, group_a, "online", "profile-v1", BASELINE),
        request(lab, group_b, "offline", "health-v1", BASELINE),
        request(lab, group_b, "online", "health-v1", BASELINE),
    ]
    baseline = {
        "authenticated_reader_reads_both_groups_and_both_stores": all(row["http_status"] == 200
                                                                       for row in baseline_rows),
        "offline_rows_retain_history": len(body(baseline_rows[0]).get("result", [])) == 2
                                       and len(body(baseline_rows[2]).get("result", [])) == 2,
        "online_rows_return_latest_only": body(baseline_rows[1]).get("result", {}).get("event_time")
                                           == "2026-01-02T00:00:00Z"
                                           and body(baseline_rows[3]).get("result", {}).get("event_time")
                                           == "2026-01-02T00:00:00Z",
        "definition_versions_are_explicit": [body(row).get("definition_version") for row in baseline_rows]
                                            == ["profile-v1", "profile-v1", "health-v1", "health-v1"],
    }
    baseline_ok = all(baseline.values())
    lab.check("red", "Coarse authenticated identity can read both owned groups in both stores",
              baseline_ok, baseline)

    scoped_rows = [
        request(lab, group_a, "offline", "profile-v1"),
        request(lab, group_a, "online", "profile-v1"),
        request(lab, group_b, "offline", "health-v1"),
        request(lab, group_b, "online", "health-v1"),
        request(lab, group_a, "online", "profile-v2"),
    ]
    backend_rows = {
        f"{gateway}/{group}/{store}": int(lab.kubectl(
            "exec", gateway, "--", "python", "/fixture/feature_store_fixture.py",
            "backend", group, store, timeout=12).stdout)
        for gateway, group in ((BASELINE, group_b), (SCOPED, group_a), (SCOPED, group_b))
        for store in ("online", "offline")
    }
    green = {
        "live_backend_rbac_checks_both_gateways_and_stores": backend_rows == {
            f"{gateway}/{group}/{store}": expected
            for gateway, group, expected in ((BASELINE, group_b, 200), (SCOPED, group_a, 200),
                                             (SCOPED, group_b, 403))
            for store in ("online", "offline")
        },
        "named_group_allowed_in_both_stores": read_ok(scoped_rows[0], group_a, "offline", "profile-v1")
                                              and read_ok(scoped_rows[1], group_a, "online", "profile-v1"),
        "other_named_group_denied_in_both_stores_without_data": all(
            row["http_status"] == 403 and body(row) == {
                "status": 403, "decision": "denied", "result": None
            } for row in scoped_rows[2:4]),
        "unknown_definition_version_has_no_data": scoped_rows[4]["http_status"] == 404
                                                  and body(scoped_rows[4]).get("result") is None,
        "offline_is_historical_and_online_is_latest": len(body(scoped_rows[0])["result"]) == 2
            and body(scoped_rows[1])["result"]["risk_band"] == "green",
    }
    green_ok = all(green.values())
    lab.check("green", "Scoped permission allows the named group and blocks the other group before retrieval",
              green_ok, green)

    unauthenticated = request(lab, group_a, "online", "profile-v1", credential="no-token")
    positive_row = request(lab, group_a, "offline", "profile-v1")
    positive = {
        "credential_is_required": unauthenticated["http_status"] == 401
                                  and body(unauthenticated) == {
                                      "status": 401, "decision": "unauthenticated", "result": None
                                  },
        "named_reader_retains_authorized_historical_access": read_ok(
            positive_row, group_a, "offline", "profile-v1")
            and len(body(positive_row)["result"]) == 2,
        "scoped_gateway_events_match_decisions": gateway_events(lab, SCOPED) == [
            {"event": "feature-read", "principal": "fixture-reader", "group": group_a,
             "store": "offline", "decision": "allowed"},
            {"event": "feature-read", "principal": "fixture-reader", "group": group_a,
             "store": "online", "decision": "allowed"},
            {"event": "feature-read", "principal": "fixture-reader", "group": group_b,
             "store": "offline", "decision": "denied"},
            {"event": "feature-read", "principal": "fixture-reader", "group": group_b,
             "store": "online", "decision": "denied"},
            {"event": "feature-read", "principal": "fixture-reader", "group": group_a,
             "store": "online", "decision": "version-not-found"},
            {"event": "feature-read", "principal": "unverified", "group": group_a,
             "store": "online", "decision": "unauthenticated"},
            {"event": "feature-read", "principal": "fixture-reader", "group": group_a,
             "store": "offline", "decision": "allowed"},
        ],
    }
    positive_ok = all(positive.values())
    lab.check("positive", "Unauthenticated reads fail while the named reader retains allowed access",
              positive_ok, positive)

    evidence = {
        "case": "feature-store-scoped-access-v1",
        "principal": "fixture-feature-reader",
        "audience": AUDIENCE,
        "groups": [group_a, group_b],
        "baseline": {"checks": baseline, "measured_rows": baseline_rows},
        "scoped": {"checks": green, "measured_rows": scoped_rows,
                   "gateway_events": gateway_events(lab, SCOPED), "backend_http_status": backend_rows},
        "positive": {"checks": positive, "unauthenticated_row": unauthenticated,
                     "allowed_row": positive_row},
        "semantics": {"offline": "historical event-time rows", "online": "latest entity value",
                      "version": "definition metadata label; not a historical storage snapshot"},
        "sanitization": "fixed synthetic values only; bearer tokens, runtime timestamps, and cluster identifiers omitted",
    }
    (lab.evidence / "feature-store-access-observations.json").write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n")
