"""Exercise webhook trust rotation and two-backend service resilience."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import time


HERE = Path(__file__).parent
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
WEBHOOK = "saf-0605-008"
HA_SERVICE = "saf-0605-008-ha"
BACKENDS = ("a", "b")
TIMEOUT_SECONDS = 3
PDB = "saf-0605-008-available"
SCOPE = (
    "One disposable Kubernetes v1.36.1 kind cluster, one ValidatingWebhookConfiguration, "
    "two separately addressable case-owned HTTPS backends on distinct workers behind one ClusterIP Service, "
    "and short-lived synthetic CA and server certificates. Only CREATE requests for named "
    "ConfigMaps in saf-test are matched, and all probes use server dry-run. The case checks "
    "an untrusted CA rejection with ordinary API continuity, staged CA overlap while rotating "
    "each backend certificate, direct API-server verification of each backend identity, and "
    "admission through the shared Service after one backend leaves its endpoints, a "
    "PodDisruptionBudget for the last healthy backend, and native latency instrumentation. It does not "
    "establish production automated renewal, secret distribution, topology governance, managed "
    "control-plane behavior, sustained availability, or production change controls."
)


def _kubectl(lab, *args, payload=None, timeout=35, allow_failure=False):
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        f"--request-timeout={max(5, timeout - 5)}s", *args,
    ]
    try:
        return lab.command(*command, payload=payload, timeout=timeout,
                           allow_failure=allow_failure)
    except Exception as error:
        if allow_failure:
            raise
        lab.block(f"case-owned Kubernetes request failed ({type(error).__name__})")


def _run(lab, *args, timeout=30):
    try:
        lab.command(*args, timeout=timeout)
    except Exception as error:
        lab.block(f"synthetic certificate operation failed ({type(error).__name__})")


def _make_ca(lab, directory, label):
    key, cert = directory / f"{label}.key", directory / f"{label}.crt"
    _run(lab, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj",
         f"/CN=SAF-0605-008-{label}", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash")
    return key, cert


def _make_leaf(lab, directory, ca, label, backend):
    key = directory / f"{label}-{backend}.key"
    csr = directory / f"{label}-{backend}.csr"
    cert = directory / f"{label}-{backend}.crt"
    ext = directory / f"{label}-{backend}.ext"
    ext.write_text(
        "subjectAltName=DNS:saf-0605-008-ha.saf-test.svc,"
        f"DNS:saf-0605-008-{backend}.saf-test.svc\n"
        "extendedKeyUsage=serverAuth\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "authorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n",
        encoding="ascii",
    )
    _run(lab, "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(csr), "-subj", f"/CN=saf-0605-008-{backend}")
    _run(lab, "openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca[1]),
         "-CAkey", str(ca[0]), "-CAcreateserial", "-out", str(cert), "-days", "2",
         "-extfile", str(ext))
    # The live API-server call verifies the Service DNS name separately.
    _run(lab, "openssl", "verify", "-CAfile", str(ca[1]), "-purpose", "sslserver", str(cert))
    return cert, key


def _secret(lab, name, cert, key):
    _kubectl(lab, "-n", NAMESPACE, "create", "secret", "tls",
             name, "--cert", str(cert), "--key", str(key))


def _deployment(backend, secret):
    name = f"saf-0605-008-{backend}"
    container = {
        "name": "webhook", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["python", "/fixture.py"],
        "env": [{"name": "SAF_BACKEND", "value": backend}],
        "ports": [{"name": "https", "containerPort": 8443}],
        "readinessProbe": {"tcpSocket": {"port": 8443}, "periodSeconds": 1},
        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                      "limits": {"cpu": "100m", "memory": "96Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True, "runAsNonRoot": True,
                            "runAsUser": 10001, "capabilities": {"drop": ["ALL"]}},
        "volumeMounts": [
            {"name": "code", "mountPath": "/fixture.py", "subPath": "fixture.py", "readOnly": True},
            {"name": "tls", "mountPath": "/tls", "readOnly": True},
        ],
    }
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {
            "replicas": 1, "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name, "saf-0605-008-ha": "true"}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "terminationGracePeriodSeconds": 5,
                    "nodeSelector": {"saf-0605-008.example/backend": backend},
                    "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [container],
                    "volumes": [
                        {"name": "code", "configMap": {"name": "saf-0605-008-code"}},
                        {"name": "tls", "secret": {"secretName": secret}},
                    ],
                },
            },
        },
    }


def _service(name, selector):
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": NAMESPACE},
            "spec": {"selector": selector,
                     "ports": [{"name": "https", "port": 443, "targetPort": 8443}]}}


def _install(lab, leaves):
    _kubectl(lab, "label", "namespace", NAMESPACE, "saf-0605-008.example/enabled=true", "--overwrite")
    code = {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "saf-0605-008-code", "namespace": NAMESPACE},
            "data": {"fixture.py": (HERE / "fixture.py").read_text(encoding="utf-8")}}
    items = [code]
    for backend in BACKENDS:
        secret = f"saf-0605-008-{backend}-tls"
        _secret(lab, secret, *leaves[("old", backend)])
        items.append(_deployment(backend, secret))
        items.append(_service(f"saf-0605-008-{backend}", {"app": f"saf-0605-008-{backend}"}))
    items.append(_service(HA_SERVICE, {"saf-0605-008-ha": "true"}))
    items.append({"apiVersion": "policy/v1", "kind": "PodDisruptionBudget",
                  "metadata": {"name": PDB, "namespace": NAMESPACE},
                  "spec": {"minAvailable": 1,
                           "selector": {"matchLabels": {"saf-0605-008-ha": "true"}}}})
    _kubectl(lab, "apply", "-f", "-", payload=json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))
    for backend in BACKENDS:
        _kubectl(lab, "-n", NAMESPACE, "rollout", "status", f"deployment/saf-0605-008-{backend}",
                 "--timeout=90s", timeout=100)


def _webhook(ca_bundle, service=HA_SERVICE):
    entry = {
        "name": "saf-0605-008.example.test", "admissionReviewVersions": ["v1"],
        "sideEffects": "None", "failurePolicy": "Fail", "matchPolicy": "Equivalent",
        "timeoutSeconds": TIMEOUT_SECONDS,
        "clientConfig": {"service": {"namespace": NAMESPACE, "name": service,
                                     "path": "/validate", "port": 443},
                         "caBundle": ca_bundle},
        "namespaceSelector": {"matchLabels": {"saf-0605-008.example/enabled": "true"}},
        "objectSelector": {"matchLabels": {"saf-0605-008.example/checked": "true"}},
        "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"],
                   "resources": ["configmaps"], "scope": "Namespaced"}],
    }
    return {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": WEBHOOK}, "webhooks": [entry]}


def _configure(lab, ca_certs, service=HA_SERVICE):
    bundle = base64.b64encode(b"".join(cert.read_bytes() for cert in ca_certs)).decode("ascii")
    _kubectl(lab, "apply", "-f", "-", payload=json.dumps(_webhook(bundle, service)))


def _probe(lab, name):
    resource = {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": name, "namespace": NAMESPACE,
                             "labels": {"saf-0605-008.example/checked": "true"}},
                "data": {"fixture": "synthetic harmless admission probe"}}
    return _kubectl(lab, "create", "-f", "-", "--dry-run=server", "-o", "json",
                    payload=json.dumps(resource), timeout=25, allow_failure=True)


def _backend_events(lab, backend):
    result = _kubectl(lab, "-n", NAMESPACE, "logs", f"deployment/saf-0605-008-{backend}", "--tail=50")
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]


def _fingerprint(cert):
    return hashlib.sha256(cert.read_bytes()).hexdigest()


def _wait_probe(lab, name, *, backends=BACKENDS, fingerprint=None, error_matches=None):
    deadline = time.monotonic() + 20
    while True:
        result = _probe(lab, name)
        if error_matches:
            observed = result.returncode != 0 and error_matches(result.stderr.lower())
        else:
            observed = result.returncode == 0 and any(
                event.get("event") == "admission" and event.get("probe") == name
                and event.get("backend") == backend
                and (fingerprint is None or event.get("certificate_sha256") == fingerprint)
                for backend in backends for event in _backend_events(lab, backend)
            )
        if observed or time.monotonic() >= deadline:
            return observed
        time.sleep(0.4)


def _wait_endpoints(lab, count):
    deadline = time.monotonic() + 20
    while True:
        result = _kubectl(lab, "-n", NAMESPACE, "get", "endpointslices",
                          "-l", f"kubernetes.io/service-name={HA_SERVICE}", "-o", "json")
        ready = [entry for item in json.loads(result.stdout)["items"]
                 for entry in item.get("endpoints", []) if entry.get("conditions", {}).get("ready")]
        if len(ready) == count or time.monotonic() >= deadline:
            return ready
        time.sleep(0.3)


def _replace_backend(lab, backend, phase, leaf):
    service = f"saf-0605-008-{backend}"
    pods = _kubectl(lab, "-n", NAMESPACE, "get", "pods", "-l", f"app={service}", "-o", "name")
    old_pods = pods.stdout.strip().splitlines()
    if len(old_pods) != 1:
        raise RuntimeError(f"Expected one pre-rotation Pod for {service}: {old_pods}")
    secret = f"saf-0605-008-{backend}-{phase}-tls"
    # Stage the new files before changing the Pod template.
    _secret(lab, secret, *leaf)
    patch = {"spec": {"template": {"spec": {"volumes": [
        {"name": "tls", "secret": {"secretName": secret}},
    ]}}}}
    deployment = f"deployment/{service}"
    _kubectl(lab, "-n", NAMESPACE, "patch", deployment, "--type=strategic", "-p", json.dumps(patch))
    _kubectl(lab, "-n", NAMESPACE, "rollout", "status", deployment, "--timeout=90s", timeout=100)
    _kubectl(lab, "-n", NAMESPACE, "wait", "--for=delete", old_pods[0], "--timeout=25s",
             timeout=30)
    current = json.loads(_kubectl(lab, "-n", NAMESPACE, "get", "pods", "-l", f"app={service}",
                                   "-o", "json").stdout)["items"]
    if len(current) != 1 or not any(
        volume["name"] == "tls" and volume["secret"]["secretName"] == secret
        for volume in current[0]["spec"]["volumes"]
    ):
        raise RuntimeError(f"Rotated backend {service} did not mount the staged TLS Secret")


def _observe_last_backend_budget(lab, remaining):
    pod = remaining[0]["targetRef"]["name"]
    deadline = time.monotonic() + 15
    while True:
        budget = json.loads(_kubectl(lab, "-n", NAMESPACE, "get", "pdb", PDB, "-o", "json").stdout)
        status = budget.get("status", {})
        protected = status.get("currentHealthy") == 1 and status.get("disruptionsAllowed") == 0
        if protected or time.monotonic() >= deadline:
            break
        time.sleep(0.3)
    eviction = {"apiVersion": "policy/v1", "kind": "Eviction",
                "metadata": {"name": pod, "namespace": NAMESPACE},
                "deleteOptions": {"dryRun": ["All"]}}
    rejected = _kubectl(lab, "create", "--raw",
                        f"/api/v1/namespaces/{NAMESPACE}/pods/{pod}/eviction?dryRun=All",
                        "-f", "-", payload=json.dumps(eviction), allow_failure=True)
    error = rejected.stderr.lower()
    matched = rejected.returncode != 0 and "disruption budget" in error and "toomanyrequests" in error
    lab.check("green", "The budget rejects a dry-run eviction of the last webhook endpoint",
              protected and matched, {"one_healthy_backend": status.get("currentHealthy") == 1,
                                      "zero_disruptions_allowed": status.get("disruptionsAllowed") == 0,
                                      "eviction_rejected_by_budget": matched})


def _observe_latency_metric(lab):
    metrics = _kubectl(lab, "get", "--raw=/metrics").stdout
    metric = "apiserver_admission_webhook_admission_duration_seconds_count"
    exported = any(line.startswith(metric + "{")
                   and 'name="saf-0605-008.example.test"' in line
                   and float(line.split()[-1]) > 0 for line in metrics.splitlines())
    lab.check("positive", "API server exports a sampled latency histogram for the owned webhook",
              exported, {"metric": metric, "owned_webhook_series_has_samples": exported})


def run(lab):
    version = json.loads(_kubectl(lab, "version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    lab.check("positive", "The live admission comparison runs on Kubernetes v1.36.1",
              version == "v1.36.1", {"kubernetes": version})
    with tempfile.TemporaryDirectory(prefix="saf-0605-008-") as name:
        directory = Path(name)
        old_ca = _make_ca(lab, directory, "old-ca")
        new_ca = _make_ca(lab, directory, "new-ca")
        wrong_ca = _make_ca(lab, directory, "untrusted-ca")
        leaves = {(epoch, backend): _make_leaf(lab, directory, ca, epoch, backend)
                  for epoch, ca in (("old", old_ca), ("new", new_ca)) for backend in BACKENDS}
        fingerprints = {item: _fingerprint(leaf[0]) for item, leaf in leaves.items()}
        _install(lab, leaves)

        ready = _wait_endpoints(lab, 2)
        distinct = len(ready) == 2 and len({entry.get("nodeName") for entry in ready} - {None}) == 2
        lab.check("positive", "Two ready webhook backends run on distinct workers",
                  distinct, {"ready_endpoints": len(ready), "workers_are_distinct": distinct})
        _configure(lab, [old_ca[1]], "saf-0605-008-a")
        initial = _wait_probe(lab, "saf-0605-008-trusted-old-a", backends=("a",),
                              fingerprint=fingerprints[("old", "a")])
        lab.check("positive", "The originally trusted webhook serves the selected admission request",
                  initial, {"matching_old_certificate_served_probe": initial})

        _configure(lab, [wrong_ca[1]], "saf-0605-008-a")
        rejected = _wait_probe(
            lab, "saf-0605-008-untrusted",
            error_matches=lambda text: "x509" in text and "unknown authority" in text,
        )
        continuity = _kubectl(lab, "get", "namespace", NAMESPACE, "-o", "name").returncode == 0
        lab.check("red", "Untrusted webhook CA rejects matching dry-run at TLS",
                  rejected, {"x509_unknown_authority": rejected})
        lab.check("positive", "Ordinary API reads continue while matching webhook trust is wrong",
                  continuity, {"namespace_read_succeeded": continuity})

        overlap = [old_ca[1], new_ca[1]]
        _configure(lab, overlap, "saf-0605-008-a")
        _replace_backend(lab, "a", "renewed", leaves[("new", "a")])
        new_a = _wait_probe(lab, "saf-0605-008-overlap-new-a", backends=("a",),
                            fingerprint=fingerprints[("new", "a")])
        _configure(lab, overlap, "saf-0605-008-b")
        old_b = _wait_probe(lab, "saf-0605-008-overlap-old-b", backends=("b",),
                            fingerprint=fingerprints[("old", "b")])
        _replace_backend(lab, "b", "renewed", leaves[("new", "b")])
        new_b = _wait_probe(lab, "saf-0605-008-overlap-new-b", backends=("b",),
                            fingerprint=fingerprints[("new", "b")])
        lab.check("green", "During trust overlap the old and renewed endpoints both serve admission",
                  new_a and old_b and new_b, {"new_a_served": new_a, "old_b_served": old_b,
                                             "new_b_served": new_b})

        _replace_backend(lab, "a", "wrong-name", leaves[("new", "b")])
        _configure(lab, [new_ca[1]], "saf-0605-008-a")
        wrong_identity = _wait_probe(
            lab, "saf-0605-008-wrong-identity",
            error_matches=lambda text: "x509" in text and "saf-0605-008-a.saf-test.svc" in text
            and "saf-0605-008-b.saf-test.svc" in text,
        )
        lab.check("red", "A trusted certificate for the other Service DNS name is rejected",
                  wrong_identity, {"x509_service_identity_error": wrong_identity})
        _replace_backend(lab, "a", "restored", leaves[("new", "a")])

        for backend in BACKENDS:
            _configure(lab, [new_ca[1]], f"saf-0605-008-{backend}")
            served = _wait_probe(lab, f"saf-0605-008-new-only-{backend}", backends=(backend,),
                                 fingerprint=fingerprints[("new", backend)])
            lab.check("green", f"Renewed backend {backend} serves admission with only the new CA",
                      served, {"exact_renewed_leaf_served": served})

        _configure(lab, [new_ca[1]])
        healthy = _wait_probe(lab, "saf-0605-008-shared-healthy")
        lab.check("positive", "The shared Service admits after the old CA is retired",
                  healthy, {"sample_reached_shared_backend": healthy})
        before = _wait_endpoints(lab, 2)
        _kubectl(lab, "-n", NAMESPACE, "scale", "deployment/saf-0605-008-b", "--replicas=0")
        remaining = _wait_endpoints(lab, 1)
        served = _wait_probe(lab, "saf-0605-008-one-backend", backends=("a",),
                             fingerprint=fingerprints[("new", "a")])
        lab.check("green", "Admission continues through the shared Service after one endpoint leaves",
                  len(before) == 2 and len(remaining) == 1 and served,
                  {"initial_ready_endpoints": len(before), "remaining_ready_endpoints": len(remaining),
                   "surviving_backend_served_probe": served})
        _observe_last_backend_budget(lab, remaining)
        _observe_latency_metric(lab)
