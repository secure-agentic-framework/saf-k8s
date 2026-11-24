"""Verify the signed image in the Gatekeeper GPU Pod admission path via Ratify."""
from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import runpy
import time

HERE = Path(__file__).resolve().parent
GATEKEEPER = "gatekeeper-system"
NAMESPACE = "saf-0605-001-ai"
OUTSIDE = "saf-0605-001-provenance-outside"
CHART = "1.15.9"
CHART_HASH = "f8b06edb2b1ca7d010ff9d8222bb49ca7db1911462e6284652b8ec97cf051fd2"
TAG = "v1.4.8@sha256:69d48986d1f120fd62c334eab3a71a85f405aea2e1f9e31df7a3f490852be790"
IMAGE = f"ghcr.io/notaryproject/ratify:{TAG}"
PROVIDER = "ratify-provider"
URL = "https://ratify.gatekeeper-system:6001/ratify/gatekeeper/v1/verify"
LABEL = "saf-k8s.example/case"
CONSTRAINT = "saf-gpu-provenance"
WEBHOOK = 'admission webhook "validation.gatekeeper.sh" denied'
GPU = "nvidia.com/gpu"


def kube_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def fixture_tls(lab, directory):
    ca, ca_key = directory / "ratify-ca.crt", directory / "ratify-ca.key"
    cert, key = directory / "ratify-leaf.crt", directory / "ratify-leaf.key"
    csr, ext = directory / "ratify-leaf.csr", directory / "ratify-leaf.ext"
    hostname = "ratify.gatekeeper-system"
    ext.write_text(f"subjectAltName=DNS:{hostname},DNS:{hostname}.svc\n"
                   "basicConstraints=critical,CA:FALSE\n"
                   "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    lab.command("openssl", "req", "-newkey", "rsa:2048", "-x509", "-nodes", "-days", "2",
                "-subj", "/CN=SAF case Ratify CA", "-keyout", str(ca_key), "-out", str(ca),
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    lab.command("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={hostname}",
                "-keyout", str(key), "-out", str(csr))
    lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                "-CAcreateserial", "-extfile", str(ext), "-days", "2", "-out", str(cert))
    return {"crt": cert, "key": key, "caCert": ca, "caKey": ca_key}


def install_provider(lab, registry, operator_key, images):
    manifest_dir = lab.kubeconfig.parent
    key = manifest_dir / "ratify-operator.pub"
    key.write_text(operator_key)
    lab.command("helm", "pull", "ratify", "--repo", "https://notaryproject.github.io/ratify",
                "--version", CHART, "--destination", str(manifest_dir), timeout=100)
    chart = manifest_dir / f"ratify-{CHART}.tgz"
    if sha256(chart.read_bytes()).hexdigest() != CHART_HASH:
        lab.block("Ratify's published Helm chart failed its SHA-256 check")
    tls = fixture_tls(lab, manifest_dir)
    values_path = manifest_dir / "ratify-values.json"
    # Ratify v1.4.8 compares an exact scope with the full subject, including the digest.
    scopes = sorted(images.values())
    values_path.write_text(json.dumps({
        "image": {"tag": TAG},
        "notation": {"enabled": False},
        "cosign": {"enabled": True, "scopes": scopes, "tLogVerify": False},
        "oras": {"cache": {"enabled": False}},
        "provider": {"enableMutation": False, "cache": {"enabled": False},
                     "tls": {"cabundle": b64encode(tls["caCert"].read_bytes()).decode("ascii")},
                     "timeout": {"validationTimeoutSeconds": 4}},
        "upgradeCRDs": {"enabled": False},
    }))
    tls_flags = [flag for field, path in tls.items() for flag in ("--set-file", f"provider.tls.{field}={path}")]
    lab.command("helm", "install", "ratify", str(chart), "--kubeconfig", str(lab.kubeconfig),
                "--kube-context", f"kind-{lab.cluster}", "--namespace", GATEKEEPER,
                "--values", str(values_path), "--set-file", f"cosignKeys[0]={key}",
                *tls_flags, "--wait", "--timeout", "150s", timeout=165)
    ca_name = "saf-registry-trust"
    lab.kubectl("-n", GATEKEEPER, "create", "configmap", ca_name,
                f"--from-file=registry-ca.crt={registry.registry_ca}")
    address = json.loads(registry.docker("inspect", registry.registry_container,
        "--format", "{{json .NetworkSettings.Networks.kind}}").stdout)["IPAddress"]
    patch = {"spec": {"template": {"spec": {
        "hostAliases": [{"ip": address, "hostnames": [registry.registry.split(":", 1)[0]]}],
        "volumes": [{"name": ca_name, "configMap": {"name": ca_name}}],
        "containers": [{"name": "ratify",
            "env": [{"name": "SSL_CERT_FILE", "value": "/registry-trust/registry-ca.crt"}],
            "volumeMounts": [{"name": ca_name, "mountPath": "/registry-trust", "readOnly": True}]}],
    }}}}
    deployment = kube_json(lab, "-n", GATEKEEPER, "get", "deployment", "ratify")
    patch["spec"]["template"]["spec"]["containers"][0]["name"] = deployment["spec"]["template"]["spec"]["containers"][0]["name"]
    lab.kubectl("-n", GATEKEEPER, "patch", "deployment", "ratify", "--patch", json.dumps(patch))
    lab.kubectl("-n", GATEKEEPER, "rollout", "status", "deployment/ratify",
                "--timeout=120s", timeout=130)
    deploy = kube_json(lab, "-n", GATEKEEPER, "get", "deployment", "ratify")
    provider = kube_json(lab, "get", "provider.externaldata.gatekeeper.sh", PROVIDER)
    admitted_images = [c["image"] for c in deploy["spec"]["template"]["spec"]["containers"]]
    lab.check("positive", "The Ratify provider uses a pinned image and a CA-authenticated HTTPS endpoint",
              admitted_images == [IMAGE] and provider["spec"]["url"] == URL and bool(provider["spec"].get("caBundle")),
              {"image": IMAGE, "chart_sha256": CHART_HASH, "provider_url": URL, "tls_ca_configured": bool(provider["spec"].get("caBundle"))})
    return provider


def probe(lab, name, image, *, namespace=NAMESPACE, dry_run=False):
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": name, "namespace": namespace, "labels": {LABEL: "0605-001-provenance"}},
           "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                    "runtimeClassName": "saf-gpu", "containers": [{
                        "name": "inert", "image": image, "command": ["/case/marker-do-not-run"],
                        "resources": {"requests": {GPU: "1"}, "limits": {GPU: "1"}},
                    }]}}
    flags = ("--dry-run=server",) if dry_run else ()
    return lab.kubectl("-n", namespace, "create", "-f", "-", "-o", "json", *flags,
                       payload=json.dumps(pod), allow_failure=True)


def denied_as(lab, name, image, reason, result):
    response = lab.kubectl("-n", NAMESPACE, "get", "pod", name, allow_failure=True)
    return (result.returncode != 0 and all(marker in result.stderr for marker in (WEBHOOK, CONSTRAINT, image, reason))
            and response.returncode != 0 and "not found" in response.stderr.lower())


def wait_for(lab, predicate, reason, timeout=65):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(1)
    lab.block(reason)


def assert_webhook_cache_disabled(lab):
    deployment = kube_json(lab, "-n", GATEKEEPER, "get", "deployment", "gatekeeper-controller-manager")
    selector = ",".join(f"{key}={value}" for key, value in deployment["spec"]["selector"]["matchLabels"].items())
    pods = kube_json(lab, "-n", GATEKEEPER, "get", "pods", "-l", selector)["items"]
    settings = [c["args"] for pod in pods for c in pod["spec"]["containers"] if c["name"] == "manager"]
    disabled = bool(settings) and all("--external-data-provider-response-cache-ttl=0s" in args for args in settings)
    lab.check("positive", "Every Gatekeeper webhook Pod starts with the external response cache disabled",
              disabled, {"webhook_cache_disabled": disabled})


def endpoints_available(lab):
    rows = kube_json(lab, "-n", GATEKEEPER, "get", "endpointslices",
                     "-l", "kubernetes.io/service-name=ratify")["items"]
    # A terminating endpoint can still serve traffic after Ready becomes false.
    pods = kube_json(lab, "-n", GATEKEEPER, "get", "pods", "-l", "app.kubernetes.io/name=ratify")
    return bool(pods["items"]) or any(ep.get("addresses") for row in rows for ep in (row.get("endpoints") or []))


def verify_admission(lab, images):
    lab.kubectl("create", "namespace", OUTSIDE)
    name = "gatekeeper-validating-webhook-configuration"
    configuration = kube_json(lab, "get", "validatingwebhookconfiguration", name)
    index = next(i for i, webhook in enumerate(configuration["webhooks"])
                 if webhook["name"] == "validation.gatekeeper.sh")
    settings = [{"op": "add", "path": f"/webhooks/{index}/timeoutSeconds", "value": 8},
                {"op": "add", "path": f"/webhooks/{index}/failurePolicy", "value": "Fail"}]
    lab.kubectl("patch", "validatingwebhookconfiguration", name, "--type=json",
                "--patch", json.dumps(settings))
    approved = images["approved"]
    wrong_signer = images["unrelated-signer"]
    baseline = {key: probe(lab, f"sig-before-{key}", subject, dry_run=True).returncode == 0
                for key, subject in (("approved", approved), ("wrong", wrong_signer),
                                     ("unsigned", images["missing-attestation"]))}
    lab.check("red", "All exact fixture subjects reach API admission before the signature constraint",
              all(baseline.values()), {"before_policy_admitted": baseline})
    assert_webhook_cache_disabled(lab)
    lab.apply(HERE / "constraint-template.yaml")
    lab.kubectl("wait", "--for=condition=Established", "crd/safgpuimagesignature.constraints.gatekeeper.sh",
                "--timeout=60s", timeout=70)
    lab.apply(HERE / "constraint.yaml")
    def wrong_sig_is_blocked():
        result = probe(lab, "sig-ready-probe", wrong_signer, dry_run=True)
        return result.returncode != 0 and all(marker in result.stderr for marker in (WEBHOOK, CONSTRAINT, wrong_signer))
    wait_for(lab, wrong_sig_is_blocked, "Gatekeeper did not begin evaluating the signed image constraint")
    name = "sig-approved"
    allowed = probe(lab, name, approved)
    if allowed.returncode:
        lab.kubectl("-n", GATEKEEPER, "logs", "deployment/ratify", "--tail=85", allow_failure=True)
    obj = kube_json(lab, "-n", NAMESPACE, "get", "pod", name) if allowed.returncode == 0 else {}
    evidence = {"approved_subject": approved, "approved_stored_pod": obj}
    lab.check("positive", "Gatekeeper admits and stores the GPU Pod whose digest Ratify verified with the approved key",
              bool(obj) and obj["spec"]["containers"][0]["image"] == approved,
              {"verified_subject_persisted": bool(obj)})
    denied = probe(lab, "sig-wrong-signer", wrong_signer)
    evidence["wrong_signer"] = {"image": wrong_signer, "response": denied.stderr}
    lab.check("green", "Gatekeeper denies the exact GPU subject signed by the unrelated fixture key",
              denied_as(lab, "sig-wrong-signer", wrong_signer, "verified Cosign signature", denied),
              {"wrong_signer_rejected_by_exact_constraint": True if denied.returncode else False})
    unsigned = images["missing-attestation"]
    rejected = probe(lab, "sig-unsigned", unsigned)
    evidence["unsigned"] = {"image": unsigned, "response": rejected.stderr}
    unsigned_denied = denied_as(lab, "sig-unsigned", unsigned, "verified Cosign signature", rejected)
    lab.check("green", "Gatekeeper denies a GPU subject whose repository has no signature",
              unsigned_denied, {"unsigned_subject_denied_and_absent": unsigned_denied})
    outside = probe(lab, "sig-outside", wrong_signer, namespace=OUTSIDE, dry_run=True)
    lab.check("positive", "The same wrong-signer subject reaches admission outside the selected namespace",
              outside.returncode == 0, {"admitted_outside_fixture_scope": outside.returncode == 0})
    lab.kubectl("-n", GATEKEEPER, "scale", "deployment/ratify", "--replicas=0")
    try:
        wait_for(lab, lambda: not endpoints_available(lab), "Ratify still had a ready endpoint after scaling down")
        failed = probe(lab, "sig-provider-down", approved)
        evidence["provider_unavailable"] = {"image": approved, "response": failed.stderr}
        if failed.returncode == 0:
            lab.kubectl("-n", GATEKEEPER, "logs", "deployment/gatekeeper-controller-manager", "--tail=60", allow_failure=True)
        details = failed.stderr
        reason = "Ratify provider unavailable" if "Ratify provider unavailable" in details else "verified Cosign signature"
        denied = denied_as(lab, "sig-provider-down", approved, reason, failed)
        lab.check("green", "With no running provider Pod or endpoint, Gatekeeper denies the previously admitted GPU subject",
                  denied, {"rejected_by_signature_constraint_during_outage": denied})
    finally:
        lab.kubectl("-n", GATEKEEPER, "scale", "deployment/ratify", "--replicas=1")
        lab.kubectl("-n", GATEKEEPER, "rollout", "status", "deployment/ratify",
                    "--timeout=120s", timeout=130)
    def restored():
        return probe(lab, "sig-provider-restored", approved, dry_run=True).returncode == 0
    wait_for(lab, restored, "The previously approved subject was not admitted after Ratify recovered")
    lab.check("positive", "The same subject is admitted when the signature verifier returns",
              restored(), {"previously_approved_subject_admitted_after_recovery": True})
    return evidence


def sign_owned_subjects(registry, images):
    approved = registry.work / "ratify-operator"
    unrelated = registry.work / "ratify-unrelated"
    for directory, index in ((approved, "approved"), (unrelated, "unrelated-signer")):
        directory.mkdir(mode=0o700)
        registry.cosign(directory, "generate-key-pair")
        registry.cosign(directory, "sign", "--yes", "--key", "/work/cosign.key",
                        "--use-signing-config=false", "--tlog-upload=false",
                        "--new-bundle-format=false", "--registry-referrers-mode=legacy", images[index])
        registry.cosign(directory, "verify", "--key", "/work/cosign.pub",
                        "--insecure-ignore-tlog=true", images[index])
    return (approved / "cosign.pub").read_text()


def run(lab, image_fixture):
    module = runpy.run_path(str(image_fixture))
    with module["registry"](lab) as (registry, port, _chart_values):
        images = module["_build_and_push"](registry, port)
        operator_key = sign_owned_subjects(registry, images)
        provider = install_provider(lab, registry, operator_key, images)
        checks = verify_admission(lab, images)
        (lab.evidence / "gatekeeper-ratify-provenance.json").write_text(json.dumps(
            {"provider": provider["spec"], **checks}, indent=2) + "\n")
