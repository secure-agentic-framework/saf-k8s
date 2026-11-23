"""Check denied admission when signature lookup or the admission webhook fails."""
from contextlib import ExitStack, contextmanager
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import ssl
import time
import urllib.request

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-0602-006"
POLICY = "saf-0602-006-signature"
WEBHOOK = f"ivpol.validate.kyverno.svc-fail-finegrained-{POLICY}"
MUTATING_WEBHOOK = f"ivpol.mutate.kyverno.svc-fail-finegrained-{POLICY}"
DENIAL = "image must have an approved fixture signature"
SCOPE = (
    "Kubernetes Pod CREATE server-side dry-run in one enrolled Kind namespace with a "
    "pinned Kyverno installation, an owned TLS registry, immutable image references and "
    "one ephemeral Cosign identity. Tests signature denial, registry lookup failure, "
    "webhook unavailability, and recovery. Production coverage and existing workloads "
    "require independent evidence."
)


def load_case(directory, file):
    location = HERE.parent / directory / file
    spec = importlib.util.spec_from_file_location(location.stem, location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def publish_images(image, registry, host_port):
    subjects = image._build_and_push(registry, host_port)
    remote, old_digest = subjects["approved"].rsplit("@", 1)
    repository = remote.split("/", 1)[1]
    url = f"https://127.0.0.1:{host_port}/v2/{repository}/manifests/"
    medium = "application/vnd.oci.image.manifest.v1+json"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=registry.registry_ca)),
    )
    with opener.open(urllib.request.Request(url + old_digest, headers={"Accept": medium}),
                     timeout=10) as response:
        original = json.load(response)
    refs = {"unsigned": subjects["missing-attestation"]}
    for label in ("healthy", "registry-outage", "webhook-outage", "recovered"):
        manifest = {**original, "annotations": {"org.opencontainers.image.title": label}}
        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        digest = "sha256:" + sha256(payload).hexdigest()
        request = urllib.request.Request(url + label, data=payload, method="PUT",
                                         headers={"Content-Type": medium})
        with opener.open(request, timeout=10) as response:
            if response.status != 201 or response.headers.get("Docker-Content-Digest") != digest:
                raise image.FixtureError("Owned registry failed to store the exact test digest")
        refs[label] = f"{remote}@{digest}"

    signer = registry.work / "0602-006-signer"
    signer.mkdir(mode=0o700)
    registry.cosign(signer, "generate-key-pair")
    for label in ("healthy", "registry-outage", "webhook-outage", "recovered"):
        registry.cosign(signer, "sign", *image.FIXTURE_SIGNING, refs[label])
    return refs, (signer / "cosign.pub").read_text()


def install_policy(registry, public_key):
    obj = {
        "apiVersion": "policies.kyverno.io/v1", "kind": "ImageValidatingPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "validationActions": ["Deny"], "failurePolicy": "Fail",
            "webhookConfiguration": {"timeoutSeconds": 10},
            "evaluation": {"background": {"enabled": False}},
            "matchConstraints": {
                "resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                   "operations": ["CREATE"], "resources": ["pods"]}],
                "namespaceSelector": {"matchLabels": {"saf-k8s.example/case": "0602-006"}},
            },
            "matchImageReferences": [{"glob": f"{registry.registry}/fixture/*@*"}],
            "attestors": [{"name": "fixture", "cosign": {
                "key": {"data": public_key},
                "ctlog": {"insecureIgnoreSCT": True, "insecureIgnoreTlog": True},
            }}],
            "validations": [{
                "expression": "images.containers.map(image, verifyImageSignatures(image, "
                              "[attestors.fixture])).all(result, result > 0)",
                "message": DENIAL,
            }],
        },
    }
    registry.kube("create", "-f", "-", input_text=json.dumps(obj))


def wait_for(registry, predicate, message):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.5)
    registry.lab.block(message)


def failure_policies(registry):
    response = registry.kube("get", "validatingwebhookconfigurations,mutatingwebhookconfigurations",
                             "-o", "json")
    return {hook["name"]: hook["failurePolicy"] for item in json.loads(response.stdout)["items"]
            for hook in item["webhooks"] if hook.get("name") in (WEBHOOK, MUTATING_WEBHOOK)}


def registry_running(registry):
    return registry.docker("inspect", registry.registry_container, "--format",
                           "{{.State.Running}}").stdout.strip() == "true"


def patch_registry_endpoint(registry, address, port):
    name = registry.registry_container + "-owned"
    patch = [{"op": "replace", "path": "/endpoints/0/addresses/0", "value": address},
             {"op": "replace", "path": "/ports/0/port", "value": port}]
    registry.kube("-n", "kyverno", "patch", "endpointslice", name, "--type=json", "-p", json.dumps(patch))


def kind_address(registry, container):
    state = registry.docker("inspect", container, "--format", "{{json .NetworkSettings.Networks.kind}}")
    return json.loads(state.stdout)["IPAddress"]


@contextmanager
def without_registry(registry):
    node_address = kind_address(registry, f"{registry.lab.cluster}-control-plane")
    registry.docker("stop", "--timeout", "2", registry.registry_container)
    if registry_running(registry):
        registry.lab.block("The owned registry did not stop")
    try:
        # Use a closed port on the fixture node so requests get TCP refusal
        # before the API server's webhook timeout rather than a silent drop.
        patch_registry_endpoint(registry, node_address, 1)
        yield
    finally:
        registry.docker("start", registry.registry_container)
        patch_registry_endpoint(registry, kind_address(registry, registry.registry_container), 5000)


def service_has_endpoint(registry):
    items = json.loads(registry.kube("-n", "kyverno", "get", "endpointslices", "-l",
                                     "kubernetes.io/service-name=kyverno-svc", "-o", "json").stdout)["items"]
    return any(endpoint["conditions"].get("ready", False)
               for item in items for endpoint in item["endpoints"])


@contextmanager
def without_webhook(registry):
    service = json.loads(registry.kube("-n", "kyverno", "get", "service", "kyverno-svc",
                                       "-o", "json").stdout)["spec"]
    port, = (entry["port"] for entry in service["ports"] if entry["name"] == "https")
    slices = json.loads(registry.kube("-n", "kyverno", "get", "endpointslices", "-l",
                                       "kubernetes.io/service-name=kyverno-svc", "-o", "json").stdout)["items"]
    endpoints = {(address, entry["port"]) for group in slices for entry in group["ports"]
                 if entry.get("name") == "https" for endpoint in group["endpoints"]
                 if endpoint["conditions"].get("ready", False) for address in endpoint["addresses"]}
    if not endpoints:
        registry.lab.block("The owned Kyverno webhook had no Ready backend before fault injection")
    routes = {(service["clusterIP"], port)} | endpoints
    node = f"{registry.lab.cluster}-control-plane"
    with ExitStack() as restore:
        for address, port in sorted(routes):
            match = ("-d", address, "-p", "tcp", "--dport", str(port), "-m", "comment",
                     "--comment", "saf-owned-webhook-transport", "-j", "DROP")
            router = ("exec", node, "iptables", "-w", "-t", "raw")
            registry.docker(*router, "-I", "OUTPUT", "1", *match)
            restore.callback(registry.docker, *router, "-D", "OUTPUT", *match)
        yield


def run(lab):
    image = load_case("SAF-K8S-0605-002", "image_admission.py")
    kyverno = load_case("SAF-K8S-1006-005", "case.py")
    with image.registry(lab) as (registry, host_port, values):
        kyverno._install_kyverno(lab, values)
        imgs, key = publish_images(image, registry, host_port)
        registry.kube("create", "namespace", NAMESPACE)
        registry.kube("label", "namespace", NAMESPACE, "saf-k8s.example/case=0602-006")

        def probe(label):
            return image._probe(registry, f"probe-{label}", imgs[label], NAMESPACE)

        def accepted(label, result):
            return image._admitted(result, f"probe-{label}", imgs[label], NAMESPACE)

        original = accepted("unsigned", probe("unsigned"))
        lab.check("red", "The same unsigned digest is admitted before enabling the signature policy",
                  original, {"unsigned_baseline_admitted": original})
        install_policy(registry, key)
        image.POLICY = POLICY
        image._wait_policy(registry)

        def signature_denial():
            result = probe("unsigned")
            return result.returncode != 0 and WEBHOOK in result.stderr and (
                DENIAL in result.stderr or "no signatures" in result.stderr.lower()
                or "no matching signatures" in result.stderr.lower()
            )

        wait_for(registry, signature_denial, "Unsigned image did not reach the expected signature denial")
        lab.check("green", "Kyverno rejects the identical unsigned digest",
                  failure_policies(registry).get(WEBHOOK) == "Fail",
                  {"signature_denied": True, "effective_validating_failure_policy": "Fail"})
        healthy = accepted("healthy", probe("healthy"))
        lab.check("positive", "The already signed approved image is admitted",
                  healthy, {"signed_baseline_admitted": healthy})

        with without_registry(registry):
            def registry_denial():
                result = probe("registry-outage")
                message = result.stderr.lower()
                return result.returncode != 0 and WEBHOOK in result.stderr and "denied the request" in message and (
                    "connection refused" in message or "dial tcp" in message or "i/o timeout" in message
                    or "context deadline exceeded" in message or "connection reset" in message
                )

            wait_for(registry, registry_denial, "Expected registry retrieval denial was not observed")
            lab.check("green", "A reachable verifier denies a new signed digest while the registry is unavailable",
                      service_has_endpoint(registry) and failure_policies(registry).get(WEBHOOK) == "Fail"
                      and not registry_running(registry),
                      {"registry_dependency_denied": True, "webhook_endpoint_ready": True,
                       "owned_registry_running": False})
        recovered = wait_for(registry, lambda: accepted("registry-outage", probe("registry-outage")),
                             "The same signed digest remained denied after registry recovery")
        lab.check("positive", "Registry recovery permits the same signed digest", recovered,
                  {"same_signed_digest_admitted_after_registry_recovery": recovered})

        with without_webhook(registry):
            registered = failure_policies(registry)
            result = probe("webhook-outage")
            failed_mutating_call = (
                result.returncode != 0 and MUTATING_WEBHOOK in result.stderr
                and "failed calling webhook" in result.stderr.lower()
            )
            both_fail_closed = registered == {WEBHOOK: "Fail", MUTATING_WEBHOOK: "Fail"}
            ready = service_has_endpoint(registry) and registry_running(registry)
            lab.check("green", "The API fails closed when it cannot reach its registered signature webhooks",
                      both_fail_closed and failed_mutating_call and ready,
                      {"mutating_failure_policy": registered.get(MUTATING_WEBHOOK),
                       "validating_failure_policy": registered.get(WEBHOOK),
                       "api_reported_failed_mutating_webhook_call": failed_mutating_call,
                       "verifier_and_registry_remained_available_in_cluster": ready})
        for label in ("webhook-outage", "recovered"):
            admitted = wait_for(registry, lambda: accepted(label, probe(label)),
                                f"Signed {label} probe was denied after webhook recovery")
            lab.check("positive", f"Webhook recovery admits the {label} digest",
                      admitted, {"signed_digest_admitted_after_webhook_recovery": admitted})
