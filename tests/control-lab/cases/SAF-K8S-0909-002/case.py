"""Live Kind demonstration for a pinned, synthetic document embedding pipeline."""
import base64
import importlib.util
import json
from tempfile import TemporaryDirectory
from pathlib import Path

HERE = Path(__file__).resolve().parent
SIBLING = HERE.parent / "SAF-K8S-0908-001" / "case.py"
NS = "saf-test"
CODE = "saf-embedding-code"
ARTIFACTS = "saf-embedding-artifacts"
SIGNATURES = "saf-embedding-signatures"
VERIFIER = ("ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:"
            "0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d")
SCOPE = (
    "A pinned Cosign init container verifies a local ECDSA signature over exact synthetic "
    "model bytes. The workload independently checks model and input digest pins, rejects "
    "a format-invalid document before the embedding call, and reproduces the expected "
    "vector in separate live Kubernetes Pods."
)


def load_runtime(lab):
    if not SIBLING.is_file():
        lab.block("The adjacent pinned Python runtime helper is unavailable")
    spec = importlib.util.spec_from_file_location("saf_embedding_runtime", SIBLING)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_runtime(lab)


def verifier_image(lab):
    reference = "saf-k8s-fixture/cosign:3.1.4-0f06154836d2"
    inspect = ("docker", "image", "inspect", "--format", "{{.Id}}")
    expected = lab.command(*inspect, VERIFIER, allow_failure=True)
    if expected.returncode:
        lab.command("docker", "pull", VERIFIER, timeout=180)
        expected = lab.command(*inspect, VERIFIER)
    cached = lab.command(*inspect, reference, allow_failure=True)
    if cached.returncode:
        lab.command("docker", "image", "tag", VERIFIER, reference)
        cached = lab.command(*inspect, reference)
    if not expected.stdout.strip() or cached.stdout.strip() != expected.stdout.strip():
        lab.block("The local Cosign image does not match the reviewed verifier digest")
    platform = lab.command("docker", "image", "inspect", "--format",
                           "{{.Os}}/{{.Architecture}}", reference).stdout.strip()
    with TemporaryDirectory(dir=lab.kubeconfig.parent) as temp:
        archive = str(Path(temp) / "verifier.tar")
        lab.command("docker", "image", "save", "--platform", platform, "--output",
                    archive, reference, timeout=120)
        lab.command("kind", "load", "image-archive", archive, "--name", lab.cluster, timeout=120)
    return reference


def signatures(lab):
    with TemporaryDirectory(dir=lab.kubeconfig.parent) as temp:
        root = Path(temp)
        key, public, signature = (root / name for name in ("signer.pem", "signer.pub", "signature.der"))
        lab.command("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
        lab.command("openssl", "ec", "-in", str(key), "-pubout", "-out", str(public))
        material = {"signer.pub": public.read_text()}
        for name, model in (("approved", "embedding_model_v1.json"),
                            ("alternate", "embedding_model_unapproved.json")):
            lab.command("openssl", "dgst", "-sha256", "-sign", str(key), "-out",
                        str(signature), str(HERE / model))
            material[name+".sig"] = base64.b64encode(signature.read_bytes()).decode("ascii")
        return material


def _create(lab, kind, name, api="v1", **fields):
    metadata = {"name": name}
    if kind != "Namespace":
        metadata["namespace"] = NS
    return lab.create({"apiVersion": api, "kind": kind, "metadata": metadata, **fields})


def _publish_inputs(lab, image, verifier):
    from fixtures import container, pod

    _create(lab, "ConfigMap", CODE, immutable=True,
            data={"ingest_fixture.py": (HERE / "ingest_fixture.py").read_text()})
    artifact_names = {
        "model-v1.json": "embedding_model_v1.json",
        "model-unapproved.json": "embedding_model_unapproved.json",
        "approved.txt": "approved_document.txt",
        "malformed.txt": "malformed_document.txt",
    }
    _create(lab, "ConfigMap", ARTIFACTS, immutable=True,
            data={key: (HERE / filename).read_text() for key, filename in artifact_names.items()})
    _create(lab, "ConfigMap", SIGNATURES, immutable=True, data=signatures(lab))

    common_volumes = [
        {"name": "code", "configMap": {"name": CODE}},
        {"name": "artifacts", "configMap": {"name": ARTIFACTS}},
    ]
    calls = {
        "embedding-red": ("unlocked", "model-unapproved.json", None),
        "embedding-bad-signature": ("pinned", "model-unapproved.json", "approved.sig"),
        "embedding-green": ("pinned", "model-unapproved.json", "alternate.sig"),
        "embedding-positive-a": ("pinned", "model-v1.json", "approved.sig"),
        "embedding-positive-b": ("pinned", "model-v1.json", "approved.sig"),
    }
    for name, (mode, model, signature) in calls.items():
        unit = container(
            "fixture", image=image, imagePullPolicy="Never",
            command=["python", "/fixture/ingest_fixture.py", mode,
                     f"/artifacts/{model}", "/artifacts/approved.txt",
                     "/artifacts/malformed.txt"],
            volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                          {"name": "artifacts", "mountPath": "/artifacts", "readOnly": True}],
            securityContext={"allowPrivilegeEscalation": False,
                             "readOnlyRootFilesystem": True,
                             "capabilities": {"drop": ["ALL"]}},
            resources={"requests": {"cpu": "10m", "memory": "16Mi"},
                       "limits": {"cpu": "100m", "memory": "64Mi"}},
        )
        request = pod(name, [unit], automountServiceAccountToken=False,
                      volumes=common_volumes,
                      securityContext={"runAsNonRoot": True, "runAsUser": 65534,
                                       "seccompProfile": {"type": "RuntimeDefault"}})
        request["metadata"]["namespace"] = NS
        if signature:
            request["spec"]["volumes"] = common_volumes + [
                {"name": "signatures", "configMap": {"name": SIGNATURES}}]
            init = container("verify-model", image=verifier, imagePullPolicy="Never",
                             command=["/ko-app/cosign", "verify-blob", "--key", "/proof/signer.pub",
                                      "--signature", "/proof/"+signature, "--insecure-ignore-tlog",
                                      "--insecure-ignore-sct", "/artifacts/"+model],
                             volumeMounts=[
                                 {"name": "signatures", "mountPath": "/proof", "readOnly": True},
                                 {"name": "artifacts", "mountPath": "/artifacts", "readOnly": True}])
            request["spec"]["initContainers"] = [init]
        lab.create(request)


def _result(lab, pod_name):
    lab.kubectl("-n", NS, "wait", f"--for=jsonpath={{.status.phase}}=Succeeded",
                f"pod/{pod_name}", "--timeout=95s", timeout=105)
    raw = lab.kubectl("-n", NS, "logs", f"pod/{pod_name}").stdout.strip()
    return json.loads(raw)


def signature_blocked(lab):
    name = "embedding-bad-signature"
    lab.kubectl("-n", NS, "wait", "--for=jsonpath={.status.phase}=Failed", "pod/"+name,
                "--timeout=95s", timeout=105)
    pod = json.loads(lab.kubectl("-n", NS, "get", "pod/"+name, "-o", "json").stdout)
    status = pod["status"]
    verifier = status["initContainerStatuses"][0]
    logs = lab.kubectl("-n", NS, "logs", "pod/"+name, "-c", "verify-model").stdout
    main_started = any(row.get("containerID") for row in status.get("containerStatuses", []))
    return {"invalid_signature_reported": "invalid signature" in logs.lower(),
            "verifier_rejected": verifier["state"]["terminated"]["exitCode"] != 0,
            "embedding_did_not_start": not main_started}


def run(lab):
    _publish_inputs(lab, load_runtime(lab), verifier_image(lab))
    red = _result(lab, "embedding-red")
    green = _result(lab, "embedding-green")
    first = _result(lab, "embedding-positive-a")
    second = _result(lab, "embedding-positive-b")

    red_event = red.get("observations", [{}])[-1]
    red_ok = (red_event.get("event") == "embedded" and red_event.get("vector_emitted") is True
              and red_event.get("model_sha256") !=
              "e3a1d0077990215bb53a9b38b66dda648bf7968114546f64acd592f2378cb789"
              and tuple(red_event.get("vector", ())) != (0.5, 0.75, 1.0))
    lab.check("red", "An unapproved but valid model artifact changes the emitted vector",
              red_ok, {"unapproved_model_accepted": red_ok,
                       "vector_changed": red_event.get("vector") != [0.5, 0.75, 1.0],
                       "vector_emitted": red_event.get("vector_emitted")})

    signature = signature_blocked(lab)
    lab.check("green", "The pinned verifier rejects a signature for different model bytes before startup",
              all(signature.values()), signature)
    rejected_model = green
    green_ok = (rejected_model.get("event") == "model_rejected"
                and rejected_model.get("reason") == "digest_mismatch"
                and rejected_model.get("vector_emitted") is False
                and rejected_model.get("embed_calls") == 0)
    lab.check("green", "The approved digest also rejects signed alternate bytes before vector output",
              green_ok, {"rejected_before_embedding": green_ok,
                         "reason": rejected_model.get("reason"),
                         "embed_calls": rejected_model.get("embed_calls", 0),
                         "vector_emitted": rejected_model.get("vector_emitted")})

    def positive_shape(result):
        events = result.get("observations", [])
        rejected = next((row for row in events if row.get("event") == "document_rejected"), {})
        embedded = next((row for row in events if row.get("event") == "embedded"), {})
        return rejected, embedded

    malformed_a, vector_a = positive_shape(first)
    malformed_b, vector_b = positive_shape(second)
    order_a = [row.get("event") for row in first.get("observations", [])]
    order_b = [row.get("event") for row in second.get("observations", [])]
    expected = [0.5, 0.75, 1.0]
    positive_ok = (
        malformed_a.get("reason") == malformed_b.get("reason") == "format_invalid"
        and order_a == order_b == ["document_rejected", "embedded"]
        and malformed_a.get("embed_calls") == malformed_b.get("embed_calls") == 0
        and malformed_a.get("vector_emitted") is False
        and malformed_b.get("vector_emitted") is False
        and vector_a.get("vector") == vector_b.get("vector") == expected
        and vector_a.get("expected_vector_match") is True
        and vector_b.get("expected_vector_match") is True
        and vector_a.get("embed_calls") == vector_b.get("embed_calls") == 1
    )
    lab.check("positive", "Pinned valid input is validated and maps to the expected vector twice",
              positive_ok, {"malformed_rejected_before_embedding": positive_ok,
                            "malformed_reason": malformed_a.get("reason"),
                            "malformed_embed_calls": malformed_a.get("embed_calls"),
                            "malformed_event_precedes_embedding": order_a == order_b == ["document_rejected", "embedded"],
                            "independent_workloads_match": vector_a.get("vector") == vector_b.get("vector"),
                            "expected_vector_match": vector_a.get("vector") == expected,
                            "vector": vector_a.get("vector")})

    evidence = {
        "schema": "saf-k8s-0909-002-observations/1",
        "red": {"unapproved_model_accepted": red_ok,
                "unapproved_model_sha256": red_event.get("model_sha256"),
                "vector_changed": red_event.get("vector") != expected},
        "green": {"signature_decision": signature, "rejected_before_embedding": green_ok,
                  "reason": rejected_model.get("reason"),
                  "embed_calls": rejected_model.get("embed_calls", 0),
                  "vector_emitted": rejected_model.get("vector_emitted")},
        "positive": {"malformed_fixture_rejected_before_embedding": positive_ok,
                     "malformed_reason": malformed_a.get("reason"),
                     "malformed_embed_calls": malformed_a.get("embed_calls"),
                     "malformed_event_precedes_embedding": order_a == order_b == ["document_rejected", "embedded"],
                     "independent_workloads_identical": vector_a.get("vector") == vector_b.get("vector"),
                     "expected_vector_match": vector_a.get("vector") == expected,
                     "vector": vector_a.get("vector")},
    }
    (lab.evidence / "embedding-integrity-observations.json").write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n")
