"""Verify approved keyless OCI signing and private Sigstore proof."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
ISSUER = "https://kubernetes.default.svc.cluster.local"
NAMESPACE = "saf-test"
SIGNER = "saf-0602-001-signer"
EXPECTED_IDENTITY = f"https://kubernetes.io/namespaces/{NAMESPACE}/serviceaccounts/{SIGNER}"
COSIGN = ("ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:"
          "0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d")
PYTHON = ("docker.io/library/python:3.13-slim@sha256:"
          "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
SKOPEO = ("quay.io/skopeo/stable:v1.20.0@sha256:"
          "47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4")
SCOPE = (
    "Kind v1.36.1 with a cluster-local Kubernetes-issued OIDC service account token, "
    "private Fulcio, certificate transparency, Rekor v2, timestamp and TUF services, and "
    "a test-owned TLS registry. Pinned Cosign verifies the exact OCI image digest and "
    "required transparency and time evidence before a release creates the fixture Pod. "
    "Native admission consumes the verified image reference from an immutable fixture approval. "
    "Deployed identity policy, verifier integration, admission coverage and provenance require separate evidence."
)


def load_module(name, location):
    spec = importlib.util.spec_from_file_location(name, location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stage_image(registry):
    lab = registry.lab
    lab.command("docker", "pull", BUSYBOX_IMAGE, timeout=140)
    directory = registry.work / "keyless-image"
    directory.mkdir(mode=0o700)
    registry.docker("image", "save", "--output", str(directory / "image.tar"), BUSYBOX_IMAGE, timeout=100)
    (directory / "ca.crt").write_bytes(registry.registry_ca.read_bytes())
    target = f"{registry.registry}/fixture/keyless:case"
    registry.docker("run", "--rm", "--network", "kind", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--volume", f"{directory}:/fixture",
                    SKOPEO, "copy", "--format", "oci", "--dest-cert-dir", "/fixture",
                    "--digestfile", "/fixture/subject-digest", "docker-archive:/fixture/image.tar",
                    f"docker://{target}", timeout=120)
    return f"{target.rsplit(':', 1)[0]}@{(directory / 'subject-digest').read_text().strip()}"


def signing_config_args():
    endpoints = {
        "fulcio": ("http://fulcio.fulcio-system.svc", 1),
        "rekor": ("http://rekor.rekor-system.svc", 2),
        "tsa": ("http://tsa.tsa-system.svc/api/v1/timestamp", 1),
        "oidc-provider": (ISSUER, 1),
    }
    services = [f"--{service}=url={url},api-version={api},start-time=2024-01-01T00:00:00Z,operator=saf-test"
                for service, (url, api) in endpoints.items()]
    return ["signing-config", "create", *services, "--rekor-config=EXACT:1", "--tsa-config=EXACT:1",
            "--out", "/saf-bundle/signing-config.json"]


def client_pod(name, args, *, sign=False):
    env = [{"name": k, "value": v} for k, v in {
        "TUF_ROOT": "/saf-tuf-cache", "TUF_MIRROR": "http://tuf.tuf-system.svc",
        "TUF_ROOT_JSON": "/saf-tuf/root.json", "SSL_CERT_FILE": "/saf-registry/ca.crt",
    }.items()]
    mounts = [
        {"name": "tuf-cache", "mountPath": "/saf-tuf-cache"},
        {"name": "tuf-root", "mountPath": "/saf-tuf", "readOnly": True},
        {"name": "registry-ca", "mountPath": "/saf-registry", "readOnly": True},
    ]
    termination_mount = {"name": "bundle", "mountPath": "/saf-bundle"}
    volumes = [
        {"name": "tuf-cache", "emptyDir": {}},
        {"name": "tuf-root", "configMap": {"name": "saf-private-sigstore-root"}},
        {"name": "registry-ca", "configMap": {"name": "saf-private-registry-ca"}},
    ]
    containers = [{"name": "cosign", "image": COSIGN, "args": args, "env": env, "volumeMounts": list(mounts)}]
    spec = {"automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532},
            "volumes": volumes, "containers": containers}
    if sign:
        spec["serviceAccountName"] = SIGNER
        spec["initContainers"] = [{
            "name": "pin-private-signing-endpoints", "image": COSIGN, "args": signing_config_args(),
            "volumeMounts": [termination_mount],
        }]
        volumes.extend([
            {"name": "identity", "projected": {"sources": [{"serviceAccountToken": {
                "path": "oidc-token", "audience": "sigstore", "expirationSeconds": 600,
            }}]}},
            {"name": "bundle", "emptyDir": {}},
        ])
        containers[0]["volumeMounts"].extend([
            {"name": "identity", "mountPath": "/saf-identity", "readOnly": True},
            termination_mount,
        ])
        containers.append({"name": "evidence", "image": PYTHON, "volumeMounts": [termination_mount],
                           "command": ["python", "-c", "import time; time.sleep(240)"]})
    for container in containers:
        container["resources"] = {"requests": {"cpu": "25m", "memory": "48Mi"},
                                  "limits": {"cpu": "1", "memory": "256Mi"}}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": spec}


def invocation(lab, name, args, *, sign=False):
    lab.create(client_pod(name, args, sign=sign))
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        expression = 'jsonpath={.status.containerStatuses[?(@.name=="cosign")].state.terminated.exitCode}'
        status = lab.kubectl("get", "pod", name, "-o", expression).stdout.strip()
        if status:
            output = lab.kubectl("logs", name, "-c", "cosign").stdout
            return int(status), output
        time.sleep(1)
    lab.kubectl("describe", "pod", name, allow_failure=True)
    lab.block(f"Cosign fixture {name} did not finish")


def verification(ref, *, identity=EXPECTED_IDENTITY, issuer=ISSUER):
    return ["verify", "--certificate-identity", identity, "--certificate-oidc-issuer", issuer, ref]


def receipt(bundle):
    materials = bundle["verificationMaterial"]
    entries = materials.get("tlogEntries", [])
    logged = any(entry.get("inclusionProof", {}).get("checkpoint", {}).get("envelope")
                 and entry["inclusionProof"].get("rootHash") and entry.get("logId", {}).get("keyId")
                 for entry in entries)
    has_timestamp = bool(materials.get("timestampVerificationData", {}).get("rfc3161Timestamps"))
    has_certificate = bool(materials.get("certificate", {}).get("rawBytes"))
    return {"private_rekor_inclusion_proof": logged, "timestamp_present": has_timestamp,
            "fulcio_leaf_present": has_certificate}


def run_verified_image(registry, ref):
    lab = registry.lab
    node = f"{lab.cluster}-control-plane"
    path = f"/etc/containerd/certs.d/{registry.registry}"
    config = registry.work / "keyless-hosts.toml"
    config.write_text(f'[host."https://{registry.registry}"]\n'
                      f'capabilities = ["pull", "resolve"]\nca = "{path}/ca.crt"\n')
    registry.docker("exec", node, "mkdir", "-p", path)
    registry.docker("cp", str(config), f"{node}:{path}/hosts.toml")
    registry.docker("cp", str(registry.registry_ca), f"{node}:{path}/ca.crt")
    name = "saf-0602-001-verified"
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "containers": [{"name": "app", "image": ref, "imagePullPolicy": "Always",
                        "command": ["/bin/echo", "keyless-fixture-ready"]}],
    }})
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}", "--timeout=85s", timeout=95)
    state = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)["status"]
    image = state["containerStatuses"][0]["imageID"].endswith(ref.rsplit("@", 1)[1])
    marker = lab.kubectl("logs", name).stdout.strip() == "keyless-fixture-ready"
    lab.check("positive", "Kubernetes runs the exact digest after keyless verification",
              image and marker, {"runtime_digest_matches": image, "fixture_process_exited_successfully": marker})


def exercise(lab, registry, root):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": SIGNER}})
    for name, files in (
        ("saf-private-sigstore-root", {"root.json": root.decode("utf-8")}),
        ("saf-private-registry-ca", {"ca.crt": registry.registry_ca.read_text()}),
    ):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "data": files})
    ref = stage_image(registry)
    code, detail = invocation(lab, "saf-unsigned", verification(ref))
    absent = code != 0 and ("no signatures" in detail.lower() or "no matching attestations" in detail.lower())
    lab.check("red", "The exact image digest has no keyless proof before signing", absent,
              {"signature_absent": absent})
    code, detail = invocation(lab, "saf-sign", [
        "sign", "--yes", "--identity-token", "/saf-identity/oidc-token",
        "--signing-config", "/saf-bundle/signing-config.json",
        "--bundle", "/saf-bundle/receipt.json", ref,
    ], sign=True)
    if code != 0:
        logs = subprocess.run(
            ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
             "-n", "fulcio-system", "logs", "deployment/fulcio", "--tail=140"],
            env=lab.env, capture_output=True, text=True, check=False, timeout=15,
        )
        scrubbed = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                          "[redacted fixture token]", logs.stdout + logs.stderr)
        (lab.evidence / "private-fulcio-diagnostics.log").write_text(scrubbed)
        lab.block("Private Cosign signing returned nonzero; see private Fulcio fixture diagnostics")
    bundle = json.loads(lab.kubectl("exec", "saf-sign", "-c", "evidence", "--",
                                    "cat", "/saf-bundle/receipt.json").stdout)
    proofs = receipt(bundle)
    lab.check("green", "Signing returns private Rekor inclusion, a timestamp and the Fulcio leaf",
              all(proofs.values()), proofs)

    for label, wrong in (("identity", EXPECTED_IDENTITY + "-other"), ("issuer", ISSUER + "/other")):
        code, detail = invocation(lab, f"saf-other-{label}", verification(ref, **{label: wrong}))
        text = detail.lower()
        denied = code != 0 and "failed to verify certificate identity" in text and wrong.lower() in text
        lab.check("green", f"Cosign rejects the valid signature under a mismatched {label}",
                  denied, {"wrong_expected_value_rejected": denied})
    code, detail = invocation(lab, "saf-verified-id", verification(ref))
    verified = code == 0
    lab.check("positive", "Cosign verifies the certificate identity, private log proof and digest",
              verified, {"verified_using_local_private_root": verified})
    admission = load_module("saf_keyless_admission", HERE / "admission_addendum.py")
    admission.run(lab, ref=ref, verification_result={
        "ref": ref, "identity": EXPECTED_IDENTITY, "issuer": ISSUER, "cosign_exit_code": code, **proofs,
    })
    run_verified_image(registry, ref)
    (lab.evidence / "private-keyless-observations.json").write_text(json.dumps({
        **proofs, "oidc_issuer": ISSUER, "certificate_identity_policy": EXPECTED_IDENTITY,
        "signature_digest": ref.rsplit("@", 1)[1], "verified": verified,
    }, indent=2, sort_keys=True) + "\n")


def run(lab):
    private = load_module("saf_private_sigstore", HERE / "private_sigstore.py")
    fixture = load_module("saf_private_registry", HERE.parent / "SAF-K8S-0605-002" / "image_admission.py")
    root = private.provision(lab)
    with fixture.registry(lab) as (registry, _, _):
        exercise(lab, registry, root)
