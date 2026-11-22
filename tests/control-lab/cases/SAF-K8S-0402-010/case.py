"""Exercise v1.37 signer-authorized CTB selection and projected update."""
import json
from pathlib import Path
import re
import subprocess
import time


NODE_IMAGE = (
    "kindest/node:v1.37.0@sha256:"
    "a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
)
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
NAMESPACE = "saf-0402-010-fixtures"
SIGNER = "identity.example.test/pod-workload"
SELECTED_NAME = "identity.example.test:pod-workload:selected"
DECOY_NAME = "identity.example.test:pod-workload:decoy"
SELECTOR = {"matchLabels": {"saf-k8s.example/track": "selected"}}
SCOPE = (
    "Kubernetes v1.37.0 kind with one inert Pod. Authorized requests create and update "
    "synthetic public CA bundles. The Pod checks selection and refresh by signer and label. "
    "Signer-specific authorization, Pod certificate lifecycle and federation require separate evidence."
)


def prepare_kind(lab, temporary: Path) -> Path:
    """Use the pinned 1.37 kind node without changing feature gates."""
    config = temporary / "kind.yaml"
    config.write_text("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n- role: control-plane\n", encoding="utf-8")
    config.chmod(0o600)
    return config


def _kubectl(lab, *args, payload=None, timeout=45):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig),
               "--context", f"kind-{lab.cluster}", f"--request-timeout={timeout - 5}s",
               "--namespace", NAMESPACE, *args]
    with (lab.evidence / "commands.log").open("a", encoding="utf-8") as log:
        log.write(f"$ kubectl {' '.join(args)} [body and response omitted]\n")
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            env=lab.env, timeout=timeout)
    if result.returncode:
        detail = re.sub(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                        "[public fixture certificate]", result.stderr, flags=re.S)
        lab.block(f"The owned CTB request failed: {detail[:320].strip()}")
    return result.stdout


def _make_ca(temporary: Path, label: str) -> tuple[bytes, str]:
    key = temporary / f"{label}.key"
    cert = temporary / f"{label}.pem"
    try:
        result = subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-days", "2", "-subj", f"/CN=saf-k8s-{label}.test",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(key), "-out", str(cert),
        ], capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError("synthetic CA generation failed")
        key.chmod(0o600)
        pem = cert.read_bytes()
        fingerprint = _fingerprints(pem, temporary)
        if len(fingerprint) != 1:
            raise ValueError("synthetic CA certificate did not parse")
        return pem, fingerprint[0]
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise RuntimeError("could not prepare a synthetic public CA") from None
    finally:
        key.unlink(missing_ok=True)


def _fingerprints(pem: bytes, temporary: Path) -> list[str]:
    """Return public certificate fingerprints only, never PEM or key bytes."""
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    if not blocks and pem.strip():
        raise ValueError("Projected CA file contains invalid certificate data")
    found = []
    for index, block in enumerate(blocks):
        path = temporary / f"fingerprint-{index}.pem"
        path.write_bytes(block + b"\n")
        try:
            result = subprocess.run(["openssl", "x509", "-in", str(path), "-noout",
                                     "-fingerprint", "-sha256"], capture_output=True,
                                    text=True, timeout=15)
        finally:
            path.unlink(missing_ok=True)
        if result.returncode:
            raise ValueError("Projected CA certificate did not parse")
        found.append(result.stdout.strip().split("=", 1)[-1].replace(":", "").lower())
    return found


def _bundle(name, track, pem):
    return {
        "apiVersion": "certificates.k8s.io/v1", "kind": "ClusterTrustBundle",
        "metadata": {"name": name, "labels": {"saf-k8s.example/track": track}},
        "spec": {"signerName": SIGNER, "trustBundle": pem.decode("ascii")},
    }


def _pod():
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "ctb-consumer", "namespace": NAMESPACE},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                 "serviceAccountName": "default",
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [{"name": "idle", "image": IMAGE,
                                 "command": ["sh", "-c", "sleep 3600"],
                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                     "readOnlyRootFilesystem": True,
                                                     "capabilities": {"drop": ["ALL"]}},
                                 "volumeMounts": [{"name": "roots", "mountPath": "/ctb",
                                                   "readOnly": True}]}],
                 "volumes": [{"name": "roots", "projected": {"sources": [
                     {"clusterTrustBundle": {"signerName": SIGNER,
                                              "labelSelector": SELECTOR,
                                              "path": "roots.pem", "optional": True}}
                 ]}}]},
    }


def _projected(lab, temporary: Path):
    output = _kubectl(lab, "exec", "ctb-consumer", "--", "cat", "/ctb/roots.pem", timeout=30)
    return _fingerprints(output.encode("ascii", errors="ignore"), temporary)


def check_projection(lab, temporary, expected, phase, assertion):
    deadline = time.monotonic() + 150
    observed = []
    while time.monotonic() < deadline:
        observed = _projected(lab, temporary)
        if observed == expected:
            break
        time.sleep(3)
    lab.check(phase, assertion, observed == expected,
              {"fingerprints_match": observed == expected, "certificate_count": len(observed)})


def run(lab):
    temporary = lab.kubeconfig.parent / "ctb-material"
    temporary.mkdir(mode=0o700)
    version = json.loads(_kubectl(lab, "version", "-o", "json"))
    api = json.loads(_kubectl(lab, "get", "--raw=/apis/certificates.k8s.io/v1"))
    nodes = json.loads(_kubectl(lab, "get", "nodes", "-o", "json"))
    server = version["serverVersion"]["gitVersion"]
    kubelets = {item["status"]["nodeInfo"]["kubeletVersion"] for item in nodes["items"]}
    served = {item["name"] for item in api["resources"]}
    lab.check("positive", "Pinned Kubernetes v1.37 serves the stable identity APIs",
              server == "v1.37.0" and kubelets == {"v1.37.0"}
              and {"clustertrustbundles", "podcertificaterequests"} <= served,
              {"server": server, "kubelets": sorted(kubelets),
               "ctb_v1": "clustertrustbundles" in served,
               "pcr_v1": "podcertificaterequests" in served})

    first_pem, first_fp = _make_ca(temporary, "selected-v1")
    decoy_pem, decoy_fp = _make_ca(temporary, "comparison")
    next_pem, next_fp = _make_ca(temporary, "selected-v2")
    if len({first_fp, decoy_fp, next_fp}) != 3:
        lab.block("The fixture requires three distinct public certificates")
    _kubectl(lab, "create", "namespace", NAMESPACE, "-o", "name")
    _kubectl(lab, "create", "-f", "-", "-o", "name",
             payload=json.dumps(_bundle(DECOY_NAME, "decoy", decoy_pem)))
    _kubectl(lab, "create", "-f", "-", "-o", "name", payload=json.dumps(_pod()))
    _kubectl(lab, "wait", "--for=condition=Ready", "pod/ctb-consumer", "--timeout=120s", timeout=130)
    check_projection(lab, temporary, [], "red",
                     "A bundle without the selected label supplies no trust anchors")

    _kubectl(lab, "create", "-f", "-", "-o", "name",
             payload=json.dumps(_bundle(SELECTED_NAME, "selected", first_pem)))
    check_projection(lab, temporary, [first_fp], "green",
                     "The Pod receives only the public CA selected by signer and label")

    replacement = _bundle(SELECTED_NAME, "selected", next_pem)
    replacement["metadata"]["resourceVersion"] = _kubectl(
        lab, "get", "clustertrustbundle", SELECTED_NAME, "-o", "jsonpath={.metadata.resourceVersion}"
    ).strip()
    _kubectl(lab, "replace", "-f", "-", "-o", "name", payload=json.dumps(replacement))
    check_projection(lab, temporary, [next_fp], "positive",
                     "The running Pod receives only the replacement CA after the update")
