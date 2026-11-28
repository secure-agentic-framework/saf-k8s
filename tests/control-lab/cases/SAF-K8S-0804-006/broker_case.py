"""Exercise recipient-bound sealed release through a separately running Kubernetes broker."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time

NS = "saf-test"
HOST = "sealed-broker.saf-test.svc.cluster.local"
MARKER_SHA256 = hashlib.sha256(b"saf-sealed-fixture-marker-v1").hexdigest()
HERE = Path(__file__).resolve().parent


def _quiet(lab, args, *, input=None, timeout=45, check=True, env=None):
    """Run commands that may carry tokens, envelopes or generated key material without runner logging."""
    try:
        result = subprocess.run(args, input=input, text=True, capture_output=True,
                                env=env or lab.env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        lab.block(f"Fixture command could not complete ({Path(args[0]).name}): {type(exc).__name__}")
    if check and result.returncode:
        lab.block(f"Fixture command failed ({Path(args[0]).name}, exit {result.returncode})")
    return result


def _kubectl(lab, *args, input=None, timeout=45, check=True):
    base = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "--namespace", NS, f"--request-timeout={timeout - 5}s", *args]
    return _quiet(lab, base, input=input, timeout=timeout, check=check)


def _apply(lab, obj):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(obj), timeout=30)


def _wait(lab, name, timeout=90):
    ready = lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", f"--timeout={timeout}s",
                        timeout=timeout + 10, allow_failure=True)
    if ready.returncode:
        lab.kubectl("get", "pod", name, allow_failure=True)
        lab.kubectl("logs", name, allow_failure=True)
        lab.block(f"Fixture Pod {name} did not become ready")


def _exec(lab, pod, *args, input=None, timeout=35, check=True):
    return _kubectl(lab, "exec", "-i", pod, "--", *args, input=input, timeout=timeout, check=check)


def _json(text, label):
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        raise RuntimeError(f"Malformed {label} response")
    if type(value) is not dict:
        raise RuntimeError(f"Malformed {label} response")
    return value


def _pod(name, service_account, container, volumes):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": NS},
            "spec": {"restartPolicy": "Never", "serviceAccountName": service_account,
                     "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "runAsGroup": 65534, "fsGroup": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [container], "volumes": volumes}}


def _container(name, image, mode, mounts, *, ports=None, probe=None):
    result = {"name": name, "image": image, "imagePullPolicy": "Never", "command": ["/fixture", mode],
              "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                  "capabilities": {"drop": ["ALL"]}},
              "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                            "limits": {"cpu": "200m", "memory": "128Mi"}},
              "volumeMounts": mounts}
    if ports:
        result["ports"] = ports
    if probe:
        result["readinessProbe"] = probe
    return result


def _client(lab, image, name, sa, *, wrong_audience=False):
    tokens = [{"serviceAccountToken": {"audience": "saf-fixture-sealed-release",
                                      "expirationSeconds": 600, "path": "good"}}]
    if wrong_audience:
        tokens.append({"serviceAccountToken": {"audience": "saf-fixture-unrelated",
                                              "expirationSeconds": 600, "path": "wrong"}})
    volumes = [
        {"name": "trust", "configMap": {"name": "sealed-public-ca"}},
        {"name": "scratch", "emptyDir": {"sizeLimit": "16Mi", "medium": "Memory"}},
        {"name": "identity", "projected": {"defaultMode": 0o440, "sources": tokens}},
    ]
    mounts = [
        {"name": "trust", "mountPath": "/trust", "readOnly": True},
        {"name": "scratch", "mountPath": "/scratch"},
        {"name": "identity", "mountPath": "/identity", "readOnly": True},
    ]
    probe = {"exec": {"command": ["/fixture", "public"]}, "periodSeconds": 1}
    _apply(lab, _pod(name, sa, _container("client", image, "prepare", mounts, probe=probe), volumes))


def _service_account_uid(lab, name):
    obj = _json(_kubectl(lab, "get", "serviceaccount", name, "-o", "json").stdout, "ServiceAccount")
    uid = obj.get("metadata", {}).get("uid")
    if not isinstance(uid, str) or not uid:
        raise RuntimeError("ServiceAccount UID unavailable")
    return uid


def _pod_uid(lab, name):
    obj = _json(_kubectl(lab, "get", "pod", name, "-o", "json").stdout, "Pod")
    uid = obj.get("metadata", {}).get("uid")
    if not isinstance(uid, str) or not uid:
        raise RuntimeError("Pod UID unavailable")
    return uid


def _request(lab, pod, mode, envelope):
    return _json(_exec(lab, pod, "/fixture", "request", mode,
                       input=json.dumps(envelope), timeout=50).stdout, "broker request")


def run(lab):
    if not shutil.which("go") or not shutil.which("docker"):
        lab.block("The local Go toolchain and Docker CLI are required")
    source = HERE / "sealed-broker" / "main.go"
    if not source.is_file():
        lab.block("Missing standard-library sealed-broker fixture source")
    hostarch = platform.machine().lower()
    arch = {"x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(hostarch)
    if not arch:
        lab.block("Unsupported host architecture for the offline fixture build")
    hostos = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    if not hostos:
        lab.block("Unsupported host operating system for the offline fixture build")

    image_owned = False
    image = f"saf-fixture-sealed-broker:{lab.cluster}"
    try:
        with tempfile.TemporaryDirectory(prefix="saf-sealed-broker-") as temp:
            work = Path(temp)
            binary = work / "fixture"
            host_binary = work / "host-fixture"
            base_env = dict(lab.env, GO111MODULE="off", GOTOOLCHAIN="local", GOPROXY="off", CGO_ENABLED="0")
            host_env = dict(base_env, GOOS=hostos, GOARCH=arch)
            lab.command("env", *[f"{name}={value}" for name, value in {
                "GO111MODULE": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off", "CGO_ENABLED": "0",
                "GOOS": "linux", "GOARCH": arch,
            }.items()], "go", "build", "-trimpath", "-o", str(binary), str(source), timeout=90)
            _quiet(lab, ["go", "build", "-trimpath", "-o", str(host_binary), str(source)], timeout=90, env=host_env)
            (work / "Dockerfile").write_text(
                "FROM scratch\nCOPY fixture /fixture\nUSER 65534:65534\n")
            lab.command("docker", "build", "--tag", image, str(work), timeout=120)
            image_owned = True
            lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=120)

            pki = work / "pki"
            pki.mkdir()
            _quiet(lab, [str(host_binary), "fixture-init", str(pki), HOST], timeout=45)
            _kubectl(lab, "create", "secret", "tls", "sealed-broker-tls",
                     "--cert", str(pki / "tls.crt"), "--key", str(pki / "tls.key"), timeout=30)
            _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "sealed-public-ca"},
                         "binaryData": {"ca.crt": base64.b64encode((pki / "ca.crt").read_bytes()).decode()}})

            # One broker identity has only the API permission needed for TokenReview.
            _apply(lab, {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "sealed-broker"}})
            _apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                         "metadata": {"name": "saf-sealed-broker-tokenreviews"},
                         "rules": [{"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"],
                                    "verbs": ["create"]}]})
            _apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                         "metadata": {"name": "saf-sealed-broker-tokenreviews"},
                         "subjects": [{"kind": "ServiceAccount", "name": "sealed-broker", "namespace": NS}],
                         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                                     "name": "saf-sealed-broker-tokenreviews"}})
            _apply(lab, {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "sealed-client"}})
            _apply(lab, {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "sealed-outsider"}})
            approved = "sealed-good"
            _client(lab, image, approved, "sealed-client", wrong_audience=True)
            _client(lab, image, "sealed-outsider", "sealed-outsider")
            _client(lab, image, "sealed-same-sa-other-pod", "sealed-client")
            _wait(lab, approved)
            good_uid = _pod_uid(lab, approved)
            sa_uid = _service_account_uid(lab, "sealed-client")
            public_key = _exec(lab, approved, "/fixture", "public")
            pub = public_key.stdout.strip()
            try:
                base64.b64decode(pub, validate=True)
            except (ValueError, TypeError):
                lab.block("Client public key response was malformed")

            settings = {"recipient_pk": pub, "issuer_public": (pki / "issuer-public.b64").read_text().strip(),
                        "namespace": NS, "service_account_name": "sealed-client",
                        "service_account_uid": sa_uid, "pod_uid": good_uid}
            _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "sealed-broker-settings"},
                         "data": {"settings.json": json.dumps(settings, separators=(",", ":"))}})
            _apply(lab, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "sealed-broker"},
                         "spec": {"selector": {"app": "sealed-broker"}, "ports": [{"port": 8443, "targetPort": 8443}]}})
            identity = {"name": "identity", "projected": {"defaultMode": 0o440, "sources": [
                {"serviceAccountToken": {"expirationSeconds": 600, "path": "token"}},
                {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}}]}}
            broker = _container("broker", image, "serve", [
                {"name": "tls", "mountPath": "/tls", "readOnly": True},
                {"name": "config", "mountPath": "/config", "readOnly": True},
                {"name": "identity", "mountPath": "/identity", "readOnly": True}],
                ports=[{"containerPort": 8443}],
                probe={"tcpSocket": {"port": 8443}, "initialDelaySeconds": 1, "periodSeconds": 2,
                       "timeoutSeconds": 1, "failureThreshold": 20})
            broker_pod = _pod("sealed-broker", "sealed-broker", broker, [
                {"name": "tls", "secret": {"secretName": "sealed-broker-tls", "defaultMode": 0o440}},
                {"name": "config", "configMap": {"name": "sealed-broker-settings"}}, identity])
            broker_pod["metadata"]["labels"] = {"app": "sealed-broker"}
            _apply(lab, broker_pod)
            _wait(lab, "sealed-broker", 60)

            # Wait for the Service path after Pod readiness. The GET is read-only.
            deadline = time.monotonic() + 20
            while True:
                reached = lab.kubectl("exec", approved, "--", "/fixture", "artifact", timeout=20,
                                      allow_failure=True)
                if reached.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    lab.block("The client could not read the artifact through the broker Service")
                time.sleep(0.5)
            artifact = _json(reached.stdout, "artifact")
            required_artifact = {"artifact_id", "policy", "measurement", "recipient_sha256", "challenge",
                                 "ciphertext_sha256", "nonce", "ciphertext", "subject", "subject_uid", "pod_uid"}
            if set(artifact) != required_artifact:
                lab.block("Broker artifact response was incomplete")
            if artifact["pod_uid"] != good_uid or artifact["subject_uid"] != sa_uid:
                lab.block("Broker artifact identity did not match the intended client")
            _wait(lab, "sealed-outsider")
            _wait(lab, "sealed-same-sa-other-pod")

            issuer_key = pki / "issuer-private.b64"
            def signed(*, expired=False, changes=None):
                subset = {key: value for key, value in artifact.items() if key not in {"nonce", "ciphertext"}}
                subset.update(changes or {})
                now = int(time.time())
                subset["issued_at"] = now - (120 if expired else 5)
                subset["expires_at"] = now - 10 if expired else now + 180
                payload = json.dumps(subset, separators=(",", ":"))
                out = _quiet(lab, [str(host_binary), "sign", str(issuer_key)], input=payload, timeout=30)
                return _json(out.stdout, "signed envelope")

            valid = signed()
            absent = {}
            invalid = dict(valid)
            invalid["signature"] = "AA=="
            expired = signed(expired=True)

            def denied(pod, token, envelope, status, reason):
                return _request(lab, pod, token, envelope) == {
                    "status": status, "reason": reason, "opened": False,
                    "returned_wrapped_key": False, "plaintext_sha256": "",
                }

            subject = "--as=system:serviceaccount:saf-test:sealed-broker"
            can_review = lab.kubectl("auth", "can-i", "create", "tokenreviews.authentication.k8s.io",
                                     subject, allow_failure=True)
            can_read_secret = lab.kubectl("auth", "can-i", "get", "secrets", subject, allow_failure=True)
            identity = {
                "no_token_rejected": denied(approved, "none", valid, 401, "token"),
                "wrong_audience_for_approved_pod_rejected": denied(approved, "wrong", valid, 401, "token"),
                "outsider_with_correct_audience_rejected": denied("sealed-outsider", "good", valid, 403, "recipient"),
                "other_pod_with_same_service_account_rejected": denied(
                    "sealed-same-sa-other-pod", "good", valid, 403, "recipient"),
                "broker_can_create_tokenreviews": can_review.returncode == 0 and can_review.stdout.strip() == "yes",
                "broker_cannot_read_kubernetes_secrets":
                    can_read_secret.returncode == 1 and can_read_secret.stdout.strip() == "no",
            }
            lab.check("broker-workload-identity", "The broker requires the approved workload identity and audience",
                      all(identity.values()), identity)

            bound = {
                "missing_envelope_rejected": denied(approved, "good", absent, 403, "signature"),
                "changed_signature_rejected": denied(approved, "good", invalid, 403, "signature"),
                "expired_envelope_rejected": denied(approved, "good", expired, 403, "time"),
            }
            for field in ("artifact_id", "policy", "measurement", "recipient_sha256", "challenge",
                          "ciphertext_sha256", "subject", "subject_uid", "pod_uid"):
                changed = signed(changes={field: artifact[field] + "-changed"})
                bound[field + "_binding_rejected"] = denied(approved, "good", changed, 403, "binding")
            lab.check("broker-bound-release", "The broker verifies proof signature, bindings and freshness",
                      all(bound.values()), bound)

            # Schedule both exec sessions before waiting on either result.
            with ThreadPoolExecutor(max_workers=2) as pool:
                pending = [pool.submit(_request, lab, approved, "good", valid) for _ in range(2)]
                race = [request.result() for request in pending]
            success = {"status": 200, "reason": "released", "opened": True,
                       "returned_wrapped_key": True, "plaintext_sha256": MARKER_SHA256}
            conflict = {"status": 409, "reason": "replay", "opened": False,
                        "returned_wrapped_key": False, "plaintext_sha256": ""}
            opened = {
                "one_concurrent_request_released_and_opened_marker": race.count(success) == 1,
                "one_concurrent_request_denied_without_key": race.count(conflict) == 1,
                "later_replay_denied_without_key": denied(approved, "good", valid, 409, "replay"),
            }
            lab.check("broker-artifact-open", "The intended workload decrypts once and replay yields no key",
                      all(opened.values()), opened)

            (lab.evidence / "artifact-broker-observations.json").write_text(json.dumps({
                "workload_identity": identity, "envelope_binding_and_time": bound,
                "artifact_open_and_replay": opened,
                "expected_plaintext_sha256": MARKER_SHA256,
            }, indent=2) + "\n")
    finally:
        if image_owned:
            lab.command("docker", "image", "rm", image, timeout=30)
