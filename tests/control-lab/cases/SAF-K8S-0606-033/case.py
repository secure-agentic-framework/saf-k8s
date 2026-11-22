"""Demonstrate scoped GitOps-only Deployment writes using a live Argo CD controller."""
from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import time

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
ARGO_RELEASE = "v3.6.1"
ARGO_INSTALL = f"https://raw.githubusercontent.com/argoproj/argo-cd/{ARGO_RELEASE}/manifests/install.yaml"
ARGO_INSTALL_SHA256 = "7be23ca7d9ca3d3074dee8332f1ca92a933b990cee7c9cf22cf3843ee8c2913e"
ARGO_TAG = f"quay.io/argoproj/argocd:{ARGO_RELEASE}"
ARGO_IMAGE = f"{ARGO_TAG}@sha256:296e3d74f449b2ce45265613fcb68c18ed7366488360c8ea32f5f2a93d2e5c54"
APP = "saf-git-only-fixture"
PROD = "prod-fixture"
POLICY = "saf-git-only-deployments"
CONTROLLER = "system:serviceaccount:argocd:argocd-application-controller"
REPO_URL = "http://saf-git-source.saf-test.svc.cluster.local:8080/repo.git"
SCOPE = (
    "One disposable Kind cluster; one case-owned namespace labelled as a production-like scope; "
    "one Deployment resource; Argo CD v3.6.1; Kubernetes v1.36.1. The case verifies the ordinary "
    "operator SA lacks Deployment write permissions, a separately write-granted out-of-band SA "
    "reaches and is denied by a ValidatingAdmissionPolicy, and the running Argo application "
    "controller reconciles an inert Deployment from a deterministic local Git repository. "
    "It does not establish fleet-wide or production operational coverage."
)


def get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def wait_until(lab, predicate, description, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(3)
    lab.block(f"Timed out waiting for {description}")


def make_git_repo(lab):
    work = lab.kubeconfig.parent / "git-work"
    bare = lab.kubeconfig.parent / "repo.git"
    shutil.copytree(HERE / "fixtures" / "source", work)
    lab.command("git", "init", "--template=", "-b", "main", str(work))
    lab.command("git", "-C", str(work), "add", "--", "release.yaml")
    lab.command("env", "GIT_AUTHOR_DATE=2026-01-01T00:00:00+00:00",
                "GIT_COMMITTER_DATE=2026-01-01T00:00:00+00:00",
                "git", "-C", str(work), "-c", "user.name=SAF fixture",
                "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null",
                "-c", "commit.gpgsign=false", "commit", "-m", "approved inert deployment")
    revision = lab.command("git", "-C", str(work), "rev-parse", "HEAD").stdout.strip()
    lab.command("git", "clone", "--bare", str(work), str(bare))
    lab.command("git", "--git-dir", str(bare), "update-server-info")
    files = [bare / "HEAD", bare / "info/refs", *sorted((bare / "objects").glob("*/*"))]
    data, projection = {}, []
    for path in files:
        key = f"file-{len(data)}"
        data[key] = b64encode(path.read_bytes()).decode("ascii")
        projection.append({"key": key, "path": f"repo.git/{path.relative_to(bare).as_posix()}"})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "saf-git-source"},
                "immutable": True, "binaryData": data})
    server = {
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "saf-git-source"},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "saf-git-source"}},
                 "template": {"metadata": {"labels": {"app": "saf-git-source"}}, "spec": {
                     "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "volumes": [{"name": "source", "configMap": {"name": "saf-git-source", "items": projection}}],
                     "containers": [{"name": "http", "image": BUSYBOX_IMAGE,
                                      "command": ["httpd", "-f", "-p", "8080", "-h", "/git"],
                                      "ports": [{"name": "http", "containerPort": 8080}],
                                      "volumeMounts": [{"name": "source", "mountPath": "/git", "readOnly": True}],
                                      "readinessProbe": {"httpGet": {"path": "/repo.git/HEAD", "port": "http"},
                                                         "initialDelaySeconds": 1, "periodSeconds": 2},
                                      "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                    "limits": {"cpu": "100m", "memory": "64Mi"}},
                                      "securityContext": {"allowPrivilegeEscalation": False,
                                                           "readOnlyRootFilesystem": True,
                                                           "capabilities": {"drop": ["ALL"]}}}]
                 }}}
    }
    lab.create(server)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "saf-git-source"},
                "spec": {"selector": {"app": "saf-git-source"},
                         "ports": [{"name": "http", "port": 8080, "targetPort": "http"}]}})
    lab.kubectl("rollout", "status", "deployment/saf-git-source", "--timeout=90s", timeout=100)
    return revision


def install_argo(lab):
    manifest = lab.kubeconfig.with_name("argo-install.yaml")
    lab.command("curl", "-fsSL", "--max-time", "60", ARGO_INSTALL, "-o", str(manifest), timeout=70)
    if sha256(manifest.read_bytes()).hexdigest() != ARGO_INSTALL_SHA256:
        lab.block("Pinned Argo CD release manifest checksum mismatch")
    manifest.write_text(manifest.read_text().replace(f"image: {ARGO_TAG}", f"image: {ARGO_IMAGE}"))
    lab.kubectl("create", "namespace", "argocd")
    lab.kubectl("apply", "--server-side", "-n", "argocd", "-f", str(manifest), timeout=180)
    wait_until(lab, lambda: all(
        (get_json(lab, "-n", "argocd", "get", kind, name)["status"].get("readyReplicas") or 0) >= 1
        for kind, name in (("statefulset", "argocd-application-controller"),
                           ("deployment", "argocd-repo-server"))
    ), "Argo CD controller and repo server", timeout=300)
    workloads = get_json(lab, "-n", "argocd", "get", "deployments,statefulsets")["items"]
    selected = [item for item in workloads if item["metadata"]["name"] in
                {"argocd-application-controller", "argocd-repo-server"}]
    images = {item["metadata"]["name"]: [c["image"] for c in item["spec"]["template"]["spec"]["containers"]]
              for item in selected}
    lab.check("positive", "Argo CD control components run the digest-pinned v3.6.1 image",
              len(images) == 2 and all(refs == [ARGO_IMAGE] for refs in images.values()), images)


def prepare_identities(lab):
    lab.kubectl("create", "namespace", PROD)
    lab.kubectl("label", "namespace", PROD, "saf.example.test/git-only=true")
    rbac = HERE / "fixtures" / "rbac.yaml"
    for document in rbac.read_text().split("\n---\n"):
        namespace = PROD if f"namespace: {PROD}" in document else "saf-test"
        lab.kubectl("-n", namespace, "apply", "-f", "-", payload=document)
    # Bind only the approved Argo controller's namespaced Deployment role.
    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "saf-argo-deployments", "namespace": PROD},
            "rules": [{"apiGroups": ["apps"], "resources": ["deployments"],
                       "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]}]}
    binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
               "metadata": {"name": "saf-argo-deployments", "namespace": PROD},
               "subjects": [{"kind": "ServiceAccount", "name": "argocd-application-controller",
                             "namespace": "argocd"}],
               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                           "name": "saf-argo-deployments"}}
    for item in (role, binding):
        lab.kubectl("-n", PROD, "create", "-f", "-", payload=json.dumps(item))


def issue_token(lab, namespace, service_account, destination):
    # Capture short-lived token privately. Never pass it as an argv value or write it to evidence.
    result = subprocess.run(["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                             "-n", namespace, "create", "token", service_account, "--duration=10m"],
                            text=True, capture_output=True, env=lab.env, timeout=30)
    if result.returncode:
        lab.block(f"TokenRequest failed for fixture identity {namespace}/{service_account}")
    token = result.stdout.strip()
    if not token:
        lab.block(f"TokenRequest returned no token for fixture identity {namespace}/{service_account}")
    view = subprocess.run(["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                           "config", "view", "--raw", "--minify", "-o", "json"],
                          text=True, capture_output=True, env=lab.env, timeout=20)
    if view.returncode:
        lab.block("Unable to extract the disposable API endpoint and CA for fixture kubeconfig")
    config = json.loads(view.stdout)
    cluster = config["clusters"][0]["cluster"]
    auth = {"apiVersion": "v1", "kind": "Config", "clusters": [{"name": "fixture",
            "cluster": {"server": cluster["server"], "certificate-authority-data": cluster["certificate-authority-data"]}}],
            "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": "fixture",
                           "namespace": PROD}}], "current-context": "fixture",
            "users": [{"name": "fixture", "user": {"token": token}}]}
    destination.write_text(json.dumps(auth))
    destination.chmod(0o600)
    del token


def identity_command(lab, kubeconfig, *args, allow_failure=False):
    command = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", "fixture", "--namespace", PROD,
               "--request-timeout=20s", *args]
    result = subprocess.run(command, text=True, capture_output=True, env=lab.env, timeout=30)
    with (lab.evidence / "identity-probes.log").open("a") as log:
        log.write("$ kubectl --kubeconfig <private-short-lived-identity> --context fixture --namespace "
                  + PROD + " " + " ".join(args) + "\n")
        log.write(result.stdout + result.stderr + f"\n[exit {result.returncode}]\n\n")
    if result.returncode and not allow_failure:
        lab.block("Identity probe command failed unexpectedly")
    return result


def policy(lab):
    lab.kubectl("apply", "-f", str(HERE / "fixtures" / "admission-policy.yaml"))
    binding = get_json(lab, "get", "validatingadmissionpolicybinding", POLICY)
    lab.check("positive", "A Deny binding scopes the fail-closed policy to the labelled fixture namespace",
              binding["spec"]["validationActions"] == ["Deny"]
              and binding["spec"]["matchResources"]["namespaceSelector"]["matchLabels"]
              == {"saf.example.test/git-only": "true"},
              {"binding": binding["metadata"]["name"], "actions": binding["spec"]["validationActions"]})


def run(lab):
    install_argo(lab)
    prepare_identities(lab)
    git_revision = make_git_repo(lab)
    lab.kubectl("wait", "--for=condition=Ready", "pod", "-l", "app=saf-git-source", "--timeout=60s", timeout=70)

    temporary = lab.kubeconfig.parent
    operator_cfg = temporary / "operator.kubeconfig"
    probe_cfg = temporary / "out-of-band.kubeconfig"
    issue_token(lab, "saf-test", "saf-operator", operator_cfg)
    issue_token(lab, "saf-test", "saf-out-of-band-probe", probe_cfg)
    verbs = {verb: identity_command(lab, operator_cfg, "auth", "can-i", verb, "deployments.apps",
                                    allow_failure=True).stdout.strip()
             for verb in ("create", "update", "patch", "delete")}
    denied = all(value == "no" for value in verbs.values())
    lab.check("positive", "The normal operator ServiceAccount has no direct Deployment mutation rights in the fixture production namespace",
              denied, {"can_i": verbs, "identity": "system:serviceaccount:saf-test:saf-operator"})
    candidate = {"apiVersion": "apps/v1", "kind": "Deployment",
                 "metadata": {"name": "operator-direct-attempt"},
                 "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "denied"}},
                          "template": {"metadata": {"labels": {"app": "denied"}},
                                       "spec": {"containers": [{"name": "marker", "image": BUSYBOX_IMAGE,
                                                                   "command": ["sh", "-c", "sleep 3600"]}]}}}}
    # Pass the inert object over stdin; keep its kubeconfig token out of argv and logs.
    denied_create = subprocess.run(["kubectl", "--kubeconfig", str(operator_cfg), "--context", "fixture",
                                    "--namespace", PROD, "--request-timeout=20s", "create", "-f", "-", "-o", "json"],
                                   input=json.dumps(candidate), text=True, capture_output=True,
                                   env=lab.env, timeout=30)
    with (lab.evidence / "identity-probes.log").open("a") as log:
        log.write("$ kubectl --kubeconfig <private-short-lived-identity> create -f <inert-fixture>\n")
        log.write(denied_create.stdout + denied_create.stderr + f"\n[exit {denied_create.returncode}]\n\n")
    lab.check("positive", "An actual routine operator create request is rejected by RBAC before admission",
              denied_create.returncode != 0 and "forbidden" in denied_create.stderr.lower(),
              {"api_request_denied": denied_create.returncode != 0,
               "forbidden": "forbidden" in denied_create.stderr.lower()})

    probe = {**candidate, "metadata": {"name": "out-of-band-fixture"}}
    def probe_create():
        result = subprocess.run(
            ["kubectl", "--kubeconfig", str(probe_cfg), "--context", "fixture",
             "--namespace", PROD, "--request-timeout=20s", "create", "-f", "-",
             "-o", "json", "--dry-run=server"],
            input=json.dumps(probe), text=True, capture_output=True, env=lab.env, timeout=30,
        )
        with (lab.evidence / "identity-probes.log").open("a") as log:
            log.write("$ kubectl --kubeconfig <fixture-identity> create -f <fixture> --dry-run=server\n")
            log.write(result.stdout + result.stderr + f"\n[exit {result.returncode}]\n\n")
        return result

    baseline_result = probe_create()
    baseline_created = (baseline_result.returncode == 0
                        and json.loads(baseline_result.stdout)["metadata"]["name"] == probe["metadata"]["name"])
    lab.check("red", "Before admission enforcement, the scoped out-of-band principal can create the inert fixture Deployment",
              baseline_created, {"created": baseline_created,
                                 "identity": "system:serviceaccount:saf-test:saf-out-of-band-probe"})
    policy(lab)

    # Registration and admission policy cache propagation are asynchronous.
    deadline = time.monotonic() + 30
    request = probe_create()
    while request.returncode == 0 and time.monotonic() < deadline:
        time.sleep(1)
        request = probe_create()
    explicit_policy_denial = (request.returncode != 0
                              and "saf-git-only-deployments" in request.stderr
                              and "approved GitOps controller" in request.stderr)
    lab.check("green", "A real out-of-band ServiceAccount request that passes RBAC is denied by the configured admission policy",
              explicit_policy_denial,
              {"role_grant_is_fixture_only": True, "api_request_denied": request.returncode != 0,
               "policy_response": "saf-git-only-deployments" in request.stderr,
               "identity": "system:serviceaccount:saf-test:saf-out-of-band-probe"})

    app = {"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
           "metadata": {"name": APP, "namespace": "argocd"},
           "spec": {"project": "default", "source": {"repoURL": REPO_URL,
                     "targetRevision": git_revision, "path": "."},
                   "destination": {"server": "https://kubernetes.default.svc", "namespace": PROD},
                   "syncPolicy": {"automated": {"enabled": True}}}}
    lab.kubectl("-n", "argocd", "create", "-f", "-", payload=json.dumps(app))

    def synced():
        application = get_json(lab, "-n", "argocd", "get", "application", APP)
        status = application.get("status", {})
        deployment = lab.kubectl("-n", PROD, "get", "deployment", "git-approved-demo",
                                 "--ignore-not-found", "-o", "json", allow_failure=True)
        if deployment.returncode or not deployment.stdout.strip():
            return False
        live = json.loads(deployment.stdout)
        return (status.get("sync", {}).get("status") == "Synced"
                and status.get("sync", {}).get("revision") == git_revision
                and status.get("health", {}).get("status") == "Healthy"
                and live["metadata"].get("labels", {}).get("app.kubernetes.io/name") == "git-approved-demo"
                and live["status"].get("readyReplicas") == 1)

    wait_until(lab, synced, "Argo CD to sync the Git revision through its actual controller identity")
    live = get_json(lab, "-n", PROD, "get", "deployment", "git-approved-demo")
    application = get_json(lab, "-n", "argocd", "get", "application", APP)
    observed = {"application_revision": application["status"]["sync"].get("revision"),
                "expected_git_revision": git_revision,
                "sync": application["status"]["sync"]["status"],
                "health": application["status"]["health"]["status"],
                "ready_replicas": live["status"].get("readyReplicas"),
                "controller_identity": CONTROLLER,
                "policy_name": POLICY}
    lab.check("positive", "The live Argo CD controller deploys the approved inert manifest from the exact local Git commit",
              observed["application_revision"] == git_revision and observed["sync"] == "Synced"
              and observed["health"] == "Healthy", observed)
