"""Verify Argo CD live drift detection and self-heal on an inert marker."""
from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import shutil
import time

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
ARGO_RELEASE = "v3.6.1"
ARGO_INSTALL = (
    "https://raw.githubusercontent.com/argoproj/argo-cd/"
    f"{ARGO_RELEASE}/manifests/install.yaml"
)
ARGO_INSTALL_SHA256 = "7be23ca7d9ca3d3074dee8332f1ca92a933b990cee7c9cf22cf3843ee8c2913e"
ARGO_TAG = f"quay.io/argoproj/argocd:{ARGO_RELEASE}"
ARGO_IMAGE = f"{ARGO_TAG}@sha256:296e3d74f449b2ce45265613fcb68c18ed7366488360c8ea32f5f2a93d2e5c54"
APP = "saf-drift-fixture"
CM = "saf-drift-marker"
POD = "saf-drift-reader"
GIT_READER = "saf-git-source"
REPO_URL = "http://saf-git-source.saf-test.svc.cluster.local:8080/repo.git"
SCOPE = (
    "One disposable kind cluster and saf-test namespace; Argo CD v3.6.1 watches a "
    "case-owned, read-only static Git source and reconciles a ConfigMap marker. "
    "The case observes Argo CD OutOfSync with automated sync/selfHeal disabled, "
    "then enables selfHeal and independently checks the ConfigMap and its mounted "
    "value in the same running Pod. Notification delivery, external Git hosting, "
    "production authorization, and other controllers require separate evidence."
)


def git_fixture(lab, directory):
    work = directory / "work"
    bare = directory / "repo.git"
    lab.command("git", "init", "--template=", "-b", "main", str(work))
    shutil.copytree(HERE / "source", work / "source")
    lab.command("git", "-C", str(work), "add", "--", "source")
    lab.command("env", "GIT_AUTHOR_DATE=2026-01-01T00:00:00+00:00",
                "GIT_COMMITTER_DATE=2026-01-01T00:00:00+00:00",
                "git", "-C", str(work), "-c", "user.name=SAF fixture",
                "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null",
                "-c", "commit.gpgsign=false", "commit", "-m", "case-owned desired marker")
    revision = lab.command("git", "-C", str(work), "rev-parse", "HEAD").stdout.strip()
    lab.command("git", "clone", "--bare", str(work), str(bare))
    lab.command("git", "--git-dir", str(bare), "update-server-info")
    return bare, revision


def install_read_only_git_source(lab):
    bare, revision = git_fixture(lab, lab.kubeconfig.parent)
    files = [bare / "HEAD", bare / "info/refs", *sorted((bare / "objects").glob("*/*"))]
    data, projection = {}, []
    for path in files:
        key = f"file-{len(data)}"
        data[key] = b64encode(path.read_bytes()).decode("ascii")
        projection.append({"key": key, "path": f"repo.git/{path.relative_to(bare).as_posix()}"})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": GIT_READER},
                "immutable": True, "binaryData": data})
    git_deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": GIT_READER},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": GIT_READER}},
            "template": {
                "metadata": {"labels": {"app": GIT_READER}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "volumes": [{"name": "source", "configMap": {"name": GIT_READER, "items": projection}}],
                    "containers": [{
                        "name": "http", "image": BUSYBOX_IMAGE,
                        "command": ["httpd", "-f", "-p", "8080", "-h", "/git"],
                        "volumeMounts": [{"name": "source", "mountPath": "/git", "readOnly": True}],
                        "ports": [{"name": "http", "containerPort": 8080}],
                        "readinessProbe": {
                            "httpGet": {"path": "/repo.git/HEAD", "port": "http"},
                            "initialDelaySeconds": 1, "periodSeconds": 2,
                        },
                        "resources": {
                            "requests": {"cpu": "10m", "memory": "24Mi"},
                            "limits": {"cpu": "100m", "memory": "64Mi"},
                        },
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]},
                        },
                    }],
                },
            },
        },
    }
    lab.create(git_deployment)
    lab.create({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": GIT_READER},
                "spec": {"selector": {"app": GIT_READER},
                         "ports": [{"name": "http", "port": 8080, "targetPort": "http"}]}})
    lab.kubectl("rollout", "status", f"deployment/{GIT_READER}", "--timeout=90s", timeout=100)
    return revision


def get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def argo_image_versions(lab):
    workloads = get_json(lab, "-n", "argocd", "get", "deployments,statefulsets")["items"]
    images = {}
    for workload in workloads:
        name = workload["metadata"]["name"]
        if name in {"argocd-application-controller", "argocd-repo-server", "argocd-server"}:
            images[name] = [container["image"] for container in workload["spec"]["template"]["spec"]["containers"]]
    return images


def application(lab):
    return get_json(lab, "-n", "argocd", "get", "application", APP)


def marker(lab):
    return get_json(lab, "get", "configmap", CM)["data"]["version"]


def mounted_marker(lab):
    return lab.kubectl("exec", POD, "--", "cat", "/fixture/version").stdout.strip()


def wait_until(lab, predicate, description, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(3)
    lab.block(f"Timed out waiting for {description}")


def settle(predicate, timeout=120):
    """Poll an expected control outcome; let the caller record a red/green miss."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(3)
    return False


def run(lab):
    install = lab.kubeconfig.with_name("argo-install.yaml")
    lab.command("curl", "-fsSL", "--max-time", "60", ARGO_INSTALL, "-o", str(install), timeout=70)
    if sha256(install.read_bytes()).hexdigest() != ARGO_INSTALL_SHA256:
        lab.block("Argo CD release manifest checksum did not match")
    install.write_text(install.read_text().replace(f"image: {ARGO_TAG}", f"image: {ARGO_IMAGE}"))
    lab.kubectl("create", "namespace", "argocd")
    lab.kubectl("apply", "--server-side", "-n", "argocd", "-f", str(install), timeout=180)
    wait_until(lab, lambda: all(
        workload.get("status", {}).get("availableReplicas", 0) >= 1
        for workload in get_json(lab, "-n", "argocd", "get", "deployments,statefulsets")["items"]
    ), "Argo CD deployments to become available", timeout=360)
    images = argo_image_versions(lab)
    required = {"argocd-application-controller", "argocd-repo-server", "argocd-server"}
    lab.check("positive", "The live controller, repository server, and API server use the tagged Argo CD release",
              required.issubset(images) and all(
                  refs == [ARGO_IMAGE] for refs in images.values()), images)

    git_revision = install_read_only_git_source(lab)
    lab.kubectl("wait", "--for=condition=Ready", "pod", "-l", f"app={GIT_READER}", "--timeout=60s", timeout=70)
    app_fixture = {"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
                "metadata": {"name": APP, "namespace": "argocd"},
                "spec": {"project": "default",
                         "source": {"repoURL": REPO_URL, "targetRevision": git_revision, "path": "source"},
                         "destination": {"server": "https://kubernetes.default.svc", "namespace": "saf-test"},
                         "syncPolicy": {"automated": {"enabled": True, "selfHeal": False}}}}
    lab.kubectl("-n", "argocd", "create", "-f", "-", payload=json.dumps(app_fixture))
    wait_until(lab, lambda: (
        (status := application(lab).get("status", {})).get("sync", {}).get("status") == "Synced"
        and status.get("health", {}).get("status") == "Healthy"
    ), "the initial Git revision to sync and report healthy")
    lab.kubectl("wait", "--for=condition=Ready", "pod", POD, "--timeout=90s", timeout=100)
    initial_state = application(lab)["status"]["sync"]
    original_pod = get_json(lab, "get", "pod", POD)["metadata"]["uid"]
    initial = {"application_sync": initial_state["status"],
               "git_commit_matched": initial_state.get("revision") == git_revision,
               "configmap": marker(lab), "mounted_value": mounted_marker(lab)}
    lab.check("positive", "The legitimate Git marker is present in the ConfigMap and running workload",
              initial["application_sync"] == "Synced" and initial["git_commit_matched"]
              and initial["configmap"] == "approved-v1"
              and initial["mounted_value"] == "approved-v1",
              initial)

    lab.kubectl("patch", "configmap", CM, "--type=merge", "-p", '{"data":{"version":"runtime-drift"}}')
    settle(lambda: application(lab)["status"].get("sync", {}).get("status") == "OutOfSync"
           and mounted_marker(lab) == "runtime-drift", timeout=120)
    red_observation = {"application_sync": application(lab)["status"]["sync"]["status"],
                       "configmap": marker(lab), "mounted_value": mounted_marker(lab),
                       "self_heal": application(lab)["spec"]["syncPolicy"]["automated"].get("selfHeal", False)}
    lab.check("red", "With selfHeal off, Argo CD detects live drift but leaves the inert marker changed",
              red_observation["application_sync"] == "OutOfSync"
              and red_observation["configmap"] == "runtime-drift"
              and red_observation["mounted_value"] == "runtime-drift"
              and red_observation["self_heal"] is False, red_observation)

    lab.kubectl("patch", "application", APP, "-n", "argocd", "--type=merge",
                "-p", '{"spec":{"syncPolicy":{"automated":{"enabled":true,"selfHeal":true}}}}')
    settle(lambda: marker(lab) == "approved-v1"
           and application(lab)["status"].get("sync", {}).get("status") == "Synced"
           and mounted_marker(lab) == "approved-v1", timeout=180)
    final_state = application(lab)["status"]["sync"]
    final = {"application_sync": final_state["status"],
             "git_commit_matched": final_state.get("revision") == git_revision,
             "configmap": marker(lab), "mounted_value": mounted_marker(lab),
             "kept_original_pod": get_json(lab, "get", "pod", POD)["metadata"]["uid"] == original_pod}
    lab.check("green", "Enabling Argo CD selfHeal restores Git state and the mounted workload marker",
              final["application_sync"] == "Synced" and final["git_commit_matched"]
              and final["configmap"] == "approved-v1"
              and final["mounted_value"] == "approved-v1"
              and final["kept_original_pod"], final)
