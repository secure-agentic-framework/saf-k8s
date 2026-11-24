"""Observe Argo CD status and metrics across an owned manifest-source failure."""
from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import re
import runpy
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
APP = "saf-health-fixture"
GIT_READER = "saf-health-git"
REPO_URL = "http://saf-health-git.saf-test.svc.cluster.local:8080/repo.git"
DEPLOYMENT = "health-fixture"
MISSING_PATH = "missing-saf-source-0606-031"
METRICS_PATH = (
    "/api/v1/namespaces/argocd/services/http:argocd-metrics:8082/proxy/metrics"
)
SCOPE = (
    "One disposable kind cluster with Argo CD v3.6.1 watching a case-owned, "
    "read-only static Git repository in saf-test. The case observes an approved "
    "full Git commit, Argo Application sync and health status, a Ready inert "
    "Deployment, the controller's argocd_app_info metric, a manifest-source "
    "failure, and recovery on the original fixture commit. Coverage is "
    "native Argo CD status and metrics on this fixture. Flux v2.9.0 also reconciles an exact "
    "approved commit over Smart HTTP, exposes a fresh failed request through Kubernetes "
    "API status and kube-state-metrics, and returns to that same approved commit. "
    "The Argo CD verification covers its signed release and SLSA source, running "
    "platform layer chain and a controlled ConfigMap update."
)


def git_fixture(lab, directory):
    work = directory / "work"
    bare = directory / "repo.git"
    lab.command("git", "init", "--template=", "--object-format=sha1", "-b", "main", str(work))
    shutil.copytree(HERE / "source", work / "source")
    lab.command("git", "-C", str(work), "-c", "core.autocrlf=false", "add", "--", "source")
    lab.command("env", "GIT_AUTHOR_DATE=2026-01-01T00:00:00+00:00",
                "GIT_COMMITTER_DATE=2026-01-01T00:00:00+00:00",
                "git", "-C", str(work), "-c", "user.name=SAF fixture",
                "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null",
                "-c", "commit.gpgsign=false", "commit", "-m", "approved fixture state")
    approved_commit = lab.command("git", "-C", str(work), "rev-parse", "HEAD").stdout.strip()
    lab.command("git", "clone", "--bare", str(work), str(bare))
    lab.command("git", "--git-dir", str(bare), "update-server-info")
    return bare, approved_commit


def install_read_only_git_source(lab):
    bare, approved_commit = git_fixture(lab, lab.kubeconfig.parent)
    files = [bare / "HEAD", bare / "info/refs", *sorted((bare / "objects").glob("*/*"))]
    data, projection = {}, []
    for path in files:
        key = f"file-{len(data)}"
        data[key] = b64encode(path.read_bytes()).decode("ascii")
        projection.append({"key": key, "path": f"repo.git/{path.relative_to(bare).as_posix()}"})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": GIT_READER},
                "immutable": True, "binaryData": data})
    git_deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": GIT_READER},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": GIT_READER}},
                 "template": {"metadata": {"labels": {"app": GIT_READER}}, "spec": {
                     "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                         "runAsGroup": 10001,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "volumes": [{"name": "source", "configMap":
                                  {"name": GIT_READER, "items": projection}}],
                     "containers": [{"name": "http", "image": BUSYBOX_IMAGE,
                                     "command": ["httpd", "-f", "-p", "8080", "-h", "/git"],
                                     "volumeMounts": [{"name": "source", "mountPath": "/git",
                                                       "readOnly": True}],
                                     "ports": [{"name": "http", "containerPort": 8080}],
                                     "readinessProbe": {"httpGet": {"path": "/repo.git/HEAD",
                                                                      "port": "http"},
                                                        "initialDelaySeconds": 1,
                                                        "periodSeconds": 2},
                                     "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                   "limits": {"cpu": "100m", "memory": "64Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}],
                 }}}
    }
    lab.create(git_deployment)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": GIT_READER},
                "spec": {"selector": {"app": GIT_READER},
                         "ports": [{"name": "http", "port": 8080, "targetPort": "http"}]}})
    lab.kubectl("rollout", "status", f"deployment/{GIT_READER}", "--timeout=90s", timeout=100)
    return approved_commit


def get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def application(lab):
    return get_json(lab, "-n", "argocd", "get", "application", APP)


def argo_images(lab):
    workloads = get_json(lab, "-n", "argocd", "get", "deployments,statefulsets")["items"]
    selected = {"argocd-application-controller", "argocd-repo-server", "argocd-server"}
    return {workload["metadata"]["name"]:
            [container["image"] for container in workload["spec"]["template"]["spec"]["containers"]]
            for workload in workloads if workload["metadata"]["name"] in selected}


def workload_observation(lab):
    deployment = get_json(lab, "get", "deployment", DEPLOYMENT)
    pods = get_json(lab, "get", "pods", "-l", "app=health-fixture")["items"]
    ready = [pod for pod in pods if pod.get("status", {}).get("phase") == "Running"
             and any(item.get("type") == "Ready" and item.get("status") == "True"
                     for item in pod.get("status", {}).get("conditions", []))]
    return {"available_replicas": deployment.get("status", {}).get("availableReplicas", 0),
            "ready_pod_uids": sorted(pod["metadata"]["uid"] for pod in ready),
            "marker": get_json(lab, "get", "configmap", "health-fixture")["data"]["version"]}


def metric_rows(text):
    rows = []
    for line in text.splitlines():
        if not line.startswith("argocd_app_info{"):
            continue
        labels = dict(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"\\]*)"', line))
        if labels.get("name") == APP and labels.get("namespace") == "argocd":
            value = line.rsplit("}", 1)[-1].strip()
            rows.append({"labels": labels, "value": value})
    return rows


def app_metrics(lab):
    result = lab.kubectl("get", "--raw", METRICS_PATH, timeout=20, allow_failure=True)
    return metric_rows(result.stdout) if result.returncode == 0 else []


def wait_until(lab, predicate, description, timeout=240, interval=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = predicate()
        if observed:
            return observed
        time.sleep(interval)
    lab.block(f"Timed out waiting for {description}")


def settle(predicate, timeout=90, interval=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = predicate()
        if observed:
            return observed
        time.sleep(interval)
    return None


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
    ), "Argo CD workloads to become available", timeout=360)
    images = argo_images(lab)
    required = {"argocd-application-controller", "argocd-repo-server", "argocd-server"}
    lab.check("positive", "The live controller, repository server, and API server use the digest-pinned Argo CD release",
              required.issubset(images) and all(refs == [ARGO_IMAGE] for refs in images.values()), images)

    approved_commit = install_read_only_git_source(lab)
    app_fixture = {"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
                   "metadata": {"name": APP, "namespace": "argocd"},
                   "spec": {"project": "default",
                            "source": {"repoURL": REPO_URL, "targetRevision": approved_commit,
                                       "path": "source"},
                            "destination": {"server": "https://kubernetes.default.svc",
                                            "namespace": "saf-test"},
                            "syncPolicy": {"automated": {"enabled": True, "selfHeal": False}}}}
    lab.kubectl("-n", "argocd", "create", "-f", "-", payload=json.dumps(app_fixture))
    wait_until(lab, lambda: (
        (state := application(lab).get("status", {})).get("sync", {}).get("status") == "Synced"
        and state.get("sync", {}).get("revision") == approved_commit
        and state.get("health", {}).get("status") == "Healthy"
    ), "approved commit to sync and report healthy")
    lab.kubectl("wait", "--for=condition=Available", f"deployment/{DEPLOYMENT}",
                "--timeout=90s", timeout=100)
    baseline_workload = workload_observation(lab)
    baseline_app = application(lab)
    baseline_metrics = settle(lambda: app_metrics(lab), timeout=60)
    baseline = {
        "sync": baseline_app["status"]["sync"]["status"],
        "revision": baseline_app["status"]["sync"]["revision"],
        "health": baseline_app["status"]["health"]["status"],
        "ready_replicas": len(baseline_workload["ready_pod_uids"]),
        "marker": baseline_workload["marker"],
        "argocd_app_info": baseline_metrics,
    }
    lab.check("positive", "Approved Git commit is Synced and Healthy with a Ready workload and native app metric",
              baseline["sync"] == "Synced"
              and baseline["revision"] == approved_commit
              and baseline["health"] == "Healthy"
              and baseline_workload["available_replicas"] == 1
              and len(baseline_workload["ready_pod_uids"]) == 1
              and baseline_workload["marker"] == "approved-v1"
              and bool(baseline_metrics)
              and baseline_metrics[0]["labels"].get("sync_status") == "Synced"
              and baseline_metrics[0]["labels"].get("health_status") == "Healthy",
              baseline)

    # The immutable fixture commit exists, but the owned Application requests
    # a directory absent from that commit.
    lab.kubectl("-n", "argocd", "patch", "application", APP, "--type=merge",
                "-p", json.dumps({"spec": {"source": {"path": MISSING_PATH}}}))

    def failed_source_observation():
        current = application(lab)
        conditions = current.get("status", {}).get("conditions", [])
        errors = [item for item in conditions if item.get("type") == "ComparisonError"]
        sync = current.get("status", {}).get("sync", {}).get("status")
        matching = [row for row in app_metrics(lab) if row["labels"].get("sync_status") == "Unknown"]
        if (errors and any(MISSING_PATH in item.get("message", "") for item in errors)
                and sync == "Unknown" and matching):
            source = current["spec"]["source"]
            return {"requested_path": source["path"], "requested_revision": source["targetRevision"],
                    "condition": "ComparisonError", "missing_path_named": True,
                    "sync": sync, "metrics": matching}
        return None

    failed = settle(failed_source_observation, timeout=180, interval=3)
    failed_workload = workload_observation(lab)
    lab.check("red", "Argo CD surfaces the missing manifest path while leaving the deployed fixture intact",
              bool(failed)
              and failed["requested_path"] == MISSING_PATH
              and failed["requested_revision"] == approved_commit
              and failed_workload == baseline_workload,
              {"failure": failed, "workload_unchanged": failed_workload == baseline_workload})

    lab.kubectl("-n", "argocd", "patch", "application", APP, "--type=merge",
                "-p", json.dumps({"spec": {"source": {"path": "source"}}}))

    def recovered_observation():
        current = application(lab)
        state = current.get("status", {})
        metrics = app_metrics(lab)
        matching = [row for row in metrics if row["labels"].get("sync_status") == "Synced"
                    and row["labels"].get("health_status") == "Healthy"]
        comparison_errors = [item for item in state.get("conditions", [])
                             if item.get("type") == "ComparisonError"]
        if (state.get("sync", {}).get("status") == "Synced"
                and state.get("sync", {}).get("revision") == approved_commit
                and state.get("health", {}).get("status") == "Healthy"
                and not comparison_errors
                and matching):
            return {"sync": state["sync"]["status"], "revision": state["sync"]["revision"],
                    "health": state["health"]["status"], "comparison_error_cleared": True,
                    "metrics": matching}
        return None

    recovered = settle(recovered_observation, timeout=240, interval=3)
    recovered_workload = workload_observation(lab)
    lab.check("green", "Restoring the manifest path clears the source error and restores native status and metrics",
              bool(recovered)
              and recovered_workload == baseline_workload
              and recovered["revision"] == approved_commit,
              {"recovery": recovered, "workload_unchanged": recovered_workload == baseline_workload,
               "approved_commit": approved_commit})

    integrity = runpy.run_path(str(HERE / "integrity" / "case.py"))
    integrity["run"](lab)

    flux = runpy.run_path(str(HERE / "flux" / "case.py"))
    flux["run"](lab)
