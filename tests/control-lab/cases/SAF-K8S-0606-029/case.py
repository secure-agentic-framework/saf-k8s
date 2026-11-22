"""Verify retained GitOps package-version and artifact-identity records."""
from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import time

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
ARGO_RELEASE = "v3.6.1"
ARGO_INSTALL = (
    "https://raw.githubusercontent.com/argoproj/argo-cd/"
    f"{ARGO_RELEASE}/manifests/install.yaml"
)
ARGO_INSTALL_SHA256 = "7be23ca7d9ca3d3074dee8332f1ca92a933b990cee7c9cf22cf3843ee8c2913e"
ARGO_TAG = f"quay.io/argoproj/argocd:{ARGO_RELEASE}"
ARGO_IMAGE = f"{ARGO_TAG}@sha256:296e3d74f449b2ce45265613fcb68c18ed7366488360c8ea32f5f2a93d2e5c54"
APP = "saf-package-fixture"
DEPLOYMENT = "release-fixture"
GIT_READER = "saf-package-git"
REPO_URL = "http://saf-package-git.saf-test.svc.cluster.local:8080/repo.git"
RELEASES = (
    {"version": "1.0.0", "chart_fixture": "chart-v1", "record": "saf-release-v1"},
    {"version": "1.1.0", "chart_fixture": "chart-v2", "record": "saf-release-v2"},
)
SCOPE = (
    "One disposable kind cluster and saf-test namespace; Argo CD v3.6.1 renders two "
    "valid Helm v2 charts (1.0.0 and 1.1.0) from a case-owned, read-only Git source. "
    "The case observes the tagged Argo CD controller, resolved Git commit, Deployment, "
    "and Ready Pod, then compares those observations with independent immutable release "
    "records containing chart version, Git chart-tree identity, runtime image digest, "
    "cluster, and namespace. The fixture covers source Helm charts rendered by Argo CD."
)


def git_fixture(lab, directory):
    work = directory / "work"
    bare = directory / "repo.git"
    lab.command("git", "init", "--template=", "--object-format=sha1", "--initial-branch=main", str(work))
    shutil.copytree(FIXTURES / RELEASES[0]["chart_fixture"], work / "chart")
    commits = []
    for index, release in enumerate(RELEASES, start=1):
        if index == 2:
            shutil.rmtree(work / "chart")
            shutil.copytree(FIXTURES / release["chart_fixture"], work / "chart")
        lab.command("git", "-C", str(work), "-c", "core.autocrlf=false", "add", "--", "chart")
        stamp = f"2026-01-0{index}T00:00:00+00:00"
        lab.command("env", f"GIT_AUTHOR_DATE={stamp}", f"GIT_COMMITTER_DATE={stamp}",
                    "git", "-C", str(work), "-c", "user.name=SAF fixture",
                    "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null",
                    "-c", "commit.gpgsign=false", "commit", "-m",
                    f"case-owned chart {release['version']}")
        commit = lab.command("git", "-C", str(work), "rev-parse", "HEAD").stdout.strip()
        tree = lab.command("git", "-C", str(work), "rev-parse", f"{commit}:chart").stdout.strip()
        commits.append({**release, "commit": commit, "tree_oid": tree})
    lab.command("git", "clone", "--bare", str(work), str(bare))
    lab.command("git", "--git-dir", str(bare), "update-server-info")
    return bare, commits


def install_read_only_git_source(lab):
    bare, commits = git_fixture(lab, lab.kubeconfig.parent)
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
                        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                    }],
                },
            },
        },
    }
    lab.create(git_deployment)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": GIT_READER},
                "spec": {"selector": {"app": GIT_READER},
                         "ports": [{"name": "http", "port": 8080, "targetPort": "http"}]}})
    lab.kubectl("rollout", "status", f"deployment/{GIT_READER}", "--timeout=90s", timeout=100)
    return commits


def get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def argo_images(lab):
    workloads = get_json(lab, "-n", "argocd", "get", "deployments,statefulsets")["items"]
    images = {}
    for workload in workloads:
        name = workload["metadata"]["name"]
        if name in {"argocd-application-controller", "argocd-repo-server", "argocd-server"}:
            images[name] = [container["image"]
                            for container in workload["spec"]["template"]["spec"]["containers"]]
    return images


def application(lab):
    return get_json(lab, "-n", "argocd", "get", "application", APP)


def observed_release(lab):
    app = application(lab)
    response = lab.kubectl("get", "deployment", DEPLOYMENT, "--ignore-not-found", "-o", "json")
    if not response.stdout.strip():
        return {}
    deployment = json.loads(response.stdout)
    template = deployment["spec"]["template"]
    labels = template["metadata"].get("labels", {})
    containers = template["spec"]["containers"]
    env = {entry["name"]: entry["value"] for entry in containers[0].get("env", [])}
    pods = get_json(lab, "get", "pods", "-l", "app.kubernetes.io/name=release-fixture")["items"]
    ready_pods = [pod for pod in pods if pod.get("status", {}).get("phase") == "Running"
                  and any(condition.get("type") == "Ready" and condition.get("status") == "True"
                          for condition in pod.get("status", {}).get("conditions", []))]
    ready = []
    for pod in ready_pods:
        pod_containers = pod["spec"]["containers"]
        pod_env = {entry["name"]: entry["value"] for entry in pod_containers[0].get("env", [])}
        status = next((item for item in pod["status"].get("containerStatuses", [])
                       if item["name"] == "fixture"), {})
        digest = re.search(r"sha256:[0-9a-f]{64}$", status.get("imageID", ""))
        ready.append({"version": pod_env.get("PACKAGE_VERSION"),
                      "image": pod_containers[0]["image"],
                      "runtime_digest": digest[0] if digest else None})
    return {
        "application_sync": app.get("status", {}).get("sync", {}).get("status"),
        "application_revision": app.get("status", {}).get("sync", {}).get("revision"),
        "chart_label": labels.get("helm.sh/chart"),
        "app_version_label": labels.get("app.kubernetes.io/version"),
        "package_version_env": env.get("PACKAGE_VERSION"),
        "available_replicas": deployment.get("status", {}).get("availableReplicas", 0),
        "ready_pods": ready,
    }


def wait_until(lab, predicate, description, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = predicate()
        if observed:
            return observed
        time.sleep(3)
    lab.block(f"Timed out waiting for {description}")


def wait_for_release(lab, commit, version):
    def deployed():
        state = observed_release(lab)
        if (state.get("application_sync") == "Synced"
                and state["application_revision"] == commit
                and state["chart_label"] == f"release-fixture-{version}"
                and state["app_version_label"] == version
                and state["package_version_env"] == version
                and state["available_replicas"] == 1
                and len(state["ready_pods"]) == 1
                and state["ready_pods"][0]["version"] == version
                and state["ready_pods"][0]["image"] == BUSYBOX_IMAGE
                and state["ready_pods"][0]["runtime_digest"]):
            return state
        return None
    return wait_until(lab, deployed, f"Argo CD and the Ready workload to use chart {version}")


def release_record(lab, release, live):
    return {
        "package": {"name": "release-fixture", "type": "helm-chart",
                    "version": release["version"]},
        "artifact": {"identity_type": "git-chart-tree-object",
                     "repository": REPO_URL, "path": "chart",
                     "git_commit": release["commit"],
                     "git_tree_oid": release["tree_oid"]},
        "workload_image": live["ready_pods"][0],
        "environment": {"cluster": lab.cluster, "namespace": "saf-test"},
    }


def record_configmap(lab, release, record):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": release["record"],
                             "labels": {"saf.example/release-fixture": release["version"]}},
                "immutable": True,
                "data": {"release.json": json.dumps(record, sort_keys=True)}})
    return get_json(lab, "get", "configmap", release["record"])


def read_record(lab, name):
    result = lab.kubectl("get", "configmap", name, "--ignore-not-found", "-o", "json")
    return json.loads(result.stdout) if result.stdout.strip() else None


def replay_observation(record):
    # The full record is saved locally with its unique cluster name.
    return {**record, "environment": {"namespace": record["environment"]["namespace"]}}


def retain_local_record(lab, release_records):
    evidence_file = lab.evidence / "release-records.json"
    evidence_file.write_text(json.dumps(release_records, indent=2, sort_keys=True) + "\n")


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
    lab.check("positive", "The live Argo CD controller stack uses the digest-pinned v3.6.1 release",
              required.issubset(images) and all(refs == [ARGO_IMAGE] for refs in images.values()), images)

    releases = install_read_only_git_source(lab)
    app = {"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
           "metadata": {"name": APP, "namespace": "argocd"},
           "spec": {"project": "default",
                    "source": {"repoURL": REPO_URL, "targetRevision": releases[0]["commit"],
                               "path": "chart"},
                    "destination": {"server": "https://kubernetes.default.svc", "namespace": "saf-test"},
                    "syncPolicy": {"automated": {"enabled": True, "selfHeal": False}}}}
    lab.kubectl("-n", "argocd", "create", "-f", "-", payload=json.dumps(app))
    live_v1 = wait_for_release(lab, releases[0]["commit"], releases[0]["version"])
    lab.check("positive", "The pinned Argo CD application rendered chart 1.0.0 into a Ready workload",
              live_v1["application_revision"] == releases[0]["commit"]
              and live_v1["chart_label"] == "release-fixture-1.0.0"
              and live_v1["package_version_env"] == "1.0.0"
              and live_v1["ready_pods"][0]["version"] == "1.0.0", live_v1)

    missing_v1 = read_record(lab, releases[0]["record"])
    helm_records = lab.kubectl("get", "secrets", "-l", "owner=helm", "-o", "name").stdout.splitlines()
    lab.check("red", "Argo CD renders the live chart with neither a fixture record nor Helm release storage",
              missing_v1 is None and not helm_records and live_v1["package_version_env"] == "1.0.0"
              and live_v1["application_revision"] == releases[0]["commit"],
              {"deployed": live_v1, "release_record": missing_v1, "helm_release_secrets": helm_records})

    records = []
    first_record = release_record(lab, releases[0], live_v1)
    first_cm = record_configmap(lab, releases[0], first_record)
    records.append(first_record)
    retain_local_record(lab, records)
    first_observed = json.loads(first_cm["data"]["release.json"])
    lab.check("positive", "The retained 1.0.0 record binds package version, chart tree, and environment",
              first_cm["immutable"] is True and first_observed == first_record
              and first_observed["package"]["version"] == live_v1["package_version_env"]
              and first_observed["artifact"]["git_commit"] == live_v1["application_revision"]
              and first_observed["environment"] == {"cluster": lab.cluster, "namespace": "saf-test"},
              {"record": replay_observation(first_observed), "deployed": live_v1})

    lab.kubectl("-n", "argocd", "patch", "application", APP, "--type=merge",
                "-p", json.dumps({"spec": {"source": {"targetRevision": releases[1]["commit"]}}}))
    live_v2 = wait_for_release(lab, releases[1]["commit"], releases[1]["version"])
    stale_v2 = read_record(lab, releases[1]["record"])
    old_record = read_record(lab, releases[0]["record"])
    lab.check("red", "After promotion, the old release record does not identify deployed chart 1.1.0",
              stale_v2 is None and old_record is not None
              and json.loads(old_record["data"]["release.json"])["package"]["version"] == "1.0.0"
              and live_v2["package_version_env"] == "1.1.0"
              and live_v2["application_revision"] == releases[1]["commit"],
              {"deployed": live_v2, "old_record_present": old_record is not None,
               "new_record": stale_v2})

    second_record = release_record(lab, releases[1], live_v2)
    second_cm = record_configmap(lab, releases[1], second_record)
    records.append(second_record)
    retain_local_record(lab, records)
    retained = [json.loads(read_record(lab, release["record"])["data"]["release.json"])
                for release in releases]
    lab.check("green", "Separate immutable records retain both deployed versions and exact chart identities",
              second_cm["immutable"] is True
              and len(retained) == 2
              and [item["package"]["version"] for item in retained] == ["1.0.0", "1.1.0"]
              and [item["artifact"]["git_commit"] for item in retained]
                  == [release["commit"] for release in releases]
              and [item["artifact"]["git_tree_oid"] for item in retained]
                  == [release["tree_oid"] for release in releases]
              and all(item["environment"] == {"cluster": lab.cluster, "namespace": "saf-test"}
                      for item in retained)
              and retained == records
              and live_v2["package_version_env"] == retained[-1]["package"]["version"]
              and live_v2["application_revision"] == retained[-1]["artifact"]["git_commit"],
              {"records": [replay_observation(record) for record in retained], "deployed": live_v2})

    modified = lab.kubectl("patch", "configmap", releases[0]["record"], "--type=merge",
                           "-p", json.dumps({"data": {"release.json": "{}"}}), allow_failure=True)
    immutable = modified.returncode != 0 and "field is immutable" in modified.stderr
    still_retained = json.loads(read_record(lab, releases[0]["record"])["data"]["release.json"])
    lab.check("green", "The Kubernetes API refuses a data change to the retained prior release record",
              immutable and still_retained == first_record,
              {"immutable_data_rejected": immutable, "prior_record_preserved": still_retained == first_record})
