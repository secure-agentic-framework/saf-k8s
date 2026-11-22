"""Exercise revision, rendered configuration, and real rollout traceability."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
APP = "saf-package-fixture"
RECONSTRUCTION = "saf-trace-reconstruction"
APPLIED = "kubectl.kubernetes.io/last-applied-configuration"
SCOPE = (
    "One disposable Kind cluster and one pinned Argo CD application with two case-owned Git "
    "chart revisions. The case links each sync to the applied Deployment manifest and a "
    "Kubernetes rollout event, retains separate records, and reconstructs the older "
    "Deployment in another namespace. Coverage is one owned Deployment and renderer path."
)


def digest(data):
    return sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def copy_renderer_fixture():
    source = HERE.parent / "SAF-K8S-0606-029" / "case.py"
    spec = importlib.util.spec_from_file_location("traceability_release_source", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install_argo(lab, renderer):
    manifest = lab.kubeconfig.with_name("trace-argo-install.yaml")
    lab.command("curl", "-fsSL", "--max-time", "60", renderer.ARGO_INSTALL, "-o", str(manifest), timeout=70)
    if sha256(manifest.read_bytes()).hexdigest() != renderer.ARGO_INSTALL_SHA256:
        lab.block("Pinned Argo CD manifest did not match its digest")
    manifest.write_text(manifest.read_text().replace(f"image: {renderer.ARGO_TAG}", f"image: {renderer.ARGO_IMAGE}"))
    lab.kubectl("create", "namespace", "argocd")
    lab.kubectl("-n", "argocd", "apply", "--server-side", "-f", str(manifest), timeout=180)
    renderer.wait_until(lab, lambda: all(
        (get_json(lab, "-n", "argocd", "get", kind, name)["status"].get("readyReplicas") or 0) >= 1
        for kind, name in (("statefulset", "argocd-application-controller"), ("deployment", "argocd-repo-server"))
    ), "Argo CD fixture controllers to be ready", timeout=240)


def capture_rollout(lab, renderer, release):
    rendered = {}
    def ready_observation():
        application = renderer.application(lab)
        history = [event for event in application["status"].get("history", [])
                   if event.get("revision") == release["commit"] and event.get("deployedAt")]
        if len(history) != 1:
            return False
        deployment = get_json(lab, "get", "deployment", renderer.DEPLOYMENT)
        serialized = deployment["metadata"].get("annotations", {}).get(APPLIED)
        if not serialized:
            return False
        manifest = json.loads(serialized)
        owner = deployment["metadata"]["uid"]
        revision = deployment["metadata"]["annotations"].get("deployment.kubernetes.io/revision")
        replica_sets = get_json(lab, "get", "replicasets", "-l", "app.kubernetes.io/name=release-fixture")["items"]
        match = [item for item in replica_sets
                 if any(ref.get("uid") == owner and ref.get("controller")
                        for ref in item["metadata"].get("ownerReferences", []))
                 and item["metadata"].get("annotations", {}).get("deployment.kubernetes.io/revision") == revision
                 and item.get("status", {}).get("readyReplicas") == 1]
        if len(match) != 1:
            return False
        rs = match[0]["metadata"]["name"]
        events = get_json(lab, "get", "events", "--field-selector", f"involvedObject.uid={owner}")["items"]
        event = next((item for item in events if item.get("reason") == "ScalingReplicaSet"
                      and rs in item.get("message", "") and item["message"].startswith("Scaled up")), None)
        if event is None:
            return False
        rendered.update(manifest=manifest, manifest_sha256=digest(manifest),
                        source_revision=release["commit"], argo_deployment_history=history[0],
                        deployment_revision=revision,
                        replica_set={"name": rs, "uid": match[0]["metadata"]["uid"]}, event=event)
        return True
    renderer.wait_until(lab, ready_observation, f"observing applied manifest and rollout for {release['version']}", timeout=60)
    return rendered


def retain(lab, name, record):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "immutable": True, "data": {"record.json": json.dumps(record, sort_keys=True)}})


def read(lab, name):
    row = get_json(lab, "get", "configmap", name)
    return row["immutable"], json.loads(row["data"]["record.json"])


def pod_version(manifest):
    return next(entry["value"] for entry in manifest["spec"]["template"]["spec"]["containers"][0]["env"]
                if entry["name"] == "PACKAGE_VERSION")


def run(lab):
    renderer = copy_renderer_fixture()
    install_argo(lab, renderer)
    first, second = renderer.install_read_only_git_source(lab)
    application = {
        "apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
        "metadata": {"name": APP, "namespace": "argocd"},
        "spec": {"project": "default",
                 "source": {"repoURL": renderer.REPO_URL, "targetRevision": first["commit"], "path": "chart"},
                 "destination": {"server": "https://kubernetes.default.svc", "namespace": "saf-test"},
                 "syncPolicy": {"automated": {"enabled": True}}}
    }
    lab.kubectl("-n", "argocd", "create", "-f", "-", payload=json.dumps(application))
    renderer.wait_for_release(lab, first["commit"], first["version"])
    missing = not lab.kubectl("get", "configmap", "trace-r1", "--ignore-not-found", "-o", "name").stdout.strip()
    lab.check("red", "The live first deployment exists before the linked traceability record",
              missing, {"live_revision": first["commit"], "record_absent": missing})
    old = capture_rollout(lab, renderer, first)
    retain(lab, "trace-r1", old)

    lab.kubectl("-n", "argocd", "patch", "application", APP, "--type=merge",
                "-p", json.dumps({"spec": {"source": {"targetRevision": second["commit"]}}}))
    renderer.wait_for_release(lab, second["commit"], second["version"])
    new = capture_rollout(lab, renderer, second)
    retain(lab, "trace-r2", new)
    retained = [read(lab, "trace-r1"), read(lab, "trace-r2")]
    records = [record for _, record in retained]
    exact = all(immutable and record == original and digest(record["manifest"]) == record["manifest_sha256"]
                for (immutable, record), original in zip(retained, (old, new)))
    source_versions = [pod_version(record["manifest"]) for record in records]
    linked = all(record["source_revision"] == record["argo_deployment_history"]["revision"] == release["commit"]
                 for record, release in zip(records, (first, second)))
    distinct = (old["deployment_revision"] != new["deployment_revision"]
                and old["replica_set"]["uid"] != new["replica_set"]["uid"]
                and old["manifest_sha256"] != new["manifest_sha256"])
    lab.check("green", "Two retained records link exact rendered deployments to Git, Argo CD, and distinct Kubernetes rollouts",
              exact and linked and distinct and source_versions == [first["version"], second["version"]],
              {"records_exact": exact, "git_revisions_match": linked, "rollouts_distinct": distinct,
               "rendered_versions": source_versions, "commits": [r["source_revision"] for r in records]})
    (lab.evidence / "retained-rollouts.json").write_text(json.dumps(records, indent=2) + "\n")

    lab.kubectl("create", "namespace", RECONSTRUCTION)
    manifest = records[0]["manifest"]
    original_spec = manifest["spec"]
    manifest["metadata"]["namespace"] = RECONSTRUCTION
    manifest["metadata"].get("annotations", {}).pop("argocd.argoproj.io/tracking-id", None)
    lab.kubectl("-n", RECONSTRUCTION, "apply", "-f", "-", payload=json.dumps(manifest))
    lab.kubectl("-n", RECONSTRUCTION, "rollout", "status", f"deployment/{renderer.DEPLOYMENT}",
                "--timeout=80s", timeout=90)
    rebuilt = get_json(lab, "-n", RECONSTRUCTION, "get", "deployment", renderer.DEPLOYMENT)
    applied = json.loads(rebuilt["metadata"]["annotations"][APPLIED])
    actual = renderer.observed_release(lab)
    rebuilt_exact = applied["spec"] == original_spec and pod_version(applied) == first["version"]
    current_unchanged = (actual["application_revision"] == second["commit"]
                         and actual["package_version_env"] == second["version"])
    lab.check("positive", "The retained first manifest reconstructs a Ready Deployment while the current revision remains active",
              rebuilt_exact and current_unchanged and rebuilt["status"].get("readyReplicas") == 1,
              {"reconstructed_spec_matches": rebuilt_exact, "current_revision_preserved": current_unchanged,
               "archived_version": first["version"], "current_version": second["version"]})
