"""Observe an approved Flux revision, fresh native failure, and recovery."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import runpy
import shutil
import time

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
FIXTURE = "flux-health-fixture"
MISSING_PATH = "./missing-saf-flux-source"
RECONCILE = "reconcile.fluxcd.io/requestedAt"
METRICS = "/api/v1/namespaces/saf-test/services/http:saf-flux-state:8080/proxy/metrics"
METRIC = "gotk_resource_info"


def approved_repo(lab):
    work = lab.kubeconfig.with_name("flux-approved")
    bare = lab.kubeconfig.with_name("flux-approved.git")
    lab.command("git", "init", "--template=", "--object-format=sha1", "-b", "main", str(work))
    shutil.copytree(HERE / "source", work / "source")
    lab.command("git", "-C", str(work), "-c", "core.autocrlf=false", "add", "--", "source")
    lab.command("env", "GIT_AUTHOR_DATE=2026-01-01T00:00:00+00:00",
                "GIT_COMMITTER_DATE=2026-01-01T00:00:00+00:00",
                "git", "-C", str(work), "-c", "user.name=SAF fixture",
                "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                "-c", "core.hooksPath=/dev/null", "commit", "-m", "approved Flux fixture")
    revision = lab.command("git", "-C", str(work), "rev-parse", "HEAD").stdout.strip()
    lab.command("git", "clone", "--bare", "--template=", str(work), str(bare))
    # The ConfigMap projection cannot preserve an empty refs directory.
    branch = bare / "refs" / "heads" / "main"
    branch.parent.mkdir(parents=True, exist_ok=True)
    branch.write_text(revision + "\n")
    (bare / "git-daemon-export-ok").touch()
    lab.command("git", "--git-dir", str(bare), "config", "http.receivepack", "false")
    return bare, revision


def resource(lab, kind, name):
    return json.loads(lab.kubectl("get", kind, name, "-o", "json").stdout)


def metric_for(lab, *, ready, reason, revision, request):
    response = lab.kubectl("get", "--raw", METRICS, allow_failure=True, timeout=15)
    if response.returncode:
        return None
    expected = {"name": FIXTURE, "exported_namespace": NAMESPACE, "ready": ready,
                "reason": reason, "revision": revision, "request": request}
    for line in response.stdout.splitlines():
        if not line.startswith(f"{METRIC}{{") or line.rsplit(" ", 1)[-1] != "1":
            continue
        labels = dict(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"', line))
        if all(labels.get(key) == value for key, value in expected.items()):
            return expected
    return None


def observe(lab, *, ready, reason, commit, request, generation, started_at):
    item = resource(lab, "kustomization", FIXTURE)
    source = resource(lab, "gitrepository", FIXTURE)
    status = item.get("status", {})
    condition = next((entry for entry in status.get("conditions", [])
                      if entry["type"] == "Ready"), {})
    source_ready = any(entry.get("type") == "Ready" and entry.get("status") == "True"
                       for entry in source.get("status", {}).get("conditions", []))
    revision = status.get("lastAppliedRevision", "")
    requested_commit = source["spec"]["ref"].get("commit", "")
    resolved = source.get("status", {}).get("artifact", {}).get("revision", "")
    transition = condition.get("lastTransitionTime")
    if (not source_ready or requested_commit != commit or resolved.rsplit("@", 1)[-1] != f"sha1:{commit}"
            or revision != resolved or item["metadata"]["generation"] != generation
            or condition.get("status") != ready or condition.get("reason") != reason
            or status.get("lastHandledReconcileAt") != request or not transition
            or datetime.fromisoformat(transition.replace("Z", "+00:00")) < started_at):
        return None
    metric = metric_for(lab, ready=ready, reason=reason, revision=revision, request=request)
    if metric is None:
        return None
    return {"object": item, "source": source, "metric": metric}


def await_observation(lab, description, **expected):
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        observed = observe(lab, **expected)
        if observed:
            return observed
        time.sleep(2)
    observed = resource(lab, "kustomization", FIXTURE)
    lab.block(f"Timed out waiting for {description}: {observed.get('status', {})}")


def configure(lab, request, path):
    patch = {"metadata": {"annotations": {RECONCILE: request}}, "spec": {"path": path}}
    response = lab.kubectl("patch", "kustomization", FIXTURE, "--type=merge",
                           "-p", json.dumps(patch), "-o", "json")
    return json.loads(response.stdout)["metadata"]["generation"]


def snapshot(lab):
    deployment = resource(lab, "deployment", FIXTURE)
    config = resource(lab, "configmap", FIXTURE)
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"app={FIXTURE}", "-o", "json").stdout)
    ready_pods = sorted(pod["metadata"]["uid"] for pod in pods["items"]
                        if any(c["type"] == "Ready" and c["status"] == "True"
                               for c in pod.get("status", {}).get("conditions", [])))
    return {"uid": deployment["metadata"]["uid"], "ready_pods": ready_pods,
            "available_replicas": deployment["status"].get("availableReplicas", 0),
            "marker": config.get("data", {}).get("version")}


def disable_unused_notifications(lab):
    # The reused fixture only installs source and kustomize controllers.
    controllers = ("source-controller", "kustomize-controller")
    for name in controllers:
        result = lab.kubectl("-n", "flux-system", "get", "deployment", name, "-o", "json")
        args = json.loads(result.stdout)["spec"]["template"]["spec"]["containers"][0]["args"]
        active = [arg for arg in args if not arg.startswith("--events-addr=")]
        if active != args:
            patch = [{"op": "replace", "path": "/spec/template/spec/containers/0/args", "value": active}]
            lab.kubectl("-n", "flux-system", "patch", "deployment", name,
                        "--type=json", "-p", json.dumps(patch))
    for name in controllers:
        lab.kubectl("-n", "flux-system", "rollout", "status", f"deployment/{name}",
                    "--timeout=120s", timeout=130)


def run(lab):
    fixture = runpy.run_path(str(HERE.parents[1] / "SAF-K8S-0606-028" / "case.py"))
    fixture["install_flux"](lab)
    disable_unused_notifications(lab)
    bare, commit = approved_repo(lab)
    fixture["install_git_server"](lab, {"baseline-unsigned": bare})
    lab.kubectl("apply", "-f", str(HERE / "metrics.yaml"))
    lab.kubectl("rollout", "status", "deployment/saf-flux-state", "--timeout=90s", timeout=100)
    url = f"{fixture['GIT_BASE']}/baseline-unsigned.git"
    metadata = {"namespace": NAMESPACE, "name": FIXTURE}
    lab.create({"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository",
                "metadata": metadata,
                "spec": {"interval": "1m", "url": url, "ref": {"commit": commit}}})
    started_at = datetime.now(timezone.utc).replace(microsecond=0)
    applied = lab.create({
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
        "metadata": {**metadata, "annotations": {RECONCILE: "approved"}},
        "spec": {"interval": "1m", "retryInterval": "10s", "path": "./source", "prune": True,
                 "targetNamespace": NAMESPACE, "sourceRef": {"kind": "GitRepository", "name": FIXTURE}},
    })
    baseline = await_observation(lab, "the approved Flux revision and metric",
                                 ready="True", reason="ReconciliationSucceeded", commit=commit,
                                 request="approved", generation=applied["metadata"]["generation"],
                                 started_at=started_at)
    lab.kubectl("rollout", "status", f"deployment/{FIXTURE}", "--timeout=90s", timeout=100)
    before = snapshot(lab)
    lab.check("positive", "Flux applied the exact approved Git commit and exported that revision and Ready status",
              before["available_replicas"] == 1 and before["marker"] == "approved-v1"
              and len(before["ready_pods"]) == 1,
              {"workload_available": before["available_replicas"] == 1,
               "git_commit": commit, "metric": baseline["metric"]})

    started_at = datetime.now(timezone.utc).replace(microsecond=0)
    generation = configure(lab, "owned-path-failure", MISSING_PATH)
    failure = await_observation(lab, "a fresh failure for the exact Flux request",
                                ready="False", reason="ArtifactFailed", commit=commit,
                                request="owned-path-failure", generation=generation,
                                started_at=started_at)
    failure_reason = next(c for c in failure["object"]["status"]["conditions"] if c["type"] == "Ready")
    unchanged = snapshot(lab) == before
    lab.check("red", "Flux exports the fresh native path failure and preserves the previously applied workload",
              unchanged and "missing-saf-flux-source" in failure_reason.get("message", "")
              and generation > applied["metadata"]["generation"],
              {"available_workload_unchanged": unchanged, "metric": failure["metric"]})

    started_at = datetime.now(timezone.utc).replace(microsecond=0)
    recovered_generation = configure(lab, "approved-restored", "./source")
    recovered = await_observation(lab, "recovery to the approved revision",
                                  ready="True", reason="ReconciliationSucceeded", commit=commit,
                                  request="approved-restored", generation=recovered_generation,
                                  started_at=started_at)
    unchanged = snapshot(lab) == before
    lab.check("green", "Flux restores Ready and the metric binds recovery to the same exact Git revision",
              unchanged and recovered_generation > generation
              and recovered["object"]["status"]["observedGeneration"] == recovered_generation,
              {"available_workload_unchanged": unchanged, "metric": recovered["metric"]})

    (lab.evidence / "flux-reconciliation.json").write_text(json.dumps(
        {"approved": baseline, "failure": failure, "recovery": recovered}, indent=2) + "\n")
