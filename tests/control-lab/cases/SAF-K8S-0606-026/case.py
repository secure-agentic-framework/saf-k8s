"""Assess real Git snapshots offline and gate a Kubernetes release marker."""
import base64
from hashlib import sha256
import json
from pathlib import Path
import time

from fixtures import container

HERE = Path(__file__).resolve().parent
GIT_IMAGE = "docker.gitea.com/gitea:1.23.8-rootless"
SCORECARD_IMAGE = "ghcr.io/ossf/scorecard:v5.6.0"
GIT_DIGEST = {
    "amd64": "78d6946032b183d5f2c438c6b56fac373050dfd8c5415d356dd605e43086dfac",
    "arm64": "c8757af5d82b86330c33dad04849dac0dd32cd81683057fa04b7c14ad987800f",
}
SCORECARD_DIGEST = {
    "amd64": "03a0d4c85e99e2dc9841f3519cae74aefbc8ce3131e2a6d2c725c87866e0142f",
    "arm64": "5aa0b1d71f365d24f5625130f46145b1170e1a68d882d9884698520fe286f0ca",
}
SCORECARD_COMMIT = "61e84743356275f6ffca23b1b2f2cb945e19eb96"
SCOPE = (
    "Two exact commits of an inert fixture repository on Kubernetes v1.36.1. "
    "A pinned OpenSSF Scorecard process assesses Pinned-Dependencies in local mode, "
    "and native Kubernetes admission trusts the independently identified repository and revision. "
    "The workflow is never executed and no hosted SCM sites, accounts, or data are assessed. "
    "The fixture leaves continuous production assessment and hosted branch controls open."
)
REPOSITORY = "fixture-scm"
WORKFLOW = ".github/workflows/build.yml"
MARKER = "saf-release-marker"
POLICY = "saf-scm-posture"
REPORT = "saf-scorecard-results"
DENIAL = "repository revision lacks an acceptable Pinned-Dependencies result"
API = "admissionregistration.k8s.io/v1"


def seed_repository(lab):
    workspace = lab.kubeconfig.parent
    repository = workspace / REPOSITORY
    bundle = workspace / "fixture-scm.bundle"
    workflow = repository / WORKFLOW
    workflow.parent.mkdir(parents=True)

    def git(*args):
        return lab.command(
            "env", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
            "GIT_AUTHOR_NAME=SAF fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid",
            "GIT_COMMITTER_NAME=SAF fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid",
            "GIT_AUTHOR_DATE=2026-01-01T00:00:00+00:00", "GIT_COMMITTER_DATE=2026-01-01T00:00:00+00:00",
            "git", "-C", str(repository), *map(str, args),
        ).stdout.strip()

    git("init", "--template=", "--object-format=sha1", "-b", "main")
    rows = {}
    for variant in ("weak", "strong"):
        content = (HERE / "fixtures" / f"{variant}.yml").read_bytes()
        workflow.write_bytes(content)
        git("add", "--", WORKFLOW)
        git("commit", "-m", f"{variant} inert fixture")
        rows[variant] = {"revision": git("rev-parse", "HEAD"),
                         "workflow_sha256": sha256(content).hexdigest()}
    git("commit", "--allow-empty", "-m", "revision with no assessment")
    unassessed = git("rev-parse", "HEAD")
    git("bundle", "create", bundle, "--all")
    return rows, unassessed, bundle.read_bytes()


def stage_image(lab, digest_reference, name):
    local = f"saf-{name}:{lab.cluster}"
    exists = lab.command("docker", "image", "inspect", digest_reference, "--format", "{{.Id}}",
                         allow_failure=True)
    if exists.returncode:
        lab.command("docker", "pull", digest_reference, timeout=150)
    lab.command("docker", "tag", digest_reference, local)
    try:
        lab.command("kind", "load", "docker-image", "--name", lab.cluster, local, timeout=120)
    finally:
        lab.command("docker", "image", "rm", local)
    return local


def prepare_scan(lab, bundle):
    lab.create(object_spec("v1", "ConfigMap", REPOSITORY, immutable=True, binaryData={
        "source.bundle": base64.b64encode(bundle).decode("ascii"),
    }))
    lab.create(object_spec("networking.k8s.io/v1", "NetworkPolicy", "saf-scorecard-offline", spec={
        "podSelector": {"matchLabels": {"app": "saf-scorecard"}},
        "policyTypes": ["Egress"], "egress": [],
    }))


def scan(lab, variant, source, images, scanner_reference):
    name = f"scorecard-{variant}"
    scratch = {"name": "scratch", "mountPath": "/checkout"}
    mount = {"name": "fixture", "mountPath": "/fixture", "readOnly": True}
    script = '''
git -c init.defaultBranch=main clone --quiet /fixture/source.bundle /checkout/repo
git -C /checkout/repo checkout --quiet --detach "$1"
test -z "$(git -C /checkout/repo status --porcelain)"
printf '%s\n' "$(git -C /checkout/repo rev-parse HEAD)"
sha256sum /checkout/repo/.github/workflows/build.yml | cut -d ' ' -f 1
'''
    git = container("checkout", image=images["git"], imagePullPolicy="Never",
                    command=["/bin/sh", "-ec", script, "checkout", source["revision"]],
                    env=[{"name": "HOME", "value": "/checkout"}], volumeMounts=[mount, scratch])
    scanner = container(
        "scorecard", image=images["scorecard"], imagePullPolicy="Never", command=["/ko-app/v5"],
        args=["--local=/checkout/repo", "--checks=Pinned-Dependencies", "--format=json", "--show-details"],
        volumeMounts=[scratch | {"readOnly": True}, {"name": "tmp", "mountPath": "/tmp"}],
    )
    git["securityContext"]["runAsUser"] = scanner["securityContext"]["runAsUser"] = 65532
    lab.create(object_spec("batch/v1", "Job", name, spec={
        "backoffLimit": 0, "activeDeadlineSeconds": 110, "template": {
            "metadata": {"labels": {"app": "saf-scorecard"}},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                         "runAsGroup": 65532, "fsGroup": 65532}, "initContainers": [git],
                     "containers": [scanner], "volumes": [
                         {"name": "fixture", "configMap": {"name": REPOSITORY}},
                         {"name": "scratch", "emptyDir": {}}, {"name": "tmp", "emptyDir": {}},
                     ]},
        },
    }))
    result = lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=115s",
                         timeout=120, allow_failure=True)
    if result.returncode:
        lab.kubectl("get", "events", "--sort-by=.lastTimestamp", allow_failure=True)
        lab.kubectl("describe", f"job/{name}", allow_failure=True)
        lab.kubectl("describe", "pods", "-l", f"job-name={name}", allow_failure=True)
        lab.kubectl("logs", f"job/{name}", "--all-containers", allow_failure=True)
        lab.block(f"Scorecard fixture Job {name} did not complete")
    checkout = lab.kubectl("logs", f"job/{name}", "-c", "checkout").stdout.splitlines()
    raw_report = lab.kubectl("logs", f"job/{name}", "-c", "scorecard").stdout
    report = json.loads(raw_report)
    scorecard = report["scorecard"]
    check, = report["checks"]
    observation = {"repository": REPOSITORY, "revision": source["revision"],
                   "workflow_sha256": source["workflow_sha256"], "score": check["score"],
                   "scorecard_commit": scorecard["commit"], "check": check["name"],
                   "checkout_matches": checkout == [source["revision"], source["workflow_sha256"]]}
    (lab.evidence / f"{variant}-scorecard.raw.json").write_text(raw_report)
    (lab.evidence / f"{variant}-checkout.json").write_text(json.dumps({
        "requested": source, "observed": checkout, "scanner": scanner_reference,
    }, indent=2) + "\n")
    expected_score = {"weak": 0, "strong": 10}[variant]
    lab.check("positive", f"The live pinned Scorecard evaluates the {variant} exact Git snapshot",
              observation["checkout_matches"] and scorecard["version"] == "v5.6.0"
              and scorecard["commit"] == SCORECARD_COMMIT
              and report["repo"]["name"] == "file:///checkout/repo"
              and check["name"] == "Pinned-Dependencies" and check["score"] == expected_score, observation)
    return check["score"]

def object_spec(api, kind, name, **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def write_marker(lab, repository, revision, *, dry_run=False):
    args = ["patch", "configmap", MARKER, "--type=merge", "-o", "json",
            "-p", json.dumps({"data": {"repository": repository, "revision": revision}})]
    if dry_run:
        args.append("--dry-run=server")
    return lab.kubectl(*args, allow_failure=True)


def current_marker(lab):
    return json.loads(lab.kubectl("get", "configmap", MARKER, "-o", "json").stdout)


def install_gate(lab, reports):
    lab.create(object_spec("v1", "ConfigMap", REPORT, immutable=True, data=reports))
    policy = {
        "failurePolicy": "Fail",
        "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
        "matchConstraints": {"resourceRules": [{
            "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
            "resources": ["configmaps"], "scope": "Namespaced",
        }]},
        "matchConditions": [{"name": "release-marker",
                             "expression": f"request.namespace == 'saf-test' && object.metadata.name == '{MARKER}'"}],
        "variables": [{"name": "postureKey",
                       "expression": "object.data['repository'] + '.' + object.data['revision']"}],
        "validations": [{
            "expression": ("has(object.data) && 'repository' in object.data && 'revision' in object.data "
                           "&& has(params.data) && variables.postureKey in params.data "
                           "&& int(params.data[variables.postureKey]) >= 8"),
            "message": DENIAL,
        }],
    }
    lab.create(object_spec(API, "ValidatingAdmissionPolicy", POLICY, spec=policy))
    lab.create(object_spec(API, "ValidatingAdmissionPolicyBinding", POLICY, spec={
        "policyName": POLICY, "validationActions": ["Deny"],
        "paramRef": {"name": REPORT, "namespace": "saf-test", "parameterNotFoundAction": "Deny"},
    }))


def is_policy_denial(result):
    return result.returncode == 1 and POLICY in result.stderr and DENIAL in result.stderr


def run_gate(lab, repository, weak, strong, unassessed, scores):
    seed = {"repository": "unrelated-approved-deployment", "revision": "already-deployed"}
    lab.create(object_spec("v1", "ConfigMap", MARKER, data=seed))
    baseline = write_marker(lab, repository, weak)
    (lab.evidence / "ungated-release.json").write_text(baseline.stdout)
    initial_request = {"repository": repository, "revision": weak}
    lab.check("red", "With no posture gate, the same low-scoring revision updates the live release marker",
              baseline.returncode == 0 and current_marker(lab)["data"] == initial_request,
              {"api_returncode": baseline.returncode, "stored": current_marker(lab)["data"]})
    write_marker(lab, seed["repository"], seed["revision"])
    before = current_marker(lab)
    lab.check("positive", "The existing release marker was restored before policy activation",
              before["data"] == seed, {"stored": before["data"]})
    install_gate(lab, {f"{repository}.{revision}": str(score) for revision, score in scores.items()})

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        probe = write_marker(lab, repository, weak, dry_run=True)
        if is_policy_denial(probe):
            break
        time.sleep(0.4)
    else:
        lab.block("The expected native admission decision did not become active")

    for label, source, revision in (
        ("low-score", repository, weak),
        ("missing-revision", repository, unassessed),
        ("wrong-repository", "unassessed-repository", strong),
    ):
        denied = write_marker(lab, source, revision)
        after = current_marker(lab)
        unchanged = after["metadata"]["resourceVersion"] == before["metadata"]["resourceVersion"]
        raw = {"returncode": denied.returncode, "stdout": denied.stdout, "stderr": denied.stderr,
               "before": before, "after": after, "attempted": {"repository": source, "revision": revision}}
        (lab.evidence / f"{label}-release-denial.json").write_text(json.dumps(raw, indent=2) + "\n")
        lab.check("green", f"The gate denies {label} and keeps the previous release unchanged",
                  is_policy_denial(denied) and unchanged and after["data"] == seed,
                  {"api_returncode": denied.returncode, "policy_denial": is_policy_denial(denied),
                   "previous_release_unchanged": unchanged and after["data"] == seed})

    approved = write_marker(lab, repository, strong)
    (lab.evidence / "approved-release.json").write_text(approved.stdout)
    expected = {"repository": repository, "revision": strong}
    stored = current_marker(lab)["data"]
    lab.check("positive", "The gate accepts the approved repository and its exact passing revision",
              approved.returncode == 0 and stored == expected,
              {"api_returncode": approved.returncode, "stored": stored})


def run(lab):
    commits, unassessed, bundle = seed_repository(lab)
    prepare_scan(lab, bundle)
    node = f"node/{lab.cluster}-control-plane"
    architecture = lab.kubectl("get", node, "-o", "jsonpath={.status.nodeInfo.architecture}").stdout.strip()
    if architecture not in SCORECARD_DIGEST:
        lab.block(f"No pinned scanner image for node architecture {architecture}")
    git_reference = f"{GIT_IMAGE}@sha256:{GIT_DIGEST[architecture]}"
    scanner_reference = f"{SCORECARD_IMAGE}@sha256:{SCORECARD_DIGEST[architecture]}"
    images = {"git": stage_image(lab, git_reference, "scm-fixture-git"),
              "scorecard": stage_image(lab, scanner_reference, "scm-fixture-scorecard")}
    scores = {source["revision"]: scan(lab, variant, source, images, scanner_reference)
              for variant, source in commits.items()}
    run_gate(lab, REPOSITORY, commits["weak"]["revision"], commits["strong"]["revision"], unassessed, scores)
