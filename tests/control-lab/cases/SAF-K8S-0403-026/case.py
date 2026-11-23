"""Test prevention at three distinct, case-owned publication boundaries."""
import json
import time

SCOPE = (
    "An inert public marker exercises an actual local Git commit hook, an isolated Git "
    "receive hook and native Kubernetes admission at a labeled release fixture boundary. "
    "The lab never publishes externally. Production scanners, protected transitions, "
    "artifact formats, and exception governance need independent evidence."
)
MARKER = "SAF_PUBLIC_SYNTHETIC_SCAN_FIXTURE_0403"
DENIAL = "SAF fixture marker rejected"
POLICY = "saf-fixture-publication-gate"
LABEL = "saf-k8s.example/release-fixture"
BRANCH = "refs/heads/main"
FILENAME = "release-config.txt"
HOOK_SCAN = r'''
    if git grep --quiet --fixed-strings "$@"; then
        printf '%s\n' 'SAF fixture marker rejected' >&2
        exit 1
    else
        status=$?
        if [ "$status" -ne 1 ]; then exit "$status"; fi
    fi
'''


def git(lab, root, *args, allow_failure=False):
    return lab.command(
        "env", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_AUTHOR_NAME=SAF fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid",
        "GIT_COMMITTER_NAME=SAF fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid",
        "git", "-C", str(root), *map(str, args), allow_failure=allow_failure,
    )


def hook(root, name, script):
    folder = root / "hooks"
    folder.mkdir(exist_ok=True)
    target = folder / name
    target.write_text(f"#!/bin/sh\nset -eu\nmarker={MARKER}\n" + script)
    target.chmod(0o700)


def visible_ref(lab, root):
    return git(lab, root, "rev-parse", BRANCH).stdout.strip()


def stage(lab, root, value):
    (root / FILENAME).write_text(value + "\n")
    git(lab, root, "add", "--", FILENAME)


def artifact(lab, name, value, dry_run=False):
    return lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                       "metadata": {"name": name, "labels": {LABEL: "governed"}},
                       "data": {"rendered": value}}, dry_run=dry_run, allow_failure=True)


def admission(lab):
    api = "admissionregistration.k8s.io/v1"
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [
                    {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                     "resources": ["configmaps"]}]}, "validations": [
                    {"expression": f"!has(object.data) || object.data.all(k, !object.data[k].contains('{MARKER}'))",
                     "message": DENIAL}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "objectSelector": {"matchLabels": {LABEL: "governed"}}}}})
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        probe = artifact(lab, "activation-probe", MARKER, dry_run=True)
        if probe.returncode and DENIAL in probe.stderr:
            return
        time.sleep(.5)
    lab.block("The governed fixture admission policy has no observable denial after activation")


def kubernetes_artifact(lab, name):
    return lab.kubectl("get", "configmap", name, "-o", "json", allow_failure=True)


def run(lab):
    root = lab.kubeconfig.parent
    work, unprotected, protected = (root / name for name in ("source", "no-gate.git", "gated.git"))
    for repo in (work, unprotected, protected):
        repo.mkdir()
        flags = ["--bare"] if repo != work else []
        git(lab, repo, "init", "--template=", "--object-format=sha1", "--initial-branch=main", *flags)
    stage(lab, work, "approved baseline")
    git(lab, work, "commit", "-m", "baseline")
    baseline = visible_ref(lab, work)
    for remote in (unprotected, protected):
        git(lab, work, "push", remote.as_uri(), f"{BRANCH}:{BRANCH}")
    stage(lab, work, MARKER)
    git(lab, work, "commit", "-m", "public synthetic marker baseline")
    marked = visible_ref(lab, work)
    git(lab, work, "push", unprotected.as_uri(), f"{marked}:{BRANCH}")
    raw = artifact(lab, "ungated-marker", MARKER)
    initial = {"ungated_commit_advanced": marked != baseline,
               "ungated_ref_advanced": visible_ref(lab, unprotected) == marked,
               "ungated_artifact_persisted": raw.returncode == 0
               and json.loads(kubernetes_artifact(lab, "ungated-marker").stdout)["data"]["rendered"] == MARKER}
    lab.check("red", "Without gates the commit, isolated destination and release fixture accept the marker",
              all(initial.values()), initial)

    git(lab, work, "reset", "--hard", baseline)
    hook(work / ".git", "pre-commit", 'set -- --cached -e "$marker" --\n' + HOOK_SCAN)
    hook(protected, "pre-receive", '''
while read -r old new branch; do
    [ "$branch" = refs/heads/main ] || exit 1
    [ "$new" != 0000000000000000000000000000000000000000 ] || exit 1
    commits=$(git rev-list "$old..$new")
    for commit in $commits; do
        set -- -e "$marker" "$commit" --
''' + HOOK_SCAN + '''
    done
done
''')
    stage(lab, work, MARKER)
    blocked_commit = git(lab, work, "commit", "-m", "attempt marked candidate", allow_failure=True)
    blocked_push = git(lab, work, "push", protected.as_uri(), f"{marked}:{BRANCH}", allow_failure=True)
    admission(lab)
    blocked_artifact = artifact(lab, "protected-marker", MARKER)
    missing = kubernetes_artifact(lab, "protected-marker")
    blocked = {
        "local_commit_denied": blocked_commit.returncode != 0 and DENIAL in blocked_commit.stderr,
        "local_ref_unchanged": visible_ref(lab, work) == baseline,
        "receive_denied": blocked_push.returncode != 0 and DENIAL in blocked_push.stderr,
        "destination_ref_unchanged": visible_ref(lab, protected) == baseline,
        "api_denied": blocked_artifact.returncode != 0 and DENIAL in blocked_artifact.stderr,
        "artifact_absent": missing.returncode != 0 and "(NotFound)" in missing.stderr,
    }
    lab.check("green", "Each installed gate denies the marker at its actual transition", all(blocked.values()), blocked)

    near_match = "SAF_PUBLIC_SYNTHETIC_SCAN_EXAMPLE_0403"
    stage(lab, work, near_match)
    git(lab, work, "commit", "-m", "approved public example")
    clean_revision = visible_ref(lab, work)
    git(lab, work, "push", protected.as_uri(), f"{clean_revision}:{BRANCH}")
    good_artifact = artifact(lab, "protected-example", near_match)
    clean = {"clean_commit_advanced": clean_revision != baseline,
             "clean_destination_advanced": visible_ref(lab, protected) == clean_revision,
             "clean_artifact_persisted": good_artifact.returncode == 0
             and json.loads(kubernetes_artifact(lab, "protected-example").stdout)["data"]["rendered"] == near_match}
    lab.check("positive", "A benign adjacent value passes all three gates", all(clean.values()), clean)
    (lab.evidence / "publication-gate-observations.json").write_text(json.dumps({
        "no_gate": initial, "mandatory_gates": blocked, "benign_example": clean,
    }, indent=2) + "\n")
