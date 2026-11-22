"""Check source-derived upgrade records and the pinned kubelet parser."""
import json
from pathlib import Path
import re
import time


CASE_DIR = Path(__file__).resolve().parent
PLAN_PATH = CASE_DIR / "feature-gate-upgrade.json"
LOCKED = "KubeletCgroupDriverFromCRI"
REMOVED = "DevicePluginCDIDevices"

SCOPE = (
    "Source-derived checks for stale configuration of one locked kubelet gate and "
    "one removed gate. The v1.36.1 kind node's kubelet binary validates the same flag "
    "inputs before hitting an intentionally impossible configuration path. This uses "
    "a separate short-lived command without changing the running kubelet. Actual "
    "upgrade execution, managed clusters and organization-wide coverage remain separate. "
    "A defensive GitRepoVolumeDriver locked-off parser check and namespace-scoped "
    "ValidatingAdmissionPolicy use only synthetic server-side dry-run requests. No "
    "gitRepo workload is persisted or executed."
)

GITREPO_GATE = "GitRepoVolumeDriver"
GITREPO_POLICY = "saf-k8s-0104-009-gitrepo-deny"
GITREPO_BINDING = "saf-k8s-0104-009-gitrepo-deny"
GITREPO_DENIAL = "spec.volumes[*].gitRepo is prohibited; migrate to a supported volume source"


def minor(release):
    match = re.fullmatch(r"v?(\d+)\.(\d+)(?:\.\d+)?", release)
    if not match:
        raise ValueError(f"invalid Kubernetes release: {release}")
    return int(match.group(1)), int(match.group(2))


def lifecycle_for(plan, target_release):
    target = minor(target_release)
    state = "active"
    for transition in plan["transitions"]:
        if target >= minor(transition["release"]):
            state = transition["lifecycle"]
    return state


def evaluate(plan, observation):
    findings = []
    for component in observation["components"]:
        if component.get("name") != plan["component"]:
            continue
        for source in component.get("observations", []):
            settings = source.get("feature_gates", {})
            for gate in settings.keys() & plan["gates"].keys():
                state = lifecycle_for(plan["gates"][gate], observation["target_release"])
                if state == "active":
                    continue
                findings.append({
                    "gate": gate,
                    "lifecycle": state,
                    "source": source.get("source", "unspecified"),
                    "configured_value": settings[gate],
                    "message": (
                        "explicit value is stale: the gate is locked to its default"
                        if state == "locked-to-default"
                        else "explicit value refers to a removed gate"
                    ),
                })
    return findings


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def fixture(name):
    return load_json(CASE_DIR / "fixtures" / name)


def check_fixtures(lab):
    plan = load_json(PLAN_PATH)
    unrelated_gate = "GracefulNodeShutdown"

    locked_bad = fixture("locked-stale.json")
    locked_findings = evaluate(plan, locked_bad)
    lab.check(
        "red",
        "v1.36 locked-to-default fixture detects a stale explicit false value",
        len(locked_findings) == 1
        and locked_findings[0]["gate"] == LOCKED
        and locked_findings[0]["lifecycle"] == "locked-to-default"
        and locked_findings[0]["configured_value"] is False
        and locked_findings[0]["source"] == "process-flag",
        locked_findings,
    )

    locked_good = fixture("locked-clean.json")
    lab.check(
        "green",
        "v1.36 green fixture removes the locked gate from flag and config observations",
        evaluate(plan, locked_good) == [],
        evaluate(plan, locked_good),
    )
    lab.check(
        "positive",
        "unrelated feature-gate observation is retained without being rewritten",
        locked_good["unrelated_feature_gates"].get(unrelated_gate) is True,
        {unrelated_gate: locked_good["unrelated_feature_gates"].get(unrelated_gate)},
    )

    removed_bad = fixture("removed-stale.json")
    removed_findings = evaluate(plan, removed_bad)
    lab.check(
        "red",
        "v1.36 removed-gate fixture distinguishes unsupported stale configuration",
        len(removed_findings) == 1
        and removed_findings[0]["gate"] == REMOVED
        and removed_findings[0]["lifecycle"] == "removed"
        and removed_findings[0]["configured_value"] is True
        and removed_findings[0]["source"] == "kubelet-config",
        removed_findings,
    )

    removed_good = fixture("removed-clean.json")
    lab.check(
        "green",
        "v1.36 clean fixture has no explicit removed gate",
        evaluate(plan, removed_good) == [],
        evaluate(plan, removed_good),
    )


def inert_pod(name, volume_source):
    """Build a synthetic Pod request; callers submit it only with server dry-run."""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": "saf-test"},
        "spec": {
            "restartPolicy": "Never",
            "containers": [{"name": "fixture", "image": "example.invalid/never-pulled:fixture",
                            "volumeMounts": [{"name": "fixture-data", "mountPath": "/fixture",
                                              "readOnly": True}]}],
            "volumes": [{"name": "fixture-data", **volume_source}],
        },
    }


def install_gitrepo_policy(lab):
    """Install a case-specific deny rule in the fresh runner-owned cluster."""
    lab.apply(CASE_DIR / "gitrepo-admission-policy.yaml")


def server_dry_run(lab, pod):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(pod), allow_failure=True)


def check_gitrepo_admission(lab):
    legacy = inert_pod("synthetic-gitrepo-never-persisted", {
        "gitRepo": {"repository": "https://example.invalid/never-clone", "revision": "inert"},
    })
    before_policy = server_dry_run(lab, legacy)
    admitted_legacy = before_policy.returncode == 0
    lab.check(
        "red", "The live API accepts the inert legacy volume before policy",
        admitted_legacy,
        {"dry_run_admitted": admitted_legacy,
         "detail": "dry-run admitted" if admitted_legacy else before_policy.stderr.strip()},
    )

    install_gitrepo_policy(lab)
    rejected = server_dry_run(lab, legacy)
    for _ in range(20):
        if rejected.returncode != 0:
            break
        time.sleep(1)
        rejected = server_dry_run(lab, legacy)
    detail = rejected.stderr
    denied_by_expected_policy = (
        rejected.returncode != 0
        and f"ValidatingAdmissionPolicy '{GITREPO_POLICY}'" in detail
        and f"binding '{GITREPO_BINDING}'" in detail
        and GITREPO_DENIAL in detail
    )
    lab.check(
        "green",
        "Server-side dry-run rejects the inert legacy field with the exact policy message",
        denied_by_expected_policy,
        {"denied_by_expected_policy": denied_by_expected_policy,
         "exact_message_present": GITREPO_DENIAL in detail,
         "detail": detail.strip() if not denied_by_expected_policy else "expected denial observed"},
    )

    supported = inert_pod("synthetic-emptydir-permitted", {"emptyDir": {}})
    admitted = server_dry_run(lab, supported)
    lab.check(
        "positive",
        "Server-side dry-run permits the supported emptyDir counterpart",
        admitted.returncode == 0,
        {"admitted": admitted.returncode == 0,
         "detail": admitted.stderr.strip() if admitted.returncode else "dry-run admitted"},
    )


def run(lab):
    check_fixtures(lab)
    node = f"{lab.cluster}-control-plane"
    node_status = json.loads(lab.kubectl("get", "node", node, "-o", "json").stdout)["status"]
    if node_status["nodeInfo"]["kubeletVersion"] != "v1.36.1":
        lab.block("The pinned kubelet version was not observed")

    # Kubelet applies feature gates before trying to load this intentionally
    # impossible file. /dev/null cannot contain a file or start a second kubelet.
    path = "/dev/null/saf-k8s-feature-gate-probe.yaml"
    for phase, label, setting, expected in (
        ("red", "Locked kubelet gate rejects the opposite value", f"{LOCKED}=false", "feature is locked to true"),
        ("red", "Removed kubelet gate is unrecognized", f"{REMOVED}=true", f"unrecognized feature gate: {REMOVED}"),
        ("red", "v1.36 gitRepo driver gate rejects enabling the locked feature", f"{GITREPO_GATE}=true", "feature is locked to false"),
        ("positive", "Recognized explicit default reaches the file sentinel", f"{LOCKED}=true", "not a directory"),
        ("positive", "gitRepo driver default reaches the impossible config sentinel", f"{GITREPO_GATE}=false", "not a directory"),
        ("green", "Removing stale flags reaches the file sentinel", None, "not a directory"),
    ):
        flags = (f"--feature-gates={setting}",) if setting else ()
        result = lab.command("docker", "exec", node, "kubelet", *flags, f"--config={path}",
                             timeout=10, allow_failure=True)
        outcome = (result.stdout + result.stderr).lower()
        matched = result.returncode != 0 and expected.lower() in outcome
        if expected == "not a directory":
            matched = matched and path in outcome
        lab.check(phase, label, matched, {"expected_parser_outcome": expected, "matched": matched})

    readiness = lab.kubectl("get", "--raw=/readyz").stdout.strip()
    lab.check("positive", "The running kind API stays ready", readiness == "ok", {"ready": readiness == "ok"})
    check_gitrepo_admission(lab)


class StaticReporter:
    """Small reporter for running only the local JSON fixture checks."""

    def __init__(self):
        self.failed = False

    def check(self, kind, description, passed, actual=None):
        status = "PASS" if passed else "FAIL"
        print(f"{status} [{kind}] {description}")
        if not passed:
            print(f"  observed: {actual!r}")
            self.failed = True


if __name__ == "__main__":
    reporter = StaticReporter()
    check_fixtures(reporter)
    raise SystemExit(1 if reporter.failed else 0)
