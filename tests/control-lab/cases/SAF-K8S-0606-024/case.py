"""Promote one case-owned Git policy through Kubernetes RBAC and observe CEL enforcement."""
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile
import time

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
PROMOTER = f"system:serviceaccount:{NAMESPACE}:policy-promoter"
EDITOR = f"system:serviceaccount:{NAMESPACE}:policy-editor"
POLICY = "saf0606024-role-scope"
SCOPE = (
    "A local case-owned bare Git repository protects its main ref with a pinned approved policy tree. "
    "Kubernetes v1.36.1 RBAC authorizes a fixture ServiceAccount to promote the exact committed policies. "
    "A scoped native ValidatingAdmissionPolicy denies a case-owned Role declaring Secret reads and "
    "admits a read-only Pod Role. No live credential, external Git host or other cluster is used. "
    "The approved tree contains one inert Role, nonmatching NetworkPolicy, Pod Security namespace labels, "
    "and the admission policy/binding. The Git hook checks every file as one exact tree. Production approval, "
    "revision authorization, hosted Git and other policy families require separate evidence."
)
FILES = ("policy.yaml", "policy-binding.yaml", "role.yaml", "networkpolicy.yaml", "namespace.yaml")
DENIAL = "fixture Roles may only read pods in the core API group"
HOOK_DENIAL = "SAF policy gate: protected files differ from the approved tree"


def _resource(kind, name, **fields):
    return {"apiVersion": "v1", "kind": kind,
            "metadata": {"name": name, "labels": {"saf-k8s.example/control": "0606-024"}},
            **fields}


def _promoter_rbac(lab):
    lab.create(_resource("ServiceAccount", "policy-promoter"))
    lab.create(_resource("ServiceAccount", "policy-editor"))
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
        "metadata": {"name": "saf0606024-policy-promoter"},
        # RBAC cannot constrain create by resource name because the name is not
        # part of the authorization attributes for a create request. Keep create
        # to these two API resource types; scope reads and mutations by name.
        "rules": [
            {"apiGroups": ["admissionregistration.k8s.io"],
             "resources": ["validatingadmissionpolicies", "validatingadmissionpolicybindings"],
             "verbs": ["create"]},
            {"apiGroups": ["admissionregistration.k8s.io"],
             "resources": ["validatingadmissionpolicies", "validatingadmissionpolicybindings"],
             "verbs": ["get", "patch", "update"], "resourceNames": [POLICY]},
        ],
    })
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
        "metadata": {"name": "saf0606024-policy-promoter"},
        "subjects": [{"kind": "ServiceAccount", "name": "policy-promoter", "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                    "name": "saf0606024-policy-promoter"},
    })
    # A namespaced Role limits namespaced policy promotion to this fixture namespace.
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "saf0606024-settings-promoter", "namespace": NAMESPACE},
        "rules": [
            {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles"], "verbs": ["create"]},
            {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles"],
             "verbs": ["get", "update"], "resourceNames": ["saf0606024-approved-empty-role"]},
            {"apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"], "verbs": ["create"]},
            {"apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"],
             "verbs": ["get", "update"], "resourceNames": ["saf0606024-approved-empty-selector"]},
        ],
    })
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": "saf0606024-settings-promoter", "namespace": NAMESPACE},
        "subjects": [{"kind": "ServiceAccount", "name": "policy-promoter", "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": "saf0606024-settings-promoter"},
    })
    # Namespace is cluster-scoped; restrict this authority to the one owned fixture namespace.
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
        "metadata": {"name": "saf0606024-namespace-promoter"},
        "rules": [{"apiGroups": [""], "resources": ["namespaces"],
                   "verbs": ["get", "patch", "update"], "resourceNames": [NAMESPACE]}],
    })
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
        "metadata": {"name": "saf0606024-namespace-promoter"},
        "subjects": [{"kind": "ServiceAccount", "name": "policy-promoter", "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                    "name": "saf0606024-namespace-promoter"},
    })
    lab.kubectl("label", "namespace", NAMESPACE, "saf-k8s.example/control=0606-024", "--overwrite")


def _git(lab, *args, allow_failure=False):
    return lab.command(
        "env", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
        "GIT_AUTHOR_NAME=SAF isolated fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid",
        "GIT_COMMITTER_NAME=SAF isolated fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid",
        "GIT_AUTHOR_DATE=2026-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE=2026-01-01T00:00:00+00:00",
        "git", *map(str, args), allow_failure=allow_failure,
    )


def _git_snapshot(lab, temporary):
    if not shutil.which("git"):
        lab.block("Git is required for the case-owned policy source repository")
    repo = temporary / "policy-source"
    _git(lab, "init", "--template=", "--object-format=sha1", "--initial-branch=main", repo)
    _git(lab, "-C", repo, "commit", "--allow-empty", "-m", "case-owned baseline")
    baseline = _git(lab, "-C", repo, "rev-parse", "HEAD").stdout.strip()
    for filename in FILES:
        shutil.copyfile(HERE / "fixtures" / filename, repo / filename)
    _git(lab, "-C", repo, "add", "--", *FILES)
    _git(lab, "-C", repo, "commit", "-m", "approved case-owned policy")
    approved = _git(lab, "-C", repo, "rev-parse", "HEAD").stdout.strip()
    tree = _git(lab, "-C", repo, "rev-parse", "HEAD^{tree}").stdout.strip()

    _git(lab, "-C", repo, "switch", "-c", "candidate", baseline)
    for filename in FILES:
        shutil.copyfile(HERE / "fixtures" / filename, repo / filename)
    candidate_policy = repo / "policy.yaml"
    altered = candidate_policy.read_text().replace("resource == 'pods'", "resource == 'configmaps'")
    candidate_policy.write_text(altered)
    _git(lab, "-C", repo, "add", "--", *FILES)
    _git(lab, "-C", repo, "commit", "-m", "unapproved case-owned policy")
    candidate = _git(lab, "-C", repo, "rev-parse", "HEAD").stdout.strip()

    unprotected = temporary / "baseline.git"
    protected = temporary / "approved.git"
    for remote in (unprotected, protected):
        _git(lab, "init", "--bare", "--template=", "--object-format=sha1", "--initial-branch=main", remote)
        _git(lab, "-C", repo, "push", remote.as_uri(), f"{baseline}:refs/heads/main")
    hooks = protected / "hooks"
    hooks.mkdir()
    hook = hooks / "pre-receive"
    shutil.copyfile(HERE / "fixtures" / "pre-receive", hook)
    hook.chmod(0o700)
    _git(lab, "-C", protected, "config", "--local", "saf.approvedPolicyTree", tree)

    def bare_ref(remote):
        return _git(lab, "-C", remote, "rev-parse", "refs/heads/main").stdout.strip()

    baseline_push = _git(lab, "-C", repo, "push", unprotected.as_uri(), "candidate:refs/heads/main")
    _raw(lab, "git-unprotected-push.raw.json", baseline_push)
    open_ref = bare_ref(unprotected)
    lab.check("red", "The unprotected Git ref advances to the unapproved policy tree",
              open_ref == candidate and candidate != approved,
              {"candidate_commit": candidate, "remote_ref": open_ref})
    refused = _git(lab, "-C", repo, "push", protected.as_uri(), "candidate:refs/heads/main",
                   allow_failure=True)
    _raw(lab, "git-protected-denial.raw.json", refused)
    unchanged = bare_ref(protected) == baseline
    lab.check("green", "The protected ref rejects the same tree and keeps its exact previous commit",
              refused.returncode != 0 and HOOK_DENIAL in refused.stderr and unchanged,
              {"policy_denial": HOOK_DENIAL in refused.stderr, "ref_unchanged": unchanged})

    # Each remaining file is altered independently in an inert candidate. None is applied to Kubernetes.
    tamper_ops = {
        "policy-binding.yaml": ("validationActions: [Deny]", "validationActions: [Warn]"),
        "role.yaml": ("name: saf0606024-approved-empty-role", "name: saf0606024-unapproved-pod-read-role"),
        "networkpolicy.yaml": ("saf-k8s.example/no-fixture-pod: 'selected'", "saf-k8s.example/no-fixture-pod: 'other'"),
        "namespace.yaml": ("pod-security.kubernetes.io/warn: restricted", "pod-security.kubernetes.io/warn: baseline"),
    }
    for index, (filename, (before, after)) in enumerate(tamper_ops.items()):
        branch = f"candidate-extra-{index}"
        _git(lab, "-C", repo, "switch", "--force-create", branch, baseline)
        for item in FILES:
            shutil.copyfile(HERE / "fixtures" / item, repo / item)
        candidate_file = repo / filename
        original = candidate_file.read_text()
        altered = original.replace(before, after, 1)
        if altered == original:
            lab.block(f"Could not create the bounded one-file candidate for {filename}")
        candidate_file.write_text(altered)
        _git(lab, "-C", repo, "add", "--", *FILES)
        _git(lab, "-C", repo, "commit", "-m", f"unapproved isolated edit {index}")
        refused_extra = _git(lab, "-C", repo, "push", protected.as_uri(), f"{branch}:refs/heads/main",
                             allow_failure=True)
        _raw(lab, f"git-protected-denial-{filename}.raw.json", refused_extra)
        still_baseline = bare_ref(protected) == baseline
        lab.check("green", f"Protected ref rejects an unapproved change to {filename}",
                  refused_extra.returncode != 0 and HOOK_DENIAL in refused_extra.stderr and still_baseline,
                  {"file": filename, "policy_denial": HOOK_DENIAL in refused_extra.stderr,
                   "ref_unchanged": still_baseline, "single_file_candidate": True})

    promoted = _git(lab, "-C", repo, "push", protected.as_uri(), "main:refs/heads/main")
    _raw(lab, "git-protected-approval.raw.json", promoted)
    revision = bare_ref(protected)
    lab.check("positive", "The protected ref accepts the approved tree",
              revision == approved, {"approved_commit": approved, "remote_ref": revision, "approved_tree": tree})

    snapshot = {"commit": revision, "files": {}}
    for filename in FILES:
        ref = f"{revision}:{filename}"
        content = _git(lab, "-C", protected, "show", ref).stdout.encode()
        if content != (HERE / "fixtures" / filename).read_bytes():
            lab.block(f"Protected ref differs from the approved fixture: {filename}")
        materialized = temporary / filename
        materialized.write_bytes(content)
        snapshot["files"][filename] = {"sha256": sha256(content).hexdigest(),
                                       "git_blob": _git(lab, "-C", protected, "rev-parse", ref).stdout.strip()}
    (lab.evidence / "policy-source.json").write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    return snapshot


def _apply_as(lab, filename, identity, allow_failure=False):
    return lab.kubectl("apply", "-f", str(filename), f"--as={identity}", allow_failure=allow_failure)


def _create_role(lab, name, rule, *, dry_run=False, allow_failure=False):
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": name, "labels": {"saf-k8s.example/control": "0606-024"}},
        "rules": [rule],
    }
    return lab.create(role, dry_run=dry_run, allow_failure=allow_failure)


def _raw(lab, name, result):
    (lab.evidence / name).write_text(json.dumps({"returncode": result.returncode,
                                                  "stdout": result.stdout,
                                                  "stderr": result.stderr}, indent=2) + "\n")


def run(lab):
    _promoter_rbac(lab)
    safe_rule = {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}
    unsafe_rule = {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}

    baseline = _create_role(lab, "saf0606024-baseline-red", unsafe_rule, allow_failure=True)
    baseline_ok = baseline.returncode == 0
    _raw(lab, "baseline-red-api.raw.json", baseline)
    observed_rules = json.loads(baseline.stdout).get("rules") if baseline_ok else None
    lab.check("red", "Before policy promotion, the native API stores the case-owned Secret-read Role",
              baseline_ok and observed_rules == [unsafe_rule],
              {"api_returncode": baseline.returncode, "stored_rules": observed_rules})
    lab.kubectl("delete", "role/saf0606024-baseline-red")

    with tempfile.TemporaryDirectory(prefix="saf0606024-", dir=str(lab.kubeconfig.parent)) as temp_name:
        temporary = Path(temp_name)
        snapshot = _git_snapshot(lab, temporary)
        lab.check("positive", "The promoter receives exact files from the protected Git ref",
                  tuple(snapshot["files"]) == FILES,
                  {"commit": snapshot["commit"],
                   "files": {name: row["sha256"] for name, row in snapshot["files"].items()}})

        editor = lab.kubectl(
            "create", "--validate=false", "-f", str(temporary / "policy.yaml"),
            f"--as={EDITOR}", allow_failure=True,
        )
        _raw(lab, "unauthorized-promotion.raw.json", editor)
        editor_denied = (editor.returncode != 0 and "Forbidden" in editor.stderr
                         and 'cannot create resource "validatingadmissionpolicies"' in editor.stderr
                         and EDITOR in editor.stderr)
        lab.check("green", "The unprivileged case ServiceAccount cannot promote policy through the API",
                  editor_denied, {"api_returncode": editor.returncode,
                                  "forbidden": "Forbidden" in editor.stderr,
                                  "requested_verb": "create",
                                  "resource": "validatingadmissionpolicies" if editor_denied else None})

        policy_path = temporary / "policy.yaml"
        binding_path = temporary / "policy-binding.yaml"
        policy_result = _apply_as(lab, policy_path, PROMOTER)
        binding_result = _apply_as(lab, binding_path, PROMOTER)
        _raw(lab, "policy-promotion.raw.json", policy_result)
        _raw(lab, "binding-promotion.raw.json", binding_result)
        live_policy = json.loads(lab.kubectl("get", f"validatingadmissionpolicy/{POLICY}", "-o", "json").stdout)
        live_binding = json.loads(lab.kubectl("get", f"validatingadmissionpolicybinding/{POLICY}", "-o", "json").stdout)
        actual = {
            "policy_expression": live_policy["spec"]["validations"][0]["expression"],
            "failure_policy": live_policy["spec"].get("failurePolicy"),
            "binding_policy": live_binding["spec"].get("policyName"),
            "validation_actions": live_binding["spec"].get("validationActions"),
            "namespace_selector": live_binding["spec"]["matchResources"]["namespaceSelector"],
        }
        (lab.evidence / "promoted-native-policy.raw.json").write_text(
            json.dumps({"policy": live_policy, "binding": live_binding}, indent=2, sort_keys=True) + "\n")
        native_ready = (policy_result.returncode == 0 and binding_result.returncode == 0
                       and actual["failure_policy"] == "Fail"
                       and actual["binding_policy"] == POLICY
                       and actual["validation_actions"] == ["Deny"]
                       and actual["namespace_selector"] == {"matchLabels": {"saf-k8s.example/control": "0606-024"}}
                       and "resource == 'pods'" in actual["policy_expression"]
                       and "verb in ['get', 'list', 'watch']" in actual["policy_expression"])
        lab.check("positive", "The promoter applies the committed native policy and scoped Deny binding",
                  native_ready, actual)

        # Require the fixture namespace to be empty before applying its Pod Security labels.
        preexisting = json.loads(lab.kubectl("get", "pods", "-n", NAMESPACE, "-o", "json").stdout).get("items", [])
        if preexisting:
            lab.block("Refusing Pod Security label promotion while the fixture namespace contains Pods")
        promoted_paths = {name: temporary / name for name in FILES}
        namespace_result = _apply_as(lab, promoted_paths["namespace.yaml"], PROMOTER)
        role_result = _apply_as(lab, promoted_paths["role.yaml"], PROMOTER)
        network_result = _apply_as(lab, promoted_paths["networkpolicy.yaml"], PROMOTER)
        for filename, result in (("namespace.yaml", namespace_result), ("role.yaml", role_result),
                                 ("networkpolicy.yaml", network_result)):
            _raw(lab, f"promotion-{filename}.raw.json", result)
        observed_namespace = json.loads(lab.kubectl("get", "namespace", NAMESPACE, "-o", "json").stdout)
        observed_role = json.loads(lab.kubectl("get", "role", "saf0606024-approved-empty-role",
                                               "-n", NAMESPACE, "-o", "json").stdout)
        observed_network = json.loads(lab.kubectl("get", "networkpolicy", "saf0606024-approved-empty-selector",
                                                   "-n", NAMESPACE, "-o", "json").stdout)
        network_selector = observed_network.get("spec", {}).get("podSelector", {}).get("matchLabels", {})
        running_pods = json.loads(lab.kubectl("get", "pods", "-n", NAMESPACE, "-o", "json").stdout).get("items", [])
        selected = [pod for pod in running_pods
                    if all(pod.get("metadata", {}).get("labels", {}).get(k) == v
                           for k, v in network_selector.items())]
        role_bindings = json.loads(lab.kubectl("get", "rolebindings", "-n", NAMESPACE, "-o", "json").stdout).get("items", [])
        role_is_unbound = not any(
            binding.get("roleRef", {}).get("kind") == "Role"
            and binding.get("roleRef", {}).get("name") == "saf0606024-approved-empty-role"
            for binding in role_bindings)
        namespace_labels = observed_namespace.get("metadata", {}).get("labels", {})
        # The apiserver serializes a newly created empty Role's rules as null.
        role_has_no_rules = observed_role.get("rules") in (None, [])
        expected_network = {"saf-k8s.example/no-fixture-pod": "selected"}
        promoted_settings_ok = (all(r.returncode == 0 for r in
                                    (policy_result, binding_result, namespace_result, role_result, network_result))
                                and namespace_labels.get("pod-security.kubernetes.io/warn") == "restricted"
                                and namespace_labels.get("pod-security.kubernetes.io/warn-version") == "v1.36"
                                and namespace_labels.get("saf-k8s.example/control") == "0606-024"
                                and role_has_no_rules
                                and observed_network.get("spec", {}).get("podSelector", {}).get("matchLabels") == expected_network
                                and observed_network.get("spec", {}).get("policyTypes") == ["Ingress", "Egress"]
                                and selected == [] and role_is_unbound)
        (lab.evidence / "multi-file-policy-promotion.raw.json").write_text(json.dumps({
            "namespace_labels": namespace_labels,
            "role_rules": observed_role.get("rules"),
            "network_policy": observed_network.get("spec"),
            "matching_pods": [p.get("metadata", {}).get("name") for p in selected],
            "role_has_no_subject_binding": role_is_unbound,
            "promoter": PROMOTER,
            "source_file_sha256": {name: snapshot["files"][name]["sha256"] for name in FILES},
        }, indent=2, sort_keys=True) + "\n")
        lab.check("positive", "One authorized promoter applies the exact approved Role, nonmatching NetworkPolicy, Pod Security namespace labels, and admission configuration",
                  promoted_settings_ok,
                  {"promoter": PROMOTER, "files": list(FILES), "namespace_labels": {
                      "pod-security.kubernetes.io/warn": namespace_labels.get("pod-security.kubernetes.io/warn"),
                      "pod-security.kubernetes.io/warn-version": namespace_labels.get("pod-security.kubernetes.io/warn-version")},
                       "role_rules_match": role_has_no_rules,
                   "network_policy_selector_match": observed_network.get("spec", {}).get("podSelector", {}).get("matchLabels") == expected_network,
                   "selected_pods": len(selected), "role_has_no_subject_binding": role_is_unbound,
                   "all_resource_apply_calls_succeeded": all(
                       r.returncode == 0 for r in (policy_result, binding_result, namespace_result, role_result, network_result))})

        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            probe = _create_role(lab, "saf0606024-baseline-red", unsafe_rule, dry_run=True, allow_failure=True)
            if probe.returncode != 0:
                break
            time.sleep(0.4)
        blocked = _create_role(lab, "saf0606024-baseline-red", unsafe_rule, allow_failure=True)
        _raw(lab, "post-promotion-red-api.raw.json", blocked)
        denied_by_policy = (blocked.returncode != 0 and "ValidatingAdmissionPolicy" in blocked.stderr
                            and POLICY in blocked.stderr
                            and DENIAL in blocked.stderr)
        lab.check("green", "The promoted native policy denies a Role declaring Secret reads",
                  denied_by_policy, {"api_returncode": blocked.returncode,
                                     "policy_name": POLICY if POLICY in blocked.stderr else None,
                                     "message_match": DENIAL in blocked.stderr})

        green = _create_role(lab, "saf0606024-post-green", safe_rule, allow_failure=True)
        green_ok = green.returncode == 0
        _raw(lab, "post-promotion-green-api.raw.json", green)
        if green_ok:
            stored = json.loads(lab.kubectl("get", "role/saf0606024-post-green", "-o", "json").stdout)
            observed_rules = stored.get("rules")
        else:
            observed_rules = None
        expected_rules = [{"apiGroups": [""], "resources": ["pods"],
                           "verbs": ["get", "list", "watch"]}]
        lab.check("green", "The same native policy admits the harmless read-only Pod Role",
                  green_ok and observed_rules == expected_rules,
                  {"api_returncode": green.returncode, "stored_rules": observed_rules})
