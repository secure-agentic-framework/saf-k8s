"""Verify ordinary impersonation name scopes and a separate harmless read decision."""
import json
import subprocess
import time

NS = "saf-test"
RBAC = "rbac.authorization.k8s.io/v1"
CALLER = "fixture-review-caller"
REVIEWER = "fixture-approved-reader"
TARGET_ACCOUNT = "fixture-approved-account"
CONFIG = "fixture-ordinary-capsule"
LABEL = "fixture-delegation"
MARKER = "owned-public-capsule-marker"
SCOPE = (
    "Real authorization reviews inspect exact approved and unrelated synthetic targets for "
    "users, groups, namespaced serviceaccounts, user extras and UIDs. One authorized "
    "delegation performs a harmless ConfigMap read. All fixture identities are temporary, "
    "and no elevated delegation, external target or production resources are exercised."
)
TARGETS = {
    "user": ("", "users", None, None, REVIEWER, "fixture-other-reader"),
    "group": ("", "groups", None, None, "fixture-review-group", "fixture-unlisted-group"),
    "serviceaccount": ("", "serviceaccounts", None, NS, TARGET_ACCOUNT, "fixture-unlisted-account"),
    "extra": ("authentication.k8s.io", "userextras", "scopes", None, "fixture-observe", "fixture-edit"),
    "uid": ("authentication.k8s.io", "uids", None, None, "fixture-reader-0001", "fixture-reader-0002"),
}


def put(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def caller_kubeconfig(lab):
    token_cmd = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                 "--namespace", NS, "create", "token", CALLER, "--duration=10m"]
    result = subprocess.run(token_cmd, env=lab.env, capture_output=True, text=True, timeout=20)
    if result.returncode or len(result.stdout.strip().split(".")) != 3:
        lab.block("Could not issue the disposable caller credential")
    def native(field):
        return lab.kubectl("config", "view", "--minify", "--raw", "-o",
                           "jsonpath={.clusters[0].cluster." + field + "}").stdout.strip()
    token_file = lab.kubeconfig.parent / "fixture-caller.token"
    token_file.touch(mode=0o600, exist_ok=False)
    token_file.write_text(result.stdout.strip())
    config = lab.kubeconfig.parent / "caller.json"
    config.touch(mode=0o600, exist_ok=False)
    config.write_text(json.dumps({
        "apiVersion": "v1", "kind": "Config", "current-context": "fixture",
        "clusters": [{"name": "owned", "cluster": {"server": native("server"),
                      "certificate-authority-data": native("certificate-authority-data")}}],
        "users": [{"name": "caller", "user": {"tokenFile": str(token_file)}}],
        "contexts": [{"name": "fixture", "context": {"cluster": "owned", "user": "caller", "namespace": NS}}],
    }))
    return config


def scoped_kubectl(lab, config, *args, **kwargs):
    return lab.command("kubectl", "--kubeconfig", str(config), "--context", "fixture",
                       "--request-timeout=7s", *args, timeout=12, **kwargs)


def reviewed(lab, config, target, name, namespace_override=None):
    group, resource, subresource, namespace, _, _ = target
    attributes = {"verb": "impersonate", "group": group, "resource": resource, "name": name}
    if subresource:
        attributes["subresource"] = subresource
    if namespace_override or namespace:
        attributes["namespace"] = namespace_override or namespace
    body = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
            "spec": {"resourceAttributes": attributes}}
    review_path = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
    out = scoped_kubectl(lab, config, "create", "--raw=" + review_path, "-f", "-", payload=json.dumps(body))
    return json.loads(out.stdout)["status"]["allowed"]


def rule(name, resource, verb, names):
    return {"apiGroups": [name], "resources": [resource], "verbs": [verb], "resourceNames": names}


def install(lab):
    synthetic = [{"kind": "ServiceAccount", "name": CALLER, "namespace": NS}]
    role_rules = {
        "cluster": [rule(group, resource + ("/" + subresource if subresource else ""),
                         "impersonate", [ordinary])
                    for group, resource, subresource, namespace, ordinary, _ in TARGETS.values() if not namespace],
        "namespace": [rule("", "serviceaccounts", "impersonate", [TARGET_ACCOUNT])],
    }
    for scope, (kind, binding) in {
            "cluster": ("ClusterRole", "ClusterRoleBinding"), "namespace": ("Role", "RoleBinding")}.items():
        name = f"{LABEL}-{scope}"
        put(lab, kind, name, RBAC, rules=role_rules[scope])
        put(lab, binding, name, RBAC, roleRef={
            "apiGroup": "rbac.authorization.k8s.io", "kind": kind, "name": name}, subjects=synthetic)


def run(lab):
    put(lab, "ConfigMap", CONFIG, data={"marker": MARKER})
    for account in (CALLER, TARGET_ACCOUNT):
        put(lab, "ServiceAccount", account, automountServiceAccountToken=False)
    put(lab, "Role", CONFIG, RBAC, rules=[rule("", "configmaps", "get", [CONFIG])])
    put(lab, "RoleBinding", CONFIG, RBAC,
        roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": CONFIG},
        subjects=[{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": REVIEWER}])
    config = caller_kubeconfig(lab)
    before = {key: not reviewed(lab, config, target, target[4]) for key, target in TARGETS.items()}
    ordinary = scoped_kubectl(lab, config, "get", "configmap", CONFIG, "-o", "name", allow_failure=True)
    baseline = {"no_target_granted_initially": all(before.values()),
                "caller_cannot_read_regular_api_object": ordinary.returncode != 0 and "(Forbidden)" in ordinary.stderr}
    lab.check("red", "The actual caller has neither identity delegation nor the separate read",
              all(baseline.values()), baseline)

    install(lab)
    for _ in range(5):
        if reviewed(lab, config, TARGETS["user"], REVIEWER):
            break
        time.sleep(.5)
    approved = {name: reviewed(lab, config, target, target[4]) for name, target in TARGETS.items()}
    rejected = {name: not reviewed(lab, config, target, target[5]) for name, target in TARGETS.items()}
    outside = not reviewed(lab, config, TARGETS["serviceaccount"], TARGET_ACCOUNT, namespace_override="default")
    lab.check("green", "Name-scoped authorization grants only the tested identities and the intended ServiceAccount namespace",
              all(approved.values()) and all(rejected.values()) and outside,
              {"approved_identity_types": approved, "unrelated_values_denied": rejected, "other_namespace_denied": outside})

    read = scoped_kubectl(lab, config, "--as=" + REVIEWER, "get", "configmap", CONFIG,
                         "-o", "jsonpath={.data.marker}")
    mismatch = scoped_kubectl(lab, config, "get", "configmap", CONFIG, "-o", "name", allow_failure=True)
    lab.kubectl("delete", "clusterrolebinding", f"{LABEL}-cluster", "--wait=true")
    removed = False
    for _ in range(6):
        if not reviewed(lab, config, TARGETS["user"], REVIEWER):
            removed = True
            break
        time.sleep(.5)
    final = {"authorized_delegated_read_observed": read.stdout == MARKER,
             "same_caller_still_has_no_direct_access": mismatch.returncode != 0 and "(Forbidden)" in mismatch.stderr,
             "removed_grant_no_longer_authorizes": removed,
             "separate_namespaced_approval_remains": reviewed(lab, config, TARGETS["serviceaccount"], TARGET_ACCOUNT)}
    lab.check("positive", "One permitted delegation reaches the public fixture and removing its grant retires it",
              all(final.values()), final)
    (lab.evidence / "impersonation-scope-observations.json").write_text(json.dumps({
        "baseline": baseline, "approved": approved, "rejected": rejected,
        "other_namespace_denied": outside, "bounded_delegation": final,
    }, indent=2) + "\n")
