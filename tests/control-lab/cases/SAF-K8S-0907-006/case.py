"""Exercise named Kubernetes-object reads and scoped reads from a PVC fixture."""
import importlib.util
import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
NS = "saf-test"
BASELINE = "fixture-dataset-coarse"
ALPHA = "fixture-dataset-alpha"
BETA = "fixture-dataset-beta"
SEED = "fixture-dataset-seed"
PVC = "fixture-training-data"
CODE = "fixture-dataset-access-code"
POLICY = "fixture-scope-training-claim"
DENIAL = "the named fixture training claim requires an approved workload identity"
MARKERS = {"alpha": "public-fixture-alpha-v1", "beta": "public-fixture-beta-v1"}
GROUPS = {"alpha": 21001, "beta": 21002}
SCOPE = (
    "In the paired saf-test namespace, compare a coarse reader with two explicitly scoped "
    "ServiceAccounts. The Kubernetes API boundary uses RBAC resourceNames for two named "
    "ConfigMaps. The persistent-file boundary uses one case-owned Kind PVC with group-owned "
    "synthetic marker files and distinct supplemental groups. The scoped identities must "
    "retain their own approved reads and receive denials for the other dataset at both "
    "boundaries. Native admission also rejects a fresh out-of-scope Pod requesting the "
    "same claim. Production object-storage IAM is outside this fixture."
)


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def binding(lab, name, role, account):
    create(lab, "RoleBinding", name, "rbac.authorization.k8s.io/v1",
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role},
           subjects=[{"kind": "ServiceAccount", "name": account, "namespace": NS}])


def role(lab, name, account, names=None):
    rule = {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}
    if names is not None:
        rule["resourceNames"] = names
    create(lab, "Role", name, "rbac.authorization.k8s.io/v1", rules=[rule])
    binding(lab, name, name, account)


def pod(name, account, groups, init=False):
    security = {"runAsUser": 10001, "runAsGroup": 10000,
                "runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}}
    if groups:
        security["supplementalGroups"] = groups
    volume_mount = {"name": "dataset", "mountPath": "/datasets", "readOnly": not init}
    spec = {"restartPolicy": "Never", "serviceAccountName": account,
            "automountServiceAccountToken": not init,
            "securityContext": security,
            "volumes": [{"name": "dataset", "persistentVolumeClaim": {"claimName": PVC}},
                        {"name": "code", "configMap": {"name": CODE}}],
            "containers": [{"name": "fixture", "image": "FIXTURE_IMAGE",
                            "imagePullPolicy": "Never",
                            "command": ["python", "/fixture/access_fixture.py", "sleep"],
                            "volumeMounts": [{**volume_mount, "readOnly": True},
                                             {"name": "code", "mountPath": "/fixture", "readOnly": True}],
                            "securityContext": {"allowPrivilegeEscalation": False,
                                                "capabilities": {"drop": ["ALL"]},
                                                "runAsNonRoot": True, "runAsUser": 10001,
                                                "runAsGroup": 10000,
                                                "seccompProfile": {"type": "RuntimeDefault"}}}]}
    if init:
        spec["initContainers"] = [{"name": "seed", "image": "FIXTURE_IMAGE",
                                  "imagePullPolicy": "Never",
                                  "command": ["python", "/fixture/access_fixture.py", "seed"],
                                  "volumeMounts": [volume_mount,
                                                   {"name": "code", "mountPath": "/fixture", "readOnly": True}],
                                  "securityContext": {"allowPrivilegeEscalation": False,
                                                      "capabilities": {"drop": ["ALL"], "add": ["CHOWN"]},
                                                      "runAsUser": 0, "runAsNonRoot": False,
                                                      "seccompProfile": {"type": "RuntimeDefault"}}}]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": spec}


def request_pod(name, account, groups, image, init=False):
    request = pod(name, account, groups, init)
    for unit in request["spec"].get("initContainers", []) + request["spec"]["containers"]:
        unit["image"] = image
    return request


def launch(lab, name, account, groups, image, init=False):
    lab.create(request_pod(name, account, groups, image, init))


def enforce_mount(lab, image):
    restricted = request_pod(BASELINE, BASELINE, list(GROUPS.values()), image)
    lab.kubectl("delete", "pod/"+BASELINE, "--wait=true")
    api = "admissionregistration.k8s.io/v1"
    allowed = json.dumps([ALPHA, BETA])
    expression = (
        "!has(object.spec.volumes) || "
        f'!object.spec.volumes.exists(v, has(v.persistentVolumeClaim) && v.persistentVolumeClaim.claimName == "{PVC}") || '
        f"(has(object.spec.serviceAccountName) && object.spec.serviceAccountName in {allowed})"
    )
    create(lab, "ValidatingAdmissionPolicy", POLICY, api,
           spec={"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
               "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]
           }]}, "validations": [{"expression": expression, "message": DENIAL}]})
    create(lab, "ValidatingAdmissionPolicyBinding", POLICY, api,
           spec={"policyName": POLICY, "validationActions": ["Deny"],
                 "matchResources": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NS}}}})
    deadline = time.monotonic() + 24
    while time.monotonic() < deadline:
        result = lab.create(restricted, dry_run=True, allow_failure=True)
        if result.returncode and DENIAL in result.stderr:
            break
        time.sleep(.25)
    else:
        lab.block("The reviewed mount policy did not become active")
    result = lab.create(restricted, allow_failure=True)
    absent = lab.kubectl("get", "pod/"+BASELINE, "--ignore-not-found=true", "-o", "name")
    return {"fresh_out_of_scope_claim_reference_denied": result.returncode != 0 and DENIAL in result.stderr,
            "denied_workload_not_persisted": absent.stdout.strip() == ""}


def observe(lab, name, mode):
    result = lab.kubectl("exec", name, "--", "python", "/fixture/access_fixture.py", "probe", mode,
                         timeout=20)
    return json.loads(result.stdout)


def run(lab):
    helper = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_k8s_0908_001_runtime", helper)
    if spec is None or spec.loader is None:
        raise RuntimeError("The paired SAF-K8S-0908-001 runner is unavailable")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    image = runtime.load_runtime(lab)

    for account in (BASELINE, ALPHA, BETA):
        create(lab, "ServiceAccount", account, automountServiceAccountToken=True)
    for dataset, marker in MARKERS.items():
        create(lab, "ConfigMap", "fixture-training-" + dataset, immutable=True,
               data={"marker": marker})
    role(lab, "fixture-training-coarse-read", BASELINE)
    role(lab, "fixture-training-alpha-read", ALPHA, ["fixture-training-alpha"])
    role(lab, "fixture-training-beta-read", BETA, ["fixture-training-beta"])
    create(lab, "ConfigMap", CODE, immutable=True,
           data={"access_fixture.py": (HERE / "access_fixture.py").read_text()})
    create(lab, "PersistentVolumeClaim", PVC, spec={
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": "1Gi"}},
    })

    # Create every PVC consumer before waiting; default Kind storage binds on first use.
    launch(lab, SEED, "default", [], image, init=True)
    launch(lab, BASELINE, BASELINE, [GROUPS["alpha"], GROUPS["beta"]], image)
    for name in (SEED, BASELINE):
        lab.kubectl("wait", "--for=condition=Ready", "pod/" + name,
                    "--timeout=95s", timeout=105)

    coarse = observe(lab, BASELINE, "coarse")
    expected_coarse = {
        "identity": f"system:serviceaccount:{NS}:{BASELINE}",
        "api": {key: {"status": 200, "marker": value} for key, value in MARKERS.items()},
        "files": {key: {"allowed": True, "marker": value} for key, value in MARKERS.items()},
    }
    red_ok = coarse == expected_coarse
    lab.check("red", "The coarse baseline reads both synthetic training datasets at both boundaries",
              red_ok, coarse)

    mount = enforce_mount(lab, image)
    lab.check("green", "Native admission denies the coarse identity a fresh reference to the protected claim",
              all(mount.values()), mount)
    launch(lab, ALPHA, ALPHA, [GROUPS["alpha"]], image)
    launch(lab, BETA, BETA, [GROUPS["beta"]], image)
    for name in (ALPHA, BETA):
        lab.kubectl("wait", "--for=condition=Ready", "pod/"+name, "--timeout=95s", timeout=105)
    alpha = observe(lab, ALPHA, "alpha")
    beta = observe(lab, BETA, "beta")
    green = {
        "alpha_identity_and_partial_assignment": alpha == {
            "identity": f"system:serviceaccount:{NS}:{ALPHA}",
            "api": {"alpha": {"status": 200, "marker": MARKERS["alpha"]},
                    "beta": {"status": 403}},
            "files": {"alpha": {"allowed": True, "marker": MARKERS["alpha"]},
                      "beta": {"allowed": False, "error": "permission-denied"}}},
        "beta_identity_and_partial_assignment": beta == {
            "identity": f"system:serviceaccount:{NS}:{BETA}",
            "api": {"alpha": {"status": 403},
                    "beta": {"status": 200, "marker": MARKERS["beta"]}},
            "files": {"alpha": {"allowed": False, "error": "permission-denied"},
                      "beta": {"allowed": True, "marker": MARKERS["beta"]}}},
    }
    lab.check("green", "Named-object RBAC and PVC file permissions deny only out-of-scope reads",
              all(green.values()), {"alpha": alpha, "beta": beta})

    positive = {
        "approved_api_reads_unchanged":
            alpha.get("api", {}).get("alpha") == coarse.get("api", {}).get("alpha")
            and beta.get("api", {}).get("beta") == coarse.get("api", {}).get("beta"),
        "approved_pvc_reads_unchanged":
            alpha.get("files", {}).get("alpha") == coarse.get("files", {}).get("alpha")
            and beta.get("files", {}).get("beta") == coarse.get("files", {}).get("beta"),
        "out_of_scope_denials_observed":
            alpha.get("api", {}).get("beta") == {"status": 403}
            and beta.get("api", {}).get("alpha") == {"status": 403}
            and alpha.get("files", {}).get("beta") == {"allowed": False, "error": "permission-denied"}
            and beta.get("files", {}).get("alpha") == {"allowed": False, "error": "permission-denied"},
    }
    lab.check("positive", "Each lawful identity keeps its approved reads with byte-for-byte marker parity",
              all(positive.values()), positive)
    (lab.evidence / "training-dataset-access-observations.json").write_text(json.dumps({
        "namespace": NS,
        "datasets": sorted(MARKERS),
        "boundaries": ["named-configmap-rbac", "case-owned-pvc-posix-groups"],
        "red_baseline": {"passed": red_ok},
        "green": green, "mount_admission": mount,
        "positive": positive,
    }, sort_keys=True, indent=2) + "\n")
