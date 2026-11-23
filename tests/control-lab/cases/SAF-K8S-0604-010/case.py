"""Build and promote a new runtime against unchanged model bytes."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

from fixtures import container

HERE = Path(__file__).resolve().parent
MODEL = '{"format":"fixture-linear-v1","weights":[3,2]}\n'
MODEL_SHA = sha256(MODEL.encode()).hexdigest()
ARTIFACT = "saf-model-fixture-v1"
RELEASE = "saf-patch-runtime"
PROBE = "saf-patch-client"
APPROVAL = "saf-patch-approval"
SKOPEO = ("quay.io/skopeo/stable:v1.20.0@sha256:"
          "47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4")
SCOPE = (
    "Three real OCI image builds are checked in Kind against one unchanged immutable "
    "model artifact. In-cluster runtime probes verify the bytes and fixture computation. "
    "The automated gate holds incompatible or unapproved releases, performs a Deployment "
    "rollout by digest, and verifies rollback. Production triggers and compatibility coverage "
    "need separate evidence."
)


def load_registry():
    path = HERE.parent / "SAF-K8S-0605-002" / "image_admission.py"
    spec = importlib.util.spec_from_file_location("saf_runtime_registry", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.registry


def builds(registry):
    out = registry.work / "runtime-builds"
    out.mkdir(mode=0o755)
    (out / "ca.crt").write_bytes(registry.registry_ca.read_bytes())
    refs = {}
    for revision in ("initial", "patched", "incompatible"):
        local_tag = f"{registry.lab.cluster}-runtime:{revision}"
        archive = out / "image.tar"
        try:
            registry.docker("build", "--network", "none", "--build-arg", f"RUNTIME_REVISION={revision}",
                            "-t", local_tag, str(HERE / "runtime"), timeout=165)
            registry.docker("image", "save", "-o", str(archive), local_tag, timeout=110)
            repository = f"{registry.registry}/fixture/patch-runtime"
            registry.docker(
                "run", "--rm", "--network", "kind", "--cap-drop=ALL", "--volume", f"{out}:/io",
                SKOPEO, "copy", "--format", "oci", "--dest-cert-dir", "/io", "--digestfile", "/io/manifest.digest",
                "docker-archive:/io/image.tar", f"docker://{repository}:{revision}", timeout=140,
            )
            refs[revision] = repository + "@" + (out / "manifest.digest").read_text().strip()
        finally:
            registry.docker("image", "rm", local_tag, allow_failure=True)
            archive.unlink(missing_ok=True)
    if len(set(refs.values())) != 3:
        registry.lab.block("The registry did not retain three distinct runtime manifests")
    return refs


def trust(registry):
    node = registry.lab.cluster + "-control-plane"
    path = f"/etc/containerd/certs.d/{registry.registry}"
    hosts = registry.work / "runtime-hosts.toml"
    hosts.write_text(f'[host."https://{registry.registry}"]\n'
                     f'capabilities = ["pull", "resolve"]\nca = "{path}/ca.crt"\n')
    registry.docker("exec", node, "mkdir", "-p", path)
    registry.docker("cp", str(hosts), f"{node}:{path}/hosts.toml")
    registry.docker("cp", str(registry.registry_ca), f"{node}:{path}/ca.crt")


def deployment(lab, name, image):
    labels = {"app": name}
    lab.create({
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
        "spec": {"replicas": 1, "revisionHistoryLimit": 3, "selector": {"matchLabels": labels},
                 "template": {"metadata": {"labels": labels}, "spec": {
                     "automountServiceAccountToken": False,
                     "containers": [{
                         "name": "runtime", "image": image, "imagePullPolicy": "Always",
                         "env": [{"name": "SAF_EXPECTED_MODEL", "value": MODEL_SHA}],
                         "readinessProbe": {"httpGet": {"path": "/probe", "port": 8080}, "periodSeconds": 1},
                         "volumeMounts": [{"name": "model", "mountPath": "/model", "readOnly": True}],
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                             "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}},
                     }],
                     "volumes": [{"name": "model", "configMap": {"name": ARTIFACT}}],
                 }}},
    })
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name}, "spec": {
        "type": "ClusterIP", "selector": labels, "ports": [{"port": 8080, "targetPort": 8080}],
    }})
    ready(lab, name)


def ready(lab, name):
    lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=85s", timeout=95)


def current(lab):
    result = json.loads(lab.kubectl("get", "deployment", RELEASE, "-o", "json").stdout)
    return {"image": result["spec"]["template"]["spec"]["containers"][0]["image"],
            "revision": result["metadata"]["annotations"]["deployment.kubernetes.io/revision"]}


def probe(lab, name, marker, ref):
    result = lab.kubectl("exec", PROBE, "--", "sh", "-c",
                         f"i=0; while [ $i -lt 10 ]; do wget -qO- -T 3 http://{name}:8080/probe "
                         "&& exit 0; i=$((i+1)); sleep 1; done; exit 1", timeout=45)
    row = json.loads(result.stdout)
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"app={name}", "-o", "json").stdout)["items"]
    if not any(not pod["metadata"].get("deletionTimestamp") and
               any(container_status.get("ready") and container_status["imageID"].endswith(ref.split("@")[1])
                   for container_status in pod["status"].get("containerStatuses", [])) for pod in pods):
        lab.block("The observed Deployment did not run the requested OCI manifest")
    if row.get("runtime") != marker or row.get("model_sha256") != MODEL_SHA:
        lab.block("The served marker and exact model digest were not observed")
    return row


def decision(lab, candidate, report, approval, baseline):
    if report["fixture_prediction"] != 16 or report["model_sha256"] != MODEL_SHA:
        return "incompatible"
    authorized = (approval is not None and approval.get("accepted") == "true"
                  and approval.get("runtime") == candidate and approval.get("model_sha256") == MODEL_SHA
                  and approval.get("previous_revision") == baseline["revision"])
    if not authorized:
        return "approval-missing-or-mismatched"
    change = [{"op": "test", "path": "/metadata/annotations/deployment.kubernetes.io~1revision",
               "value": baseline["revision"]},
              {"op": "test", "path": "/spec/template/spec/containers/0/image", "value": baseline["image"]},
              {"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": candidate}]
    lab.kubectl("patch", "deployment", RELEASE, "--type=json", "-p", json.dumps(change))
    return "deployed"


def exercise(lab, refs):
    original = lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": ARTIFACT},
                           "immutable": True, "data": {"model.json": MODEL}})
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": PROBE},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                         "containers": [container("client", command=["sh", "-c", "sleep 900"])]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{PROBE}", "--timeout=60s", timeout=70)
    deployment(lab, RELEASE, refs["initial"])
    before = current(lab)
    old = probe(lab, RELEASE, "initial", refs["initial"])
    lab.check("red", "The initial runtime is healthy and consumes the exact immutable model",
              old["fixture_prediction"] == 16 and before["image"] == refs["initial"],
              {"initial_prediction": old["fixture_prediction"], "exact_model": True})

    reports = {}
    for revision in ("patched", "incompatible"):
        name = f"saf-candidate-{revision}"
        deployment(lab, name, refs[revision])
        reports[revision] = probe(lab, name, revision, refs[revision])
    false_hit = decision(lab, refs["incompatible"], reports["incompatible"], None, before)
    no_approval = decision(lab, refs["patched"], reports["patched"], None, before)
    expected = {"accepted": "true", "runtime": refs["patched"], "model_sha256": MODEL_SHA,
                "previous_revision": before["revision"]}
    mismatched = decision(lab, refs["patched"], reports["patched"],
                          {**expected, "runtime": refs["incompatible"]}, before)
    remained = current(lab) == before and probe(lab, RELEASE, "initial", refs["initial"]) == old
    lab.check("green", "Incompatible computation and missing or mismatched approvals leave the healthy release intact",
              remained and false_hit == "incompatible" and no_approval == mismatched == "approval-missing-or-mismatched",
              {"real_incompatibility": false_hit, "unapproved": no_approval,
               "wrong_approval": mismatched, "same_healthy_revision": remained})

    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": APPROVAL},
                "immutable": True, "data": expected})
    stored = json.loads(lab.kubectl("get", "configmap", APPROVAL, "-o", "json").stdout)["data"]
    deployed = decision(lab, refs["patched"], reports["patched"], stored, before)
    ready(lab, RELEASE)
    after = current(lab)
    forward = probe(lab, RELEASE, "patched", refs["patched"])
    verified = deployed == "deployed" and after["revision"] != before["revision"]
    lab.check("green", "The approved changed image rolls out by digest with the same model and behavior",
              verified and forward == reports["patched"],
              {"new_revision": verified, "compatible_prediction": forward["fixture_prediction"], "exact_model": True})
    lab.kubectl("rollout", "undo", f"deployment/{RELEASE}", f"--to-revision={before['revision']}")
    ready(lab, RELEASE)
    restored = probe(lab, RELEASE, "initial", refs["initial"])
    model = json.loads(lab.kubectl("get", "configmap", ARTIFACT, "-o", "json").stdout)
    same = model["metadata"]["uid"] == original["metadata"]["uid"] and model["data"] == original["data"]
    final = current(lab)
    lab.check("positive", "Rollback restores the exact former runtime while retaining the same model object",
              restored == old and final["image"] == before["image"] and same,
              {"original_runtime_restored": restored == old, "same_model_object": same})
    (lab.evidence / "runtime-rollout-receipt.json").write_text(json.dumps({
        "initial": before, "promoted": after, "rolled_back": final,
        "model_sha256": MODEL_SHA, "model_uid": model["metadata"]["uid"], "candidates": reports,
    }, indent=2, sort_keys=True) + "\n")


def run(lab):
    with load_registry()(lab) as (registry, _, _):
        refs = builds(registry)
        trust(registry)
        exercise(lab, refs)
