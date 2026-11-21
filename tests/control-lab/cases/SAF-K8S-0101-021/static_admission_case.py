"""Compare API-based and manifest-based admission on stock Kubernetes v1.37."""
from contextlib import contextmanager
import json
from pathlib import Path
import runpy
import tempfile

HERE = Path(__file__).parent
BASE = runpy.run_path(str(HERE / "case.py"))
NODE_IMAGE = (
    "kindest/node:v1.37.0@sha256:"
    "a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
)
API_CONFIG_DESTINATION = "/etc/kubernetes/saf-admission-config.yaml"
POLICY_DIR_DESTINATION = "/etc/kubernetes/saf-admission-policies"
NAMESPACE = "saf-release-review"
DENIED_CONFIGMAP = "saf-release-denied-configmap"
ALLOWED_CONFIGMAP = "saf-release-allowed-configmap"
PROTECTED_POLICY = "saf-release-protected-dynamic"
ORDINARY_POLICY = "saf-release-ordinary-dynamic"
STATIC_CONFIGMAP_POLICY = "saf-release-configmap.static.k8s.io"
STATIC_PROTECTION_POLICY = "saf-release-policy-protection.static.k8s.io"
SCOPE = (
    BASE["SCOPE"] + " This release-review wrapper also compares stock and "
    "manifest-based Kubernetes v1.37.0 admission using the exact pinned kind node "
    "image. Its probes are limited to two named synthetic ConfigMaps and two "
    "named disposable ValidatingAdmissionPolicy API objects. No webhooks or "
    "external targets are contacted."
)


def kubectl(lab, cluster, kubeconfig, *args, payload=None, allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
        "--request-timeout=40s", *args, payload=payload, timeout=45,
        allow_failure=allow_failure,
    )


def policy_manifests():
    """Return two static policies and bindings scoped to the lab fixtures."""
    return f'''apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: {STATIC_CONFIGMAP_POLICY}
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      operations: ["CREATE", "UPDATE"]
      resources: ["configmaps"]
      scope: Namespaced
    namespaceSelector:
      matchLabels:
        saf-k8s.example/release-review: "true"
  validations:
  - expression: object.metadata.name != "{DENIED_CONFIGMAP}"
    message: "the named release-review ConfigMap is denied"
    reason: Forbidden
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: saf-release-configmap-binding.static.k8s.io
spec:
  policyName: {STATIC_CONFIGMAP_POLICY}
  validationActions: [Deny]
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: {STATIC_PROTECTION_POLICY}
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups: ["admissionregistration.k8s.io"]
      apiVersions: ["v1"]
      operations: ["UPDATE", "DELETE"]
      resources: ["validatingadmissionpolicies"]
      scope: Cluster
  validations:
  - expression: oldObject.metadata.name != "{PROTECTED_POLICY}"
    message: "the named release-review policy is protected"
    reason: Forbidden
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: saf-release-policy-protection-binding.static.k8s.io
spec:
  policyName: {STATIC_PROTECTION_POLICY}
  validationActions: [Deny]
'''


def admission_configuration():
    return f'''apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: ValidatingAdmissionPolicy
  configuration:
    apiVersion: apiserver.config.k8s.io/v1
    kind: ValidatingAdmissionPolicyConfiguration
    staticManifestsDir: {POLICY_DIR_DESTINATION}
'''


def kind_configuration(admission_file, policy_dir):
    # Host-to-node and node-to-apiserver mounts are both read-only.
    return f'''kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(admission_file))}
    containerPath: {API_CONFIG_DESTINATION}
    readOnly: true
  - hostPath: {json.dumps(str(policy_dir))}
    containerPath: {POLICY_DIR_DESTINATION}
    readOnly: true
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta4
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
    - name: admission-control-config-file
      value: {API_CONFIG_DESTINATION}
    extraVolumes:
    - name: saf-admission-configuration
      hostPath: {API_CONFIG_DESTINATION}
      mountPath: {API_CONFIG_DESTINATION}
      readOnly: true
      pathType: File
    - name: saf-static-admission-policies
      hostPath: {POLICY_DIR_DESTINATION}
      mountPath: {POLICY_DIR_DESTINATION}
      readOnly: true
      pathType: DirectoryOrCreate
'''


@contextmanager
def v137_profile(lab, suffix, with_static_policies):
    cluster = f"{lab.cluster}-release-{suffix}"
    existing = set(lab.command("kind", "get", "clusters").stdout.splitlines())
    if cluster in existing:
        lab.block(f"Case-owned cluster name already exists: {cluster}")

    with tempfile.TemporaryDirectory(prefix=f"saf-release-{suffix}-") as temp:
        root = Path(temp).resolve()
        kubeconfig = root / "kubeconfig"
        admission_file = root / "AdmissionConfiguration.yaml"
        policy_dir = root / "validating-policies"
        policy_dir.mkdir()
        if with_static_policies:
            (policy_dir / "release-review.yaml").write_text(policy_manifests())
            admission_file.write_text(admission_configuration())
            config = kind_configuration(admission_file, policy_dir)
        else:
            # Stock profile has no admission-control-config-file or static manifests.
            config = "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
        kind_file = root / "kind.yaml"
        kind_file.write_text(config)
        attempted = False
        try:
            attempted = True
            lab.command(
                "kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                "--config", str(kind_file), "--kubeconfig", str(kubeconfig), "--wait", "90s",
                timeout=480,
            )
            version = json.loads(kubectl(lab, cluster, kubeconfig, "get", "--raw", "/version").stdout)
            if version.get("gitVersion") != "v1.37.0":
                lab.block(f"Expected Kubernetes v1.37.0 in {cluster}, got {version.get('gitVersion')}")
            pod = json.loads(kubectl(
                lab, cluster, kubeconfig, "-n", "kube-system", "get",
                f"pod/kube-apiserver-{cluster}-control-plane", "-o", "json",
            ).stdout)
            containers = [row for row in pod["spec"]["containers"]
                          if row.get("name") == "kube-apiserver"]
            if len(containers) != 1:
                lab.block(f"Could not identify kube-apiserver in {cluster}")
            args = containers[0].get("command") or []
            config_args = BASE["parse_flags"](args, "--admission-control-config-file")
            expected_config = [API_CONFIG_DESTINATION] if with_static_policies else []
            lab.check(
                "green" if with_static_policies else "red",
                "The v1.37 API server starts with the expected manifest admission configuration",
                config_args == expected_config,
                {"image": NODE_IMAGE, "server": version.get("gitVersion"),
                 "admission_control_config_file": config_args},
            )
            kubectl(lab, cluster, kubeconfig, "create", "namespace", NAMESPACE)
            kubectl(lab, cluster, kubeconfig, "label", f"namespace/{NAMESPACE}",
                    "saf-k8s.example/release-review=true")
            yield cluster, kubeconfig
        finally:
            if attempted:
                result = lab.command(
                    "kind", "delete", "cluster", "--name", cluster,
                    "--kubeconfig", str(kubeconfig), timeout=90, allow_failure=True,
                )
                remaining = set(lab.command("kind", "get", "clusters").stdout.splitlines())
                if result.returncode or cluster in remaining:
                    lab.block(f"Could not confirm cleanup of case-owned cluster {cluster}")


def configmap(name):
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
            "data": {"fixture": "synthetic release-review probe"}}


def configmap_probe(lab, cluster, kubeconfig, name, allowed, phase, description):
    result = kubectl(
        lab, cluster, kubeconfig, "-n", NAMESPACE, "create", "-f", "-",
        "--dry-run=server", "-o", "name", payload=json.dumps(configmap(name)),
        allow_failure=True,
    )
    message = result.stderr.strip()
    if allowed:
        matched = result.returncode == 0 and f"configmap/{name}" in result.stdout
    else:
        matched = (result.returncode != 0 and "(Forbidden)" in message
                   and STATIC_CONFIGMAP_POLICY in message and name in message)
    lab.check(phase, description, matched,
              {"name": name, "returncode": result.returncode,
               "accepted": result.returncode == 0, "message": message})


def dynamic_policy(name):
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": name},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"],
                "operations": ["CREATE"], "resources": ["configmaps"],
                "scope": "Namespaced",
            }]},
            "validations": [{"expression": "true"}],
        },
    }


def policy_write(lab, cluster, kubeconfig, operation, name, allowed, phase, description):
    result = kubectl(
        lab, cluster, kubeconfig, operation, "validatingadmissionpolicy", name,
        *(["--overwrite"] if operation == "annotate" else []),
        *(["saf-k8s.example/release-review-change=attempted"] if operation == "annotate" else []),
        allow_failure=True,
    )
    message = result.stderr.strip()
    if allowed:
        matched = result.returncode == 0
    else:
        matched = (result.returncode != 0 and "(Forbidden)" in message
                   and STATIC_PROTECTION_POLICY in message and name in message)
    lab.check(phase, description, matched,
              {"name": name, "operation": operation, "returncode": result.returncode,
               "allowed": result.returncode == 0, "message": message})


def api_policy_create(lab, cluster, kubeconfig, name):
    kubectl(lab, cluster, kubeconfig, "create", "-f", "-",
            payload=json.dumps(dynamic_policy(name)))


def run(lab):
    # Keep the original v1.36.1 admission-chain and LimitRanger assessment intact.
    BASE["run"](lab)

    with v137_profile(lab, "stock", with_static_policies=False) as (cluster, kubeconfig):
        configmap_probe(
            lab, cluster, kubeconfig, DENIED_CONFIGMAP, True, "red",
            "Stock v1.37.0 accepts a server-side dry-run of the exact synthetic ConfigMap",
        )
        configmap_probe(
            lab, cluster, kubeconfig, ALLOWED_CONFIGMAP, True, "positive",
            "Stock v1.37.0 also permits a separately named ordinary synthetic ConfigMap",
        )
        api_policy_create(lab, cluster, kubeconfig, PROTECTED_POLICY)
        policy_write(lab, cluster, kubeconfig, "annotate", PROTECTED_POLICY, True, "red",
                     "Stock v1.37.0 permits an administrator to update the disposable dynamic policy")
        policy_write(lab, cluster, kubeconfig, "delete", PROTECTED_POLICY, True, "red",
                     "Stock v1.37.0 permits an administrator to delete the disposable dynamic policy")

    with v137_profile(lab, "static", with_static_policies=True) as (cluster, kubeconfig):
        dynamic_objects = kubectl(lab, cluster, kubeconfig, "get",
                                  "validatingadmissionpolicies", "-o", "name").stdout.splitlines()
        lab.check("positive", "Startup profile has no API-hosted validating policy before the denial probe",
                  not dynamic_objects, {"api_hosted_policies": len(dynamic_objects)})
        configmap_probe(
            lab, cluster, kubeconfig, DENIED_CONFIGMAP, False, "green",
            "Startup-loaded file policy denies the exact synthetic ConfigMap",
        )
        configmap_probe(
            lab, cluster, kubeconfig, ALLOWED_CONFIGMAP, True, "positive",
            "The same file policy permits a separately named ordinary synthetic ConfigMap",
        )
        api_policy_create(lab, cluster, kubeconfig, PROTECTED_POLICY)
        policy_write(lab, cluster, kubeconfig, "annotate", PROTECTED_POLICY, False, "green",
                     "Static protection denies update of the specifically named dynamic policy")
        policy_write(lab, cluster, kubeconfig, "delete", PROTECTED_POLICY, False, "green",
                     "Static protection denies deletion of the specifically named dynamic policy")

        api_policy_create(lab, cluster, kubeconfig, ORDINARY_POLICY)
        policy_write(lab, cluster, kubeconfig, "annotate", ORDINARY_POLICY, True, "positive",
                     "The static protection rule permits update of a separately named expendable API policy")
        policy_write(lab, cluster, kubeconfig, "delete", ORDINARY_POLICY, True, "positive",
                     "The static protection rule permits deletion of the separately named expendable API policy")
        configmap_probe(
            lab, cluster, kubeconfig, DENIED_CONFIGMAP, False, "green",
            "The named ConfigMap remains denied after ordinary API policy changes",
        )
        configmap_probe(
            lab, cluster, kubeconfig, ALLOWED_CONFIGMAP, True, "positive",
            "An ordinary ConfigMap remains permitted after ordinary API policy changes",
        )
