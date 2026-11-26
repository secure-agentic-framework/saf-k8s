"""Verify prevention of new legacy token Secret objects with dry-run requests."""
from datetime import datetime
import json
from pathlib import Path
import time


HERE = Path(__file__).parent
RETIRE_NAMESPACE = "saf-0402-015-retirement"
RETIRE_SECRET = "saf-k8s-0402-015-linked-empty-retirement-sentinel"
RETIRE_SA = "saf-k8s-0402-015-nonexistent-retirement-sa"
HEALTH_POD = "saf-k8s-0402-015-retirement-health"
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
REJECTION = "Secret type kubernetes.io/service-account-token is not permitted for new Secrets"
SCOPE = (
    "Kubernetes v1.36.1 server-side dry runs of an empty synthetic legacy Secret and "
    "an inert Opaque Secret, with a namespace-scoped admission policy. The case also "
    "verifies the native tracking ConfigMap and a type-based inventory query. Credential "
    "migration and production scope remain separate. A case-owned Pod also makes one "
    "actual projected short-lived token read of a named inert ConfigMap over verified "
    "API-server HTTPS; the token and response body are never retained. "
    "Scratch supplement uses an isolated Kind control-plane profile with only the "
    "legacy service-account signer path explicitly empty, while projected TokenRequest "
    "credentials remain enabled. It proves deletion of an empty annotated sentinel; "
    "Secret data values are never observed."
)


def dry_run(lab, fixture):
    return lab.kubectl("create", "--dry-run=server", "-o", "name", "-f", str(HERE / "fixtures" / fixture),
                       allow_failure=True)


def run(lab):
    legacy = "legacy-token-secret-empty.yaml"
    ordinary = "ordinary-secret-inert.yaml"
    baseline = dry_run(lab, legacy)
    admitted = baseline.returncode == 0 and baseline.stdout.strip() == "secret/saf-k8s-0402-015-legacy-empty-probe"
    lab.check("red", "The API accepts the empty legacy shape in a dry run before policy",
              admitted, {"dry_run_admitted": admitted})
    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        tested = dry_run(lab, legacy)
        denied = tested.returncode != 0 and REJECTION in tested.stderr
        if denied or time.monotonic() >= deadline:
            break
        time.sleep(0.25)
    lab.check("green", "Admission rejects the same legacy Secret request on its type",
              denied, {"matched_legacy_type_denial": denied})
    other = dry_run(lab, ordinary)
    preserved = other.returncode == 0 and other.stdout.strip() == "secret/saf-k8s-0402-015-ordinary-inert-probe"
    lab.check("positive", "Admission allows an inert Opaque Secret in a dry run",
              preserved, {"ordinary_dry_run_admitted": preserved})
    legacy_names = lab.kubectl("get", "secrets", "--field-selector", "type=kubernetes.io/service-account-token",
                              "-o", "name").stdout.splitlines()
    all_names = lab.kubectl("get", "secrets", "-o", "name").stdout.splitlines()
    lab.check("positive", "The type query succeeds and neither dry run persists a Secret",
              not legacy_names and not all_names, {"legacy_objects": len(legacy_names), "all_objects": len(all_names)})
    started = lab.kubectl("-n", "kube-system", "get", "configmap",
                          "kube-apiserver-legacy-service-account-token-tracking", "-o", "jsonpath={.data.since}").stdout
    timestamp = datetime.fromisoformat(started.strip().replace("Z", "+00:00"))
    lab.check("positive", "The built-in tracking ConfigMap records a monitoring start date",
              timestamp.year >= 2023, {"tracking_start_present": True})

    # Scratch-only extension starts after the original five checks, preserving
    # their order and original assertion conditions. The separate namespace is
    # outside the exact saf-test CREATE policy selector.
    lab.kubectl("create", "namespace", RETIRE_NAMESPACE)
    # Verify the actual control-plane static Pod is running with exactly the
    # token-population controller excluded. Other controller defaults remain on.
    selected = lab.kubectl(
        "-n", "kube-system", "get", "pods", "-l", "component=kube-controller-manager",
        "-o", "jsonpath-as-json={.items[0].spec.containers[0].command}",
    ).stdout
    command, = json.loads(selected)
    controller_values = [arg.partition("=")[2] for arg in command if arg.startswith("--controllers=")]
    signer_values = [arg.partition("=")[2] for arg in command
                     if arg.startswith("--service-account-private-key-file=")]
    disabled_only = (controller_values == ["*,-serviceaccount-token-controller"]
                     and signer_values == [""])
    lab.check("positive", "The disposable controller-manager has the legacy signer path explicitly empty and excludes the legacy token controller",
              disabled_only, {"token_controller_excluded": controller_values == ["*,-serviceaccount-token-controller"],
                              "legacy_signer_path_empty": signer_values == [""]})

    missing_sa = lab.kubectl(
        "-n", RETIRE_NAMESPACE, "get", f"serviceaccount/{RETIRE_SA}", "-o", "name",
        allow_failure=True,
    )
    absent_sa = missing_sa.returncode != 0 and "(NotFound)" in missing_sa.stderr
    lab.check("positive", "The synthetic token Secret references no existing ServiceAccount",
              absent_sa, {"referenced_serviceaccount_absent": absent_sa})

    created_secret = lab.kubectl(
        "-n", RETIRE_NAMESPACE, "create", "-f",
        str(HERE / "fixtures" / "retirement-empty-annotated.yaml"), "-o", "name",
    )
    identity = lab.kubectl(
        "-n", RETIRE_NAMESPACE, "get", "secret", RETIRE_SECRET, "-o",
        "jsonpath={.metadata.name}:{.type}:{.metadata.uid}",
    ).stdout.strip()
    data_keys = lab.kubectl(
        "-n", RETIRE_NAMESPACE, "get", "secret", RETIRE_SECRET, "-o",
        "go-template={{if .data}}{{len .data}}{{else}}0{{end}}",
    ).stdout.strip()
    name, separator, suffix = identity.partition(":")
    secret_type, separator2, uid = suffix.partition(":")
    visible = (
        created_secret.stdout.strip() == f"secret/{RETIRE_SECRET}"
        and separator and separator2 and name == RETIRE_SECRET
        and secret_type == "kubernetes.io/service-account-token" and bool(uid) and data_keys == "0"
    )
    lab.check("positive", "The empty annotated sentinel persists and is inventoried by metadata only",
              visible, {"exact_name_and_type_visible": visible, "uid_present": bool(uid),
                        "data_key_count_zero": data_keys == "0"})

    lab.kubectl(
        "-n", RETIRE_NAMESPACE, "create", "-f",
        str(HERE / "fixtures" / "retirement-health-pod.yaml"), "-o", "name",
    )
    lab.kubectl("-n", RETIRE_NAMESPACE, "wait", "--for=condition=Ready",
                f"pod/{HEALTH_POD}", "--timeout=90s", timeout=100)
    before = lab.kubectl(
        "-n", RETIRE_NAMESPACE, "get", f"pod/{HEALTH_POD}", "-o",
        "jsonpath={.status.phase}:{.status.containerStatuses[0].ready}:{.spec.automountServiceAccountToken}",
    ).stdout.strip()
    healthy_before = before == "Running:true:false"
    lab.check("positive", "The benign comparator Pod is Ready with token automount disabled",
              healthy_before, {"running_ready_automount_disabled": healthy_before})

    deleted = lab.kubectl("-n", RETIRE_NAMESPACE, "delete", f"secret/{RETIRE_SECRET}", "--wait=true")
    still_present = lab.kubectl(
        "-n", RETIRE_NAMESPACE, "get", "secret", RETIRE_SECRET, "-o", "name",
        allow_failure=True,
    )
    retired = deleted.returncode == 0 and still_present.returncode != 0
    lab.check("positive", "The exact empty sentinel is deleted and absent by metadata name",
              retired, {"delete_succeeded": deleted.returncode == 0,
                        "exact_name_absent": still_present.returncode != 0})

    after = lab.kubectl(
        "-n", RETIRE_NAMESPACE, "get", f"pod/{HEALTH_POD}", "-o",
        "jsonpath={.status.phase}:{.status.containerStatuses[0].ready}:{.spec.automountServiceAccountToken}",
    ).stdout.strip()
    healthy_after = after == "Running:true:false"
    lab.check("positive", "The benign comparator Pod remains Ready after sentinel retirement",
              healthy_after, {"running_ready_automount_disabled": healthy_after})

    # One bounded positive Request to a namespaced, inert ConfigMap using an
    # explicitly projected short-lived token and the namespace API CA.
    add_projected_read(lab)


def add_projected_read(lab):
    import re

    def create_owned(resource):
        return lab.kubectl("-n", RETIRE_NAMESPACE, "create", "-f", "-", "-o", "json",
                           payload=json.dumps(resource))

    sa = "saf-k8s-0402-015-projected-reader"
    target = "saf-k8s-0402-015-projected-read-marker"
    role = "saf-k8s-0402-015-projected-reader"
    pod = "saf-k8s-0402-015-projected-read"
    probe_cm = "saf-k8s-0402-015-projected-read-probe"
    # Determine the API audience from the actual API-server configuration,
    # without retaining or printing any credential material.
    raw = lab.kubectl("-n", "kube-system", "get", "pods", "-l", "component=kube-apiserver",
                      "-o", "jsonpath-as-json={.items[0].spec.containers[0].command}").stdout
    api_command, = json.loads(raw)
    audiences = [arg.partition("=")[2] for arg in api_command if arg.startswith("--api-audiences=")]
    issuers = [arg.partition("=")[2] for arg in api_command if arg.startswith("--service-account-issuer=")]
    audience = (audiences[0].split(",")[0] if audiences and audiences[0]
                else issuers[0].split(",")[0] if issuers and issuers[0] else "")
    audience_ok = bool(audience and re.fullmatch(r"https://[^\s,]+", audience))
    if not audience_ok:
        lab.block("Could not determine a configured HTTPS ServiceAccount API audience")

    create_owned({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": target, "namespace": RETIRE_NAMESPACE,
                             "labels": {"saf-k8s.example/fixture": "0402-015"}},
                "data": {"marker": "owned-projected-read-marker"}})
    create_owned({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": sa, "namespace": RETIRE_NAMESPACE},
                "automountServiceAccountToken": False})
    create_owned({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": role, "namespace": RETIRE_NAMESPACE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [target],
                           "verbs": ["get"]}]})
    create_owned({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": role, "namespace": RETIRE_NAMESPACE},
                "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": RETIRE_NAMESPACE}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role}})
    probe = (Path(__file__).parent / "projected_read_probe.py").read_text(encoding="utf-8")
    create_owned({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": probe_cm, "namespace": RETIRE_NAMESPACE},
                "data": {"probe.py": probe}})
    image = ("docker.io/library/python:3.13-slim@sha256:"
             "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
    create_owned({"apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": pod, "namespace": RETIRE_NAMESPACE,
                             "labels": {"saf-k8s.example/fixture": "0402-015-projected-read"}},
                "spec": {"restartPolicy": "Never", "serviceAccountName": sa,
                         "automountServiceAccountToken": False,
                         "containers": [{"name": "reader", "image": image,
                                          "command": ["python", "-c", "import time; time.sleep(3600)"],
                                          "env": [{"name": "SAF_NAMESPACE", "value": RETIRE_NAMESPACE},
                                                  {"name": "SAF_TARGET", "value": target}],
                                          "securityContext": {"allowPrivilegeEscalation": False,
                                                              "capabilities": {"drop": ["ALL"]},
                                                              "runAsNonRoot": True, "runAsUser": 10001,
                                                              "readOnlyRootFilesystem": True,
                                                              "seccompProfile": {"type": "RuntimeDefault"}},
                                          "volumeMounts": [{"name": "identity", "mountPath": "/var/run/saf-projected",
                                                            "readOnly": True},
                                                           {"name": "probe", "mountPath": "/fixture",
                                                            "readOnly": True}]}],
                         "volumes": [{"name": "identity", "projected": {"sources": [
                             {"serviceAccountToken": {"audience": audience, "expirationSeconds": 600,
                                                       "path": "token"}},
                             {"configMap": {"name": "kube-root-ca.crt",
                                             "items": [{"key": "ca.crt", "path": "ca.crt"}]}}]}},
                                     {"name": "probe", "configMap": {"name": probe_cm}}]}})
    lab.kubectl("-n", RETIRE_NAMESPACE, "wait", "--for=condition=Ready", f"pod/{pod}",
                "--timeout=90s", timeout=100)
    pod_spec = json.loads(lab.kubectl("-n", RETIRE_NAMESPACE, "get", "pod", pod, "-o", "json").stdout)
    volumes = pod_spec["spec"]["volumes"]
    token_sources = [source["serviceAccountToken"] for volume in volumes
                     if "projected" in volume for source in volume["projected"]["sources"]
                     if "serviceAccountToken" in source]
    projected = (pod_spec["spec"]["serviceAccountName"] == sa
                 and pod_spec["spec"].get("automountServiceAccountToken") is False
                 and len(token_sources) == 1
                 and token_sources[0] == {"audience": audience, "expirationSeconds": 600, "path": "token"}
                 and any("configMap" in source and source["configMap"].get("name") == "kube-root-ca.crt"
                         for volume in volumes if "projected" in volume
                         for source in volume["projected"]["sources"]))
    output = lab.kubectl("-n", RETIRE_NAMESPACE, "exec", pod, "--", "python", "-B",
                         "/fixture/probe.py", timeout=30).stdout.strip()
    try:
        observed = json.loads(output)
    except json.JSONDecodeError:
        observed = {}
    # Verify the exact grant is limited to one resource name and GET only.
    rules = json.loads(lab.kubectl("-n", RETIRE_NAMESPACE, "get", "role", role, "-o", "json").stdout)["rules"]
    grant = rules == [{"apiGroups": [""], "resources": ["configmaps"],
                       "resourceNames": [target], "verbs": ["get"]}]
    success = projected and grant and observed == {"body_retained": False, "https_status": 200}
    lab.check("positive", "A case-owned Pod uses one 600-second projected token and API CA for an HTTPS GET of its named inert ConfigMap",
              success, {"explicit_projection_and_ca": projected, "single_named_get_grant": grant,
                        "https_status_200": observed.get("https_status") == 200,
                        "token_or_response_body_emitted": False})
