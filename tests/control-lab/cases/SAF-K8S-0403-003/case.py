"""Verify live Secret volume, subPath, and init-only delivery behavior and admission."""

import json
import time

from fixtures import container, pod, ready

NS = "saf-test"
SECRET = "fixture-injection-marker"
VOLUME = "fixture-secret"
LABEL = "saf.example.org/delivery-class"
POLICY = "fixture-live-secret-mount.saf.example.org"
MESSAGE = "fresh-file class requires a read-only directory mount of the approved Secret volume"
WORKLOAD = "fixture-injection-comparison"
OLD = "public-marker-one"
NEW = "public-marker-two"
SCOPE = (
    "Exercise actual Kubernetes Secret directory refresh, subPath and init-copy snapshots, "
    "filesystem access and scoped admission. Published markers are public synthetic values. "
    "CSI, external injectors, sidecars and production workload behavior need distinct evidence."
)


def mount(path, **options):
    return {"name": VOLUME, "mountPath": path, "readOnly": True, **options}


def workload(name, mounts, *, compare=False):
    app_mounts = list(mounts)
    if compare:
        app_mounts.append({"name": "snapshot", "mountPath": "/copy", "readOnly": True})
    targets = [container("app", command=["sh", "-c", "sleep 360"], volumeMounts=app_mounts)]
    volumes = [{"name": VOLUME, "secret": {"secretName": SECRET, "defaultMode": 0o440}}]
    extras = {}
    if compare:
        targets.append(container("no-mount", command=["sh", "-c", "sleep 360"]))
        volumes.append({"name": "snapshot", "emptyDir": {}})
        extras["initContainers"] = [container("snapshot-init", command=["sh", "-ec", "cp /source/value /copy/value"],
                                             volumeMounts=[mount("/source"), {"name": "snapshot", "mountPath": "/copy"}])]
    return pod(name, targets, volumes=volumes, automountServiceAccountToken=False,
               securityContext={"fsGroup": 65534}, **extras)


def apply_policy(lab):
    api = "admissionregistration.k8s.io/v1"
    validations = [
        f"has(object.spec.volumes) && object.spec.volumes.exists(v, v.name == '{VOLUME}' && has(v.secret) && v.secret.secretName == '{SECRET}')",
        "object.spec.containers.exists(c, c.name == 'app' && has(c.volumeMounts) && "
        f"c.volumeMounts.exists(m, m.name == '{VOLUME}' && m.mountPath == '/live' && m.readOnly && "
        "(!has(m.subPath) || m.subPath == '') && (!has(m.subPathExpr) || m.subPathExpr == '')))",
    ]
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}]},
                    "validations": [{"expression": expr, "message": MESSAGE} for expr in validations]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {LABEL: "fresh-file"}}}}})


def from_container(lab, name, unit, *args, allow_failure=False):
    return lab.kubectl("exec", name, "-c", unit, "--", *args, allow_failure=allow_failure)


def values(lab):
    return from_container(lab, WORKLOAD, "app", "cat", "/live/value", "/tmp/via-subpath", "/copy/value").stdout.splitlines()


def app_instance(lab):
    doc = json.loads(lab.kubectl("get", "pod/" + WORKLOAD, "-o", "json").stdout)
    app = next(status for status in doc["status"]["containerStatuses"] if status["name"] == "app")
    return (doc["metadata"]["uid"], app["containerID"], app["restartCount"])


def run(lab):
    lab.create({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": SECRET},
                "stringData": {"value": OLD + "\n"}})
    lab.kubectl("label", "namespace", NS, f"{LABEL}=fresh-file")
    stale_spec = workload("fixture-fresh-subpath", [mount("/live", subPath="value")])
    stale_admitted = lab.create(stale_spec, dry_run=True, allow_failure=True).returncode == 0
    lab.create(workload(WORKLOAD, [mount("/live"), mount("/tmp/via-subpath", subPath="value")], compare=True))
    ready(lab, WORKLOAD)
    before = values(lab)
    instance = app_instance(lab)
    file_mode = from_container(lab, WORKLOAD, "app", "stat", "-Lc", "%a:%g", "/live/value").stdout.strip()
    unmounted = from_container(lab, WORKLOAD, "no-mount", "test", "!", "-e", "/live/value",
                               allow_failure=True).returncode == 0
    lab.check("red", "The subPath declaration is initially admitted and all three fixture read paths see the initial version",
              stale_admitted and before == [OLD, OLD, OLD],
              {"unrestricted_subpath_dry_run_admitted": stale_admitted, "before_all_three_initial": before == [OLD, OLD, OLD]})

    apply_policy(lab)
    deadline = time.monotonic() + 25
    stale_denied = False
    while time.monotonic() < deadline:
        result = lab.create(stale_spec, dry_run=True, allow_failure=True)
        stale_denied = result.returncode != 0 and POLICY in result.stderr and MESSAGE in result.stderr
        if stale_denied:
            break
        time.sleep(.4)
    missing = lab.create(workload("fixture-fresh-no-mount", []), dry_run=True, allow_failure=True)
    missing_denied = missing.returncode != 0 and POLICY in missing.stderr and MESSAGE in missing.stderr
    approved = "fixture-approved-fresh"
    lab.create(workload(approved, [mount("/live")]))
    ready(lab, approved)
    marker = from_container(lab, approved, "app", "cat", "/live/value").stdout.strip()
    lab.check("green", "The selected workload class rejects stale and missing mounts, while an approved live mount works",
              stale_denied and missing_denied and marker == OLD and file_mode == "440:65534" and unmounted,
              {"matched_subpath_denial": stale_denied, "matched_missing_mount_denial": missing_denied,
               "approved_reads_marker": marker == OLD, "file_mode_and_group": file_mode, "unmounted_probe_inaccessible": unmounted})

    lab.kubectl("patch", "secret/" + SECRET, "--type=merge", "-p", json.dumps({"stringData": {"value": NEW + "\n"}}),
                "-o", "name")
    lab.kubectl("annotate", "pod/" + WORKLOAD, "saf.example.org/refresh-probe=source-updated")
    deadline = time.monotonic() + 90
    current = before
    while time.monotonic() < deadline:
        current = values(lab)
        if current and current[0] == NEW:
            break
        time.sleep(1)
    same_instance = app_instance(lab) == instance
    lab.check("positive", "The live directory updates in the same container, while subPath and the init copy retain the first version",
              current == [NEW, OLD, OLD] and same_instance,
              {"live_directory_updated": current[0] == NEW, "subpath_unchanged": current[1] == OLD,
               "init_copy_unchanged": current[2] == OLD, "same_pod_and_container": same_instance})
    (lab.evidence / "secret-injection-observations.json").write_text(json.dumps({
        "original_subpath_admitted": stale_admitted, "scoped_subpath_denied": stale_denied,
        "scoped_missing_mount_denied": missing_denied, "approved_mount_effective": marker == OLD,
        "native_directory_updated": current[0] == NEW, "subpath_retains_snapshot": current[1] == OLD,
        "init_copy_remains_snapshot": current[2] == OLD, "pod_and_container_unchanged": same_instance,
        "mode_and_group": file_mode, "unmounted_probe_inaccessible": unmounted,
    }, indent=2) + "\n")
