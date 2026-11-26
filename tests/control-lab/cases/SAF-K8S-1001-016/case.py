"""Exercise native audit-policy selection with inert, case-owned CRD requests."""

import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
FIXTURES = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
NAMESPACE = FIXTURES["namespace"]
OTHER_NAMESPACE = NAMESPACE + "-outside"
SCOPE = (
    "Two case-owned disposable kind Kubernetes v1.36.1 clusters: an intentionally incomplete "
    "red audit policy and a green policy with five explicit Request-level synthetic AI-family rules plus a "
    "Metadata catch-all. Exact ResponseComplete audit-file events are correlated to successful "
    "case-owned API creates, patches, fallback reads, and a harmless ConfigMap control. The "
    "green policy additionally captures actual update and delete verbs on these synthetic objects "
    "and verifies a metadata-only same-resource create in a second owned namespace. "
    "The fixtures are invented CRDs, including a proxy GpuClaim; they are not real AI products, "
    "GPU plugin APIs, or production audit policy. Request bodies are inert fixture markers, and "
    "fallback events contain only metadata. No response bodies are logged."
)

# Each entry represents only the catalog's category label. Names, groups, and schemas are invented.
FAMILIES = FIXTURES["families"]


def audit_policy(green: bool) -> dict:
    rules = []
    if green:
        for family in FAMILIES:
            resources = [family["plural"]]
            if "also" in family:
                resources.append(family["also"]["plural"])
            rules.append({
                "level": "Request",
                "namespaces": [NAMESPACE],
                "verbs": ["create", "update", "patch", "delete"],
                "resources": [{"group": family["group"], "resources": resources}],
            })
        # A name-scoped exclusion checks first-match order without suppressing the other reads.
        rules.append({
            "level": "None", "namespaces": [NAMESPACE], "verbs": ["get"],
            "resources": [{"group": "", "resources": ["configmaps"],
                           "resourceNames": [FIXTURES["controls"]["negative_resource_name"]]}],
        })
        rules.append({"level": "Metadata"})
    else:
        # A positive control proves the audit backend is live. All other API requests
        # fall through to None, including all invented AI-family resources.
        rules.extend([
            {"level": "Metadata", "namespaces": [NAMESPACE], "verbs": ["create"],
             "resources": [{"group": "", "resources": ["configmaps"]}]},
            {"level": "None"},
        ])
    return {"apiVersion": "audit.k8s.io/v1", "kind": "Policy",
            "omitStages": ["RequestReceived"], "rules": rules}


def prepare_kind(lab, temporary: Path) -> Path:
    # This is the runner-owned green cluster. Red is created and deleted explicitly in run().
    policy = temporary / "green-audit-policy.json"
    policy.write_text(json.dumps(audit_policy(True)), encoding="utf-8")
    audit_dir = temporary / "green-audit"
    audit_dir.mkdir()
    return _kind_config(temporary, policy, audit_dir, "green")


def _kind_config(temporary: Path, policy: Path, audit_dir: Path, label: str) -> Path:
    config = temporary / f"{label}-kind.yaml"
    # JSON is valid YAML. JSON quoting keeps temporary host paths unambiguous.
    config.write_text(
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n  - role: control-plane\n    extraMounts:\n"
        f"      - hostPath: {json.dumps(str(policy))}\n"
        "        containerPath: /etc/kubernetes/audit-policy.json\n        readOnly: true\n"
        f"      - hostPath: {json.dumps(str(audit_dir))}\n"
        "        containerPath: /var/log/kubernetes/audit\n        readOnly: false\n"
        "kubeadmConfigPatches:\n  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n    kind: ClusterConfiguration\n"
        "    apiServer:\n      extraArgs:\n"
        "        - name: audit-policy-file\n          value: /etc/kubernetes/audit-policy.json\n"
        "        - name: audit-log-path\n          value: /var/log/kubernetes/audit/audit.log\n"
        "        - name: audit-log-mode\n          value: blocking\n"
        "      extraVolumes:\n"
        "        - name: audit-policy\n          hostPath: /etc/kubernetes/audit-policy.json\n"
        "          mountPath: /etc/kubernetes/audit-policy.json\n"
        "          readOnly: true\n          pathType: File\n"
        "        - name: audit-log\n          hostPath: /var/log/kubernetes/audit\n"
        "          mountPath: /var/log/kubernetes/audit\n"
        "          readOnly: false\n          pathType: DirectoryOrCreate\n",
        encoding="utf-8",
    )
    return config


def _resource(group: str, version: str, kind: str, name: str, marker: str,
              namespace: str = NAMESPACE) -> dict:
    return {
        "apiVersion": f"{group}/{version}", "kind": kind,
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"fixtureMarker": marker},
    }


def _crds() -> list[dict]:
    definitions = []
    for family in FAMILIES:
        kinds = [(family["kind"], family["plural"])]
        if "also" in family:
            kinds.append((family["also"]["kind"], family["also"]["plural"]))
        for kind, plural in kinds:
            definitions.append({
                "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
                "metadata": {"name": f"{plural}.{family['group']}"},
                "spec": {
                    "group": family["group"], "scope": "Namespaced",
                    "names": {"plural": plural, "singular": plural[:-1], "kind": kind,
                              "listKind": f"{kind}List"},
                    "versions": [{"name": "v1alpha1", "served": True, "storage": True,
                                  "schema": {"openAPIV3Schema": {
                                      "type": "object", "properties": {
                                          "apiVersion": {"type": "string"},
                                          "kind": {"type": "string"},
                                          "spec": {"type": "object", "x-kubernetes-preserve-unknown-fields": True},
                                      }, "required": ["spec"]}}}],
                },
            })
    for probe in FIXTURES["selector_probes"]:
        definitions.append({
            "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
            "metadata": {"name": f"{probe['plural']}.{probe['group']}"},
            "spec": {
                "group": probe["group"], "scope": "Namespaced",
                "names": {"plural": probe["plural"], "singular": probe["plural"].rstrip("s"),
                          "kind": probe["kind"], "listKind": f"{probe['kind']}List"},
                "versions": [{"name": "v1alpha1", "served": True, "storage": True,
                              "schema": {"openAPIV3Schema": {
                                  "type": "object", "properties": {
                                      "apiVersion": {"type": "string"},
                                      "kind": {"type": "string"},
                                      "spec": {"type": "object", "x-kubernetes-preserve-unknown-fields": True},
                                  }, "required": ["spec"]}}}],
            },
        })
    return definitions


def _kubectl(lab, cluster: str, kubeconfig: Path, *args, timeout=45, payload=None, allow_failure=False):
    return lab.command("kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
                       f"--request-timeout={timeout - 5}s", *args, timeout=timeout,
                       payload=payload, allow_failure=allow_failure)


def _apply_json(lab, cluster: str, kubeconfig: Path, obj: dict) -> None:
    _kubectl(lab, cluster, kubeconfig, "apply", "-f", "-", payload=json.dumps(obj))


def _wait_ready(lab, cluster: str, kubeconfig: Path) -> None:
    for crd in _crds():
        _apply_json(lab, cluster, kubeconfig, crd)
    _kubectl(lab, cluster, kubeconfig, "wait", "--for=condition=Established",
             "--timeout=60s", "crd", *[f"{x['spec']['names']['plural']}.{x['spec']['group']}" for x in _crds()], timeout=70)


def _create(lab, cluster: str, kubeconfig: Path, resource: dict) -> None:
    _kubectl(lab, cluster, kubeconfig, "create", "-f", "-", "-o", "json",
             payload=json.dumps(resource))


def _audit_records(lab, path: Path) -> list[dict]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if path.is_file():
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            records = []
            for line in lines:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return records
        time.sleep(0.5)
    return []


def _matching(records: list[dict], *, name: str, resource: str, group: str, verb: str,
              namespace: str = NAMESPACE, uri_marker="") -> list[dict]:
    return [e for e in records if e.get("stage") == "ResponseComplete"
            and e.get("verb") == verb
            and uri_marker in e.get("requestURI", "")
            and (e.get("objectRef") or {}).get("name") == name
            and (e.get("objectRef") or {}).get("resource") == resource
            and (e.get("objectRef") or {}).get("apiGroup", "") == group
            and (e.get("objectRef") or {}).get("namespace") == namespace]


def _safe_event(event: dict) -> dict:
    if "responseObject" in event or (event.get("level") == "Metadata" and "requestObject" in event):
        raise AssertionError("Audit content exceeds the configured request or metadata level")
    return {key: event[key] for key in
            ("auditID", "stage", "verb", "requestURI", "level", "objectRef", "responseStatus",
             "requestObject") if key in event}


def _await_exact(lab, audit_path: Path, *, name: str, resource: str, group: str, verb: str,
                 namespace: str = NAMESPACE, uri_marker="") -> list[dict]:
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        found = _matching(_audit_records(lab, audit_path), name=name,
                          resource=resource, group=group, verb=verb,
                          namespace=namespace, uri_marker=uri_marker)
        if found:
            return found
        time.sleep(0.5)
    return []


def _set_namespace(lab, cluster: str, kubeconfig: Path) -> None:
    _kubectl(lab, cluster, kubeconfig, "create", "namespace", NAMESPACE)
    _kubectl(lab, cluster, kubeconfig, "wait", "--for=create", "serviceaccount/default",
             "--namespace", NAMESPACE, "--timeout=20s")


def _run_red(lab, temp: Path, cluster: str):
    policy = temp / "red-audit-policy.json"
    policy.write_text(json.dumps(audit_policy(False)), encoding="utf-8")
    audit_dir = temp / "red-audit"
    audit_dir.mkdir()
    config = _kind_config(temp, policy, audit_dir, "red")
    kubeconfig = temp / "red-kubeconfig"
    # This second cluster is owned by this case and always removed in finally.
    try:
        lab.command("kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                    "--kubeconfig", str(kubeconfig), "--wait", "90s", "--config", str(config), timeout=480)
        _set_namespace(lab, cluster, kubeconfig)
        _wait_ready(lab, cluster, kubeconfig)
        control_name = FIXTURES["controls"]["red_policy_positive"]
        _create(lab, cluster, kubeconfig, {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": control_name, "namespace": NAMESPACE},
            "data": {"marker": "inert"},
        })
        for family in FAMILIES:
            candidates = [(family["plural"], family["name"])]
            if "also" in family:
                candidates.append((family["also"]["plural"], family["also"]["name"]))
            for plural, name in candidates:
                _create(lab, cluster, kubeconfig,
                        _resource(family["group"], "v1alpha1",
                                  family["kind"] if plural == family["plural"] else family["also"]["kind"],
                                  name, "red-inert"))
        records = _audit_records(lab, audit_dir / "audit.log")
        control = _matching(records, name=control_name, resource="configmaps", group="", verb="create")
        misses = []
        for family in FAMILIES:
            entries = [(family["plural"], family["name"])]
            if "also" in family:
                entries.append((family["also"]["plural"], family["also"]["name"]))
            for plural, name in entries:
                misses.append({"name": name, "resource": plural, "group": family["group"],
                               "record_count": len(_matching(records, name=name, resource=plural,
                                                              group=family["group"], verb="create"))})
        return {"control_record_count": len(control),
                "control_response_code": (control[0].get("responseStatus") or {}).get("code") if control else None,
                "unmatched_ai_creates": misses}, [_safe_event(event) for event in records]
    finally:
        clusters = lab.command("kind", "get", "clusters").stdout.splitlines()
        if cluster in clusters:
            lab.command("kind", "delete", "cluster", "--name", cluster,
                        "--kubeconfig", str(kubeconfig), timeout=90)


def run(lab) -> None:
    temp = lab.kubeconfig.parent
    red_cluster = f"{lab.cluster}-red"
    if len(red_cluster) > 63:
        lab.block("Runner-generated cluster name is too long for the case-owned red cluster")
    existing = lab.command("kind", "get", "clusters").stdout.splitlines()
    if red_cluster in existing:
        lab.block("Case-owned red cluster name is already in use")

    green_cluster = lab.cluster
    green_kubeconfig = lab.kubeconfig
    green_audit = temp / "green-audit" / "audit.log"
    _set_namespace(lab, green_cluster, green_kubeconfig)
    _wait_ready(lab, green_cluster, green_kubeconfig)
    _kubectl(lab, green_cluster, green_kubeconfig, "create", "namespace", OTHER_NAMESPACE)
    _kubectl(lab, green_cluster, green_kubeconfig, "wait",
             f"--for=jsonpath={{.status.phase}}=Active", f"namespace/{OTHER_NAMESPACE}", "--timeout=20s")

    red, red_records = _run_red(lab, temp, red_cluster)
    red_ok = (red["control_record_count"] == 1 and red["control_response_code"] == 201
              and all(x["record_count"] == 0 for x in red["unmatched_ai_creates"]))
    lab.check("red", "With named AI families unmatched and the final rule None, successful AI-family API creates have no audit records while the named positive control does",
              red_ok, red)

    green_events = []
    expected = []
    explicit = set()
    for family in FAMILIES:
        entries = [(family["plural"], family["kind"], family["name"])]
        if "also" in family:
            other = family["also"]
            entries.append((other["plural"], other["kind"], other["name"]))
        for plural, kind, name in entries:
            expected.extend((name, plural, family["group"], verb) for verb in ("create", "patch", "get"))
            explicit.update((name, plural, family["group"], verb) for verb in ("create", "patch"))
            obj = _resource(family["group"], "v1alpha1", kind, name, "green-inert")
            _create(lab, green_cluster, green_kubeconfig, obj)
            create_events = _await_exact(lab, green_audit, name=name, resource=plural,
                                         group=family["group"], verb="create")
            green_events.extend(_safe_event(x) for x in create_events)
            # Exercise the configured patch verb on the same exact API resource.
            _kubectl(lab, green_cluster, green_kubeconfig, "--namespace", NAMESPACE,
                     "patch", f"{plural}.{family['group']}", name, "--type=merge",
                     "-p", '{"spec":{"fixtureMarker":"updated"}}', "-o", "json")
            patch_events = _await_exact(lab, green_audit, name=name, resource=plural,
                                        group=family["group"], verb="patch")
            green_events.extend(_safe_event(x) for x in patch_events)
            # `get` is intentionally omitted from explicit rules and is selected by fallback.
            # kubectl patch performs its own GET. Mark the explicit read with a formatting option.
            read_path = f"/apis/{family['group']}/v1alpha1/namespaces/{NAMESPACE}/{plural}/{name}"
            _kubectl(lab, green_cluster, green_kubeconfig, "get", "--raw", read_path + "?pretty=false")
            get_events = _await_exact(lab, green_audit, name=name, resource=plural,
                                      group=family["group"], verb="get", uri_marker="pretty=false")
            green_events.extend(_safe_event(x) for x in get_events)

    # The existing fixture proves create/patch. Add one real update and delete for each
    # exact synthetic AI resource so those separate API verbs are selected too.
    verb_comparisons = []
    for family in FAMILIES:
        entries = [(family["plural"], family["name"])]
        if "also" in family:
            entries.append((family["also"]["plural"], family["also"]["name"]))
        for plural, name in entries:
            resource = f"{plural}.{family['group']}"
            current = json.loads(_kubectl(
                lab, green_cluster, green_kubeconfig, "get", resource, name,
                "--namespace", NAMESPACE, "-o", "json").stdout)
            current.setdefault("spec", {})["fixtureMarker"] = "updated-via-put"
            _kubectl(lab, green_cluster, green_kubeconfig, "replace", "-f", "-", "-o", "json",
                     payload=json.dumps(current))
            update_events = _await_exact(lab, green_audit, name=name, resource=plural,
                                         group=family["group"], verb="update")
            _kubectl(lab, green_cluster, green_kubeconfig, "delete", resource, name,
                     "--namespace", NAMESPACE, "--wait=true")
            delete_events = _await_exact(lab, green_audit, name=name, resource=plural,
                                         group=family["group"], verb="delete")
            update_event = update_events[0] if len(update_events) == 1 else {}
            delete_event = delete_events[0] if len(delete_events) == 1 else {}
            update_marker = (update_event.get("requestObject") or {}).get("spec", {}).get("fixtureMarker")
            update_ok = (len(update_events) == 1 and update_event.get("level") == "Request"
                         and update_event.get("stage") == "ResponseComplete"
                         and (update_event.get("responseStatus") or {}).get("code") == 200
                         and update_marker == "updated-via-put"
                         and "responseObject" not in update_event)
            delete_ok = (len(delete_events) == 1 and delete_event.get("level") == "Request"
                         and delete_event.get("stage") == "ResponseComplete"
                         and (delete_event.get("responseStatus") or {}).get("code") == 200
                         and "responseObject" not in delete_event)
            verb_comparisons.append({"resource": plural, "group": family["group"],
                                     "update_event_count": len(update_events), "update_request_marker": update_marker,
                                     "update_matches": update_ok, "delete_event_count": len(delete_events),
                                     "delete_matches": delete_ok})

    # Same AI API group/resource/verb in a different namespace must fall through to Metadata.
    outside_name = "fixture-model-outside-namespace"
    _create(lab, green_cluster, green_kubeconfig,
            _resource(FAMILIES[0]["group"], "v1alpha1", FAMILIES[0]["kind"], outside_name,
                     "synthetic-sensitive-marker", namespace=OTHER_NAMESPACE))
    outside_events = _await_exact(lab, green_audit, name=outside_name,
                                  resource=FAMILIES[0]["plural"], group=FAMILIES[0]["group"],
                                  verb="create", namespace=OTHER_NAMESPACE)
    outside_event = outside_events[0] if len(outside_events) == 1 else {}
    namespace_metadata = (len(outside_events) == 1 and outside_event.get("level") == "Metadata"
                          and outside_event.get("stage") == "ResponseComplete"
                          and (outside_event.get("responseStatus") or {}).get("code") == 201
                          and (outside_event.get("objectRef") or {}).get("namespace") == OTHER_NAMESPACE
                          and "requestObject" not in outside_event
                          and "responseObject" not in outside_event)

    # The same write verb reaches only the fallback when either group or resource differs.
    for probe in FIXTURES["selector_probes"]:
        name, plural, group = (probe[key] for key in ("name", "plural", "group"))
        _create(lab, green_cluster, green_kubeconfig,
                _resource(group, "v1alpha1", probe["kind"], name, "green-inert"))
        events = _await_exact(lab, green_audit, name=name, resource=plural, group=group, verb="create")
        green_events.extend(_safe_event(event) for event in events)
        expected.append((name, plural, group, "create"))

    # Independent, ordinary core API positive observation outside all explicit AI rules.
    fallback_name = FIXTURES["controls"]["broad_fallback"]
    _create(lab, green_cluster, green_kubeconfig, {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": fallback_name, "namespace": NAMESPACE},
        "data": {"marker": "inert"},
    })
    fallback_events = _await_exact(lab, green_audit, name=fallback_name,
                                   resource="configmaps", group="", verb="create")
    green_events.extend(_safe_event(x) for x in fallback_events)

    # This succeeds but is excluded by the earlier name-specific None rule.
    negative_name = FIXTURES["controls"]["negative_resource_name"]
    _create(lab, green_cluster, green_kubeconfig, {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": negative_name, "namespace": NAMESPACE},
        "data": {"marker": "inert"},
    })
    excluded_path = f"/api/v1/namespaces/{NAMESPACE}/configmaps/{negative_name}"
    _kubectl(lab, green_cluster, green_kubeconfig, "get", "--raw", excluded_path)
    after_negative = _audit_records(lab, green_audit)
    negative_events = _matching(after_negative, name=negative_name, resource="configmaps",
                                group="", verb="get")
    expected.append((fallback_name, "configmaps", "", "create"))

    checked = []
    for name, resource, group, verb in expected:
        matches = [event for event in green_events if
                   event["verb"] == verb and event["objectRef"]["resource"] == resource
                   and event["objectRef"]["name"] == name and event["objectRef"].get("apiGroup", "") == group]
        fallback = (name, resource, group, verb) not in explicit
        level = "Metadata" if fallback else "Request"
        marker = None if fallback else ("green-inert" if verb == "create" else "updated")
        response_code = 201 if verb == "create" else 200
        expected_result = {"level": level, "response_code": response_code, "fixture_marker": marker}
        if len(matches) == 1:
            event = matches[0]
            observed = {"level": event["level"], "response_code": event["responseStatus"].get("code"),
                        "fixture_marker": (event.get("requestObject") or {}).get("spec", {}).get("fixtureMarker")}
        else:
            observed = None
        checked.append({"name": name, "resource": resource, "group": group, "verb": verb,
                        "expected": expected_result, "observed": observed, "matches": observed == expected_result})

    (lab.evidence / "audit-observations.json").write_text(json.dumps({
        "red_cluster": red_cluster, "red": red, "red_records": red_records, "green_cluster": green_cluster,
        "green_response_complete": green_events, "excluded_name_event_count": len(negative_events),
        "red_policy": audit_policy(False), "green_policy": audit_policy(True),
    }, indent=2) + "\n", encoding="utf-8")
    lab.check("green", "Each named AI create and patch reaches the exact Request rule and all other selected operations reach Metadata",
              len({event["auditID"] for event in green_events}) == len(expected)
              and all(row["matches"] for row in checked), {"operations": checked})
    unlisted = [row for row in checked if row["expected"]["level"] == "Metadata"]
    lab.check("positive", "A broad Metadata fallback captures unlisted reads and an ordinary ConfigMap, with the earlier named None rule taking precedence",
              all(row["matches"] for row in unlisted) and not negative_events,
              {"unlisted_operations": len(unlisted), "all_unlisted_operations_logged": all(row["matches"] for row in unlisted),
               "excluded_name_events": len(negative_events)})
    lab.check("positive", "The explicit AI-family policy captures actual update and delete verbs for each named resource",
              len(verb_comparisons) == 7 and all(row["update_matches"] and row["delete_matches"]
                                                   for row in verb_comparisons) and namespace_metadata,
              {"resource_count": len(verb_comparisons), "operations": verb_comparisons,
               "outside_namespace_same_resource_metadata_only": namespace_metadata})
