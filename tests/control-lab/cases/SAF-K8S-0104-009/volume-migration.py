"""Verify migration of an inert published input to a supported Kubernetes volume."""
import json


IMAGE = ("docker.io/library/busybox:1.37.0@sha256:"
         "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec")
MARKER = "public-fixture-input-v1"
NAME = "fixture-supported-volume"


def template_references(item):
    kind = item["kind"]
    if kind == "List":
        return [record for entry in item["items"] for record in template_references(entry)]
    path = {
        "Pod": ("spec",),
        "Deployment": ("spec", "template", "spec"),
        "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
    }.get(kind)
    if path is None:
        return []
    fields = item
    for key in path:
        fields = fields.get(key, {})
    return [(kind, item["metadata"]["name"], value["name"])
            for value in fields.get("volumes", []) if "gitRepo" in value]


def run(lab):
    old = {"volumes": [{"name": "owned-data", "gitRepo": {"repository": "https://example.invalid/no-fetch"}}]}
    examples = {"kind": "List", "items": [
        {"kind": "Deployment", "metadata": {"name": "inert-legacy-deploy"},
         "spec": {"template": {"spec": old}}},
        {"kind": "CronJob", "metadata": {"name": "inert-legacy-cron"},
         "spec": {"jobTemplate": {"spec": {"template": {"spec": old}}}}},
    ]}
    found = template_references(examples)
    lab.check("red", "Inventory detects active-volume references in Deployment and CronJob templates",
              found == [("Deployment", "inert-legacy-deploy", "owned-data"),
                        ("CronJob", "inert-legacy-cron", "owned-data")],
              {"legacy_templates_detected": len(found)})

    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"marker": MARKER}})
    restricted = {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                  "capabilities": {"drop": ["ALL"]}}
    pod = {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": NAME},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "fsGroup": 10001,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "volumes": [{"name": "source", "configMap": {"name": NAME}}, {"name": "owned-data", "emptyDir": {}}],
            "initContainers": [{
                "name": "provide-input", "image": IMAGE, "securityContext": restricted,
                "command": ["/bin/sh", "-ec", "cp /input/marker /output/marker"],
                "volumeMounts": [{"name": "source", "mountPath": "/input", "readOnly": True},
                                 {"name": "owned-data", "mountPath": "/output"}],
            }],
            "containers": [{
                "name": "consumer", "image": IMAGE, "securityContext": restricted,
                "command": ["/bin/sh", "-ec", "test -s /fixture/marker && sleep 120"],
                "volumeMounts": [{"name": "owned-data", "mountPath": "/fixture", "readOnly": True}],
            }],
        },
    }
    lab.create(pod)
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{NAME}", "--timeout=65s", timeout=72)
    actual = json.loads(lab.kubectl("get", "pod", NAME, "-o", "json").stdout)
    init, = actual["status"]["initContainerStatuses"]
    content = lab.kubectl("exec", f"pod/{NAME}", "--", "cat", "/fixture/marker").stdout
    allowed = not template_references(actual) and init["state"]["terminated"]["exitCode"] == 0
    lab.check("green", "The supported replacement runs and its init container supplies exact fixture data",
              allowed and content.strip() == MARKER,
              {"init_completed": init["state"]["terminated"]["exitCode"] == 0,
               "legacy_volume_absent": not template_references(actual), "marker_matches": content.strip() == MARKER})
