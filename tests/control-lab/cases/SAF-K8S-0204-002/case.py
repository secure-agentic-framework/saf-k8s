"""Run a real Falco rule against live scoped kube-apiserver audit metadata."""

import hashlib
import json
from pathlib import Path
import time

SCOPE = "A pinned userspace Falco audit rule evaluates finite live Kind API events and emits an attributed JSON alert for a public marker."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
HERE = Path(__file__).resolve().parent
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
IMAGE = "saf-lab-falco-audit:source-" + SOURCE[:24]
LABEL = "org.saf.fixture.falco-source"
LOG = "/var/log/kubernetes/saf-rule-audit.ndjson"
NAMESPACE = "saf-test"
MARKED = "fixture-audit-marker"
ORDINARY = "fixture-audit-ordinary"
RULE = "SAF owned Kubernetes audit read"


def prepare_kind(_lab, temporary):
    policy = temporary / "saf-rule-audit.json"
    policy.write_text(json.dumps({
        "apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
        "rules": [{"level": "Metadata", "verbs": ["get"], "namespaces": [NAMESPACE],
                   "resources": [{"group": "", "resources": ["configmaps"]}]}, {"level": "None"}],
    }))
    config = temporary / "kind-rule-audit.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/saf-rule-audit.json
        readOnly: true
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-rule-audit.json
        - name: audit-log-path
          value: {LOG}
      extraVolumes:
        - name: saf-rule-audit-policy
          hostPath: /etc/kubernetes/saf-rule-audit.json
          mountPath: /etc/kubernetes/saf-rule-audit.json
          readOnly: true
          pathType: File
        - name: saf-rule-audit-log
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          pathType: DirectoryOrCreate
""")
    return config


def image(lab):
    found = lab.command("docker", "image", "inspect", IMAGE, allow_failure=True)
    if found.returncode:
        lab.command("docker", "build", "-q", "-t", IMAGE, "--label", f"{LABEL}={SOURCE}", str(HERE), timeout=420)
        found = lab.command("docker", "image", "inspect", IMAGE)
    metadata, = json.loads(found.stdout)
    if metadata["Config"]["Labels"].get(LABEL) != SOURCE:
        lab.block("Local Falco image does not match the reviewed build")
    lab.command("kind", "load", "docker-image", IMAGE, "--name", lab.cluster, timeout=210)


def read_events(lab):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        events = {}
        logs = lab.command("docker", "exec", lab.cluster + "-control-plane", "cat", LOG, allow_failure=True)
        if not logs.returncode:
            for line in logs.stdout.splitlines():
                event = json.loads(line)
                ref = event.get("objectRef") or {}
                if (ref.get("name") in (ORDINARY, MARKED) and ref.get("namespace") == NAMESPACE
                        and ref.get("resource") == "configmaps" and event.get("stage") == "ResponseComplete"
                        and event.get("verb") == "get" and event.get("responseStatus", {}).get("code") == 200):
                    events[ref["name"]] = event
        if {ORDINARY, MARKED} == events.keys():
            return events
        time.sleep(0.5)
    lab.block("Expected live metadata events were unavailable")


def evaluate(lab, name, rules, events):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "immutable": True, "data": {"falco.yaml": (HERE / "falco.yaml").read_text(),
                     "rules.yaml": rules, "audit.ndjson": "".join(json.dumps(event) + "\n" for event in events)}})
    unit = {"name": "engine", "image": IMAGE, "imagePullPolicy": "Never",
            "command": ["/usr/bin/falco", "-c", "/fixture/falco.yaml", "--disable-source", "syscall"],
            "env": [{"name": "HOST_ROOT", "value": "/"}],
            "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "30m", "memory": "40Mi"},
                          "limits": {"cpu": "250m", "memory": "192Mi"}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "template": {"spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "fixture", "configMap": {"name": name}}], "containers": [unit],
                }}}})
    waited = lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=48s", timeout=58, allow_failure=True)
    logs = lab.kubectl("logs", f"job/{name}", allow_failure=True)
    if waited.returncode or logs.returncode:
        lab.block("The pinned audit rule engine did not complete the owned replay")
    return [json.loads(line) for line in logs.stdout.splitlines() if line.startswith("{")]


def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE, "pod-security.kubernetes.io/enforce=restricted")
    image(lab)
    for name in (ORDINARY, MARKED):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                    "immutable": True, "data": {"value": "public synthetic lab marker"}})
        lab.kubectl("get", "configmap", name, "-o", "name")
    events = read_events(lab)
    rules = (HERE / "rules.yaml").read_text()
    baseline = evaluate(lab, "fixture-audit-nonmatching", rules.replace(MARKED, "fixture-absent"), events.values())
    lab.check("red", "The same live audit input produces no alerts for a rule with an unmatched target",
              not baseline, {"nonmatching_output_empty": not baseline})
    alerts = evaluate(lab, "fixture-audit-matching", rules, events.values())
    matched = len(alerts) == 1 and alerts[0].get("rule") == RULE and alerts[0].get("source") == "k8s_audit"
    target = alerts[0].get("output_fields", {}).get("ka.target.name") if matched else None
    lab.check("green", "Falco emits exactly one alert for the owned marker and leaves the ordinary read unalerted",
              matched and target == MARKED, {"matched_alerts": len(alerts), "ordinary_unalerted": matched and target == MARKED})
    fields = alerts[0]["output_fields"]
    event = events[MARKED]
    attributed = (fields.get("ka.target.namespace") == NAMESPACE and
                  fields.get("ka.user.name") == event["user"]["username"] and
                  fields.get("ka.auditid") == event["auditID"])
    lab.check("positive", "The delivered alert preserves source namespace, actor and audit event identity",
              attributed, {"alert_context_matches_input": attributed})
    (lab.evidence / "audit-rule-observations.json").write_text(
        json.dumps({"owned_event_names": list(events), "received_alert": alerts[0]}, indent=2) + "\n"
    )
