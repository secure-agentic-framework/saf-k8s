"""Contrast actual intent-header and issued-session behavior on an inert local marker."""

import json
from pathlib import Path

SCOPE = "A restricted Kubernetes Job compares two loopback-only marker access contracts. Cloud provider enforcement requires separate evidence."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NAME = "fixture-metadata-modes"


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME}, "immutable": True,
                "data": {"fixture.py": Path(__file__).with_name("protocol-fixture.py").read_text()}})
    container = {"name": "probe", "image": IMAGE, "command": ["python", "/fixture/fixture.py"],
                 "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                 "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "150m", "memory": "64Mi"}},
                 "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME},
                "spec": {"backoffLimit": 0, "template": {"spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "fixture", "configMap": {"name": NAME}}], "containers": [container],
                }}}})
    lab.kubectl("wait", "--for=condition=Complete", f"job/{NAME}", "--timeout=85s", timeout=95)
    observed = json.loads(lab.kubectl("logs", f"job/{NAME}").stdout)
    lab.check("red", "An HTTP marker accepts the fixed intent header without a fixture-issued session",
              observed["missing_intent"] == 400 and observed["fixed_intent_accepted"],
              {key: observed[key] for key in ("missing_intent", "fixed_intent_accepted")})
    lab.check("green", "The separate session-required route refuses missing or incorrect fixture sessions",
              observed["missing_session"] == observed["incorrect_session"] == 401,
              {key: observed[key] for key in ("missing_session", "incorrect_session")})
    lab.check("positive", "An issued fixture session retains authorized access to the same public marker",
              observed["issued_session_accepted"], {"issued_session_accepted": observed["issued_session_accepted"]})
    (lab.evidence / "metadata-access-mode-observations.json").write_text(json.dumps(observed, indent=2) + "\n")
