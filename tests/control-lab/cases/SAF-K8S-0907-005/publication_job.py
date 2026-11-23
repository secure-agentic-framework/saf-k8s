"""Small unprivileged Kubernetes Job and storage manifests for the case."""


def job(name, image, command, *, code_config, claim):
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name, "labels": {"case": "feature-publication"}},
        "spec": {
            "backoffLimit": 0,
            "template": {
                "metadata": {"labels": {"job": name}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "fsGroup": 65534},
                    "containers": [{
                        "name": "fixture", "image": image, "imagePullPolicy": "Never",
                        "command": ["python", "/fixture/pipeline_fixture.py", *command],
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "capabilities": {"drop": ["ALL"]},
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "volumeMounts": [
                            {"name": "code", "mountPath": "/fixture", "readOnly": True},
                            {"name": "publication", "mountPath": "/published",
                             "readOnly": command[0] in {"consume", "inspect-baseline"}},
                        ],
                    }],
                    "volumes": [
                        {"name": "code", "configMap": {"name": code_config}},
                        {"name": "publication", "persistentVolumeClaim": {"claimName": claim}},
                    ],
                },
            },
        },
    }
