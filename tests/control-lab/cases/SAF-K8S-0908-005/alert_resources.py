"""Small, low-privilege Kubernetes objects for the local SAF fixture."""

def pod(name, image, role, *, ports=()):
    container = {
        "name": "fixture",
        "image": image,
        "imagePullPolicy": "Never",
        "command": (["sleep", "3600"] if role == "client" else
                    ["python", "/fixture/fixture_service.py", "serve", role]),
        "volumeMounts": [{"name": "fixture-code", "mountPath": "/fixture", "readOnly": True}],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }
    if ports:
        container["ports"] = [{"name": "http", "containerPort": port} for port in ports]
        container["readinessProbe"] = {"tcpSocket": {"port": ports[0]}, "periodSeconds": 1}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "labels": {"app": name}},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [container],
            "volumes": [{"name": "fixture-code", "configMap": {"name": "fixture-code"}}],
        },
    }


def service(name, port):
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name},
        "spec": {
            "selector": {"app": name},
            "ports": [{"name": "http", "port": port, "targetPort": port}],
        },
    }


def ready(lab, name):
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=95s", timeout=105)
