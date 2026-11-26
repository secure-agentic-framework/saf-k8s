"""Small workloads shared by the pilot cases."""
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)


def pod(name, containers, **spec):
    return {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
        "spec": {"restartPolicy": "Never", "containers": containers, **spec},
    }


def container(name, **fields):
    return {
        "name": name, "image": BUSYBOX_IMAGE,
        "command": ["sh", "-c", "sleep 3600"],
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        **fields,
    }


def ready(lab, name):
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=95s", timeout=105)
