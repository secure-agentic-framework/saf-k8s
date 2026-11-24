"""Synthetic, non-running workload fixtures for SAF-K8S-0910-026."""

BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)


def deployment(name, *, privileged):
    security_context = {"allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                        "runAsNonRoot": True, "runAsUser": 65534,
                        "seccompProfile": {"type": "RuntimeDefault"}}
    if privileged:
        security_context.pop("allowPrivilegeEscalation")
        security_context["privileged"] = True
    labels = {"app": name, "saf-k8s.example/baseline": "required"}
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "labels": labels},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [{"name": "fixture", "image": BUSYBOX_IMAGE,
                                    "command": ["sh", "-c", "sleep 3600"],
                                    "securityContext": security_context}],
                },
            },
        },
    }
