"""By-ID Service exposure admission checks; all external shapes are dry-runs."""
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import time

HERE = Path(__file__).parent
ENFORCED = "saf-k8s-0505-enforced"
APPROVED = "saf-k8s-0505-approved"
OWNER = "system:serviceaccount:saf-k8s-0505-approved:platform-exposure-owner"
DEVELOPER = "system:serviceaccount:saf-k8s-0505-enforced:service-developer"
OWNER_LABEL = "saf-k8s.example/exposure-owner"
APPROVAL_ANNOTATION = "saf-k8s.example/exposure-approval"
APPROVAL = "synthetic-dry-run-approval-v1"
NODEPORT_MESSAGE = "NodePort and LoadBalancer Services require the scoped platform exposure owner approval"
EXTERNALIPS_MESSAGE = (
    "ExternalIPs require scoped platform exposure owner approval and must use the "
    "reserved 192.0.2.0/24 documentation range"
)
SCOPE = (
    "Fresh Kubernetes v1.36.1 Kind cluster; Service CREATE and UPDATE admission "
    "for NodePort, LoadBalancer, and reserved documentation-only ExternalIPs, "
    "with exact synthetic owner-namespace exception and genuine projected identities. The "    "built-in admission plugin is verified on a separate disposable node. All exposure-shaped "
    "requests are server-side dry-runs. Only selector-less ClusterIP Services "
    "are persisted; real network exposure and production registry behavior are "
    "outside this fixture."
)


def service(namespace, name, *, service_type="ClusterIP", external_ips=None,
            approved=False):
    metadata = {"name": name, "namespace": namespace}
    if approved:
        metadata["labels"] = {OWNER_LABEL: "platform-engineering"}
        metadata["annotations"] = {APPROVAL_ANNOTATION: APPROVAL}
    spec = {"type": service_type, "ports": [{"name": "http", "port": 80, "targetPort": 8080}]}
    if service_type == "LoadBalancer":
        # No LB controller is installed. This manifest is submitted only as a dry-run.
        spec["loadBalancerClass"] = "saf.example/no-controller-dry-run"
    if external_ips is not None:
        spec["externalIPs"] = external_ips
    return {"apiVersion": "v1", "kind": "Service", "metadata": metadata, "spec": spec}


def kubectl(lab, namespace, *args, identity=None, payload=None, allow_failure=False):
    if identity is None:
        return lab.kubectl("--namespace", namespace, *args, payload=payload, allow_failure=allow_failure)
    return lab.command(
        "kubectl", "--kubeconfig", str(identity), "--context", "fixture",
        "--namespace", namespace, "--request-timeout=25s", *args,
        payload=payload, allow_failure=allow_failure, timeout=30,
    )


def actor_config(lab, temporary, principal):
    namespace, name = principal.split(":")[-2:]
    original = ["kubectl", "--kubeconfig", str(lab.kubeconfig),
                "--context", f"kind-{lab.cluster}", "--request-timeout=15s"]

    def private_output(*args):
        result = subprocess.run([*original, *args], env=lab.env, text=True, capture_output=True, timeout=20)
        if result.returncode or not result.stdout.strip():
            lab.block("Could not provision the owned synthetic actor")
        return result.stdout.strip()

    server, ca = (
        private_output("config", "view", "--minify", "--raw", "-o", f"jsonpath={{.clusters[0].cluster.{field}}}")
        for field in ("server", "certificate-authority-data")
    )
    if not server.startswith("https://127.0.0.1:"):
        lab.block("Expected the exact isolated Kind API on loopback")
    # Keep case credentials out of the subprocess invocation, output, and receipts.
    token = private_output("-n", namespace, "create", "token", name, "--duration=10m")
    kubeconfig = temporary / f"{name}.json"
    kubeconfig.touch(mode=0o600, exist_ok=False)
    kubeconfig.write_text(json.dumps({
        "apiVersion": "v1", "kind": "Config", "current-context": "fixture",
        "clusters": [{"name": "owned", "cluster": {"server": server, "certificate-authority-data": ca}}],
        "users": [{"name": name, "user": {"token": token}}],
        "contexts": [{"name": "fixture", "context": {"cluster": "owned", "user": name}}],
    }))
    actual = kubectl(lab, namespace, "auth", "whoami", "-o", "json", identity=kubeconfig)
    observed = json.loads(actual.stdout)["status"]["userInfo"]["username"]
    lab.check("positive", f"The direct case token authenticates the intended {name} identity",
              observed == principal, {"authenticated_identity": observed, "expected": principal})
    return kubeconfig


def server_create(lab, obj, identity):
    return kubectl(
        lab, obj["metadata"]["namespace"], "create", "-f", "-", "--dry-run=server",
        "-o", "json", identity=identity, payload=json.dumps(obj), allow_failure=True,
    )


def server_update(lab, namespace, name, patch, identity):
    return kubectl(
        lab, namespace, "patch", "service", name, "--type=merge", "--dry-run=server",
        "-o", "json", "-p", json.dumps(patch), identity=identity, allow_failure=True,
    )


def create_base(lab, namespace, name):
    obj = service(namespace, name)
    kubectl(lab, namespace, "create", "-f", "-", payload=json.dumps(obj))


def denial(result, message):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and message in result.stderr)


def authorized_service(namespace, name, *, service_type="ClusterIP", external_ips=None):
    return service(namespace, name, service_type=service_type,
                   external_ips=external_ips, approved=True)


def run(lab):
    # Create isolated namespaces and grant only the fixture actors the Service
    # verbs needed to reach admission during both CREATE and UPDATE requests.
    for namespace in (ENFORCED, APPROVED):
        kubectl(lab, "saf-test", "create", "namespace", namespace)
    for namespace, account in ((ENFORCED, "service-developer"),
                               (APPROVED, "platform-exposure-owner")):
        kubectl(lab, namespace, "create", "serviceaccount", account)
        kubectl(lab, namespace, "create", "role", "service-exposure-probe",
                "--verb=create,get,patch,update", "--resource=services")
        kubectl(lab, namespace, "create", "rolebinding", "service-exposure-probe",
                "--role=service-exposure-probe", f"--serviceaccount={namespace}:{account}")
    # Red probes are issued in the runner's unlabelled saf-test namespace.
    kubectl(lab, "saf-test", "create", "role", "service-exposure-probe",
            "--verb=create,get,patch,update", "--resource=services")
    kubectl(lab, "saf-test", "create", "rolebinding", "service-exposure-probe",
            "--role=service-exposure-probe",
            f"--serviceaccount={ENFORCED}:service-developer")
    # Give each identity an authorized request in the other fixture namespace
    # so CEL namespace binding, rather than an RBAC failure, is the counterfactual.
    for namespace, account in ((ENFORCED, "platform-exposure-owner"),
                               (APPROVED, "service-developer")):
        kubectl(lab, namespace, "create", "rolebinding", f"cross-namespace-{account}",
                "--role=service-exposure-probe",
                f"--serviceaccount={APPROVED if namespace == ENFORCED else ENFORCED}:{account}")

    with TemporaryDirectory(prefix="saf-0505-actors-") as folder:
        temporary = Path(folder)
        owner = actor_config(lab, temporary, OWNER)
        developer = actor_config(lab, temporary, DEVELOPER)
        verify_scoped_service_policy(lab, owner, developer)
    verify_native_plugin(lab)


def verify_scoped_service_policy(lab, owner, developer):
    # Red: all three exposure mechanisms and their UPDATE form reach the
    # unenforced API and are admitted as non-persisting server dry-runs.
    red_shapes = (
        ("NodePort", None),
        ("LoadBalancer", None),
        ("ClusterIP", ["192.0.2.44"]),
    )
    update_name = "saf-0505-harmless-clusterip"
    create_base(lab, "saf-test", update_name)
    for index, (service_type, external_ips) in enumerate(red_shapes):
        create = service("saf-test", f"red-create-{index}",
                         service_type=service_type, external_ips=external_ips)
        result = server_create(lab, create, developer)
        deprecated = "externalIPs" in result.stderr and "deprecated" in result.stderr.casefold()
        lab.check("red", f"Unenforced CREATE admits {service_type} / ExternalIPs shape",
                  result.returncode == 0 and (external_ips is None or deprecated),
                  {"admitted": result.returncode == 0, "external_ip_deprecation_warning": deprecated})
        patch = {"spec": {}}
        if service_type != "ClusterIP":
            patch["spec"]["type"] = service_type
        if external_ips is not None:
            patch["spec"]["externalIPs"] = external_ips
        result = server_update(lab, "saf-test", update_name, patch, developer)
        lab.check("red", f"Unenforced UPDATE admits {service_type} / ExternalIPs shape",
                  result.returncode == 0, result.stderr.strip() or "server dry-run admitted")

    lab.apply(HERE / "admission-policy.yaml")

    # Wait for an exact policy response so a startup delay cannot be mistaken
    # for successful admission enforcement.
    ready_probe = server_create(
        lab, service(ENFORCED, "activation-probe", service_type="NodePort"), developer,
    )
    deadline = time.monotonic() + 20
    while not denial(ready_probe, NODEPORT_MESSAGE) and time.monotonic() < deadline:
        time.sleep(0.5)
        ready_probe = server_create(
            lab, service(ENFORCED, "activation-probe", service_type="NodePort"), developer,
        )
    lab.check("green", "NodePort request reaches active VAP and gets its stable denial",
              denial(ready_probe, NODEPORT_MESSAGE), ready_probe.stderr.strip())

    # Unauthorized CREATE probes exercise every mechanism separately, then
    # both combinations of Service type and ExternalIPs.
    for index, (service_type, external_ips, expected) in enumerate((
        ("NodePort", None, NODEPORT_MESSAGE),
        ("LoadBalancer", None, NODEPORT_MESSAGE),
        ("ClusterIP", ["192.0.2.44"], EXTERNALIPS_MESSAGE),
        ("NodePort", ["192.0.2.44"], NODEPORT_MESSAGE),
        ("LoadBalancer", ["192.0.2.44"], NODEPORT_MESSAGE),
        ("ClusterIP", ["192.0.2.44", "198.51.100.44"], EXTERNALIPS_MESSAGE),
    )):
        obj = service(ENFORCED, f"deny-create-{index}", service_type=service_type,
                      external_ips=external_ips)
        result = server_create(lab, obj, developer)
        lab.check("green", f"Enforced CREATE denies counterfactual {index + 1}",
                  denial(result, expected), result.stderr.strip())

    # UPDATE challenges prove Service type transitions and field addition are
    # covered after an ordinary ClusterIP Service already exists.
    for index, (service_type, external_ips, expected) in enumerate((
        ("NodePort", None, NODEPORT_MESSAGE),
        ("LoadBalancer", None, NODEPORT_MESSAGE),
        ("ClusterIP", ["192.0.2.44"], EXTERNALIPS_MESSAGE),
        ("NodePort", ["192.0.2.44"], NODEPORT_MESSAGE),
        ("LoadBalancer", ["192.0.2.44"], NODEPORT_MESSAGE),
        ("ClusterIP", ["192.0.2.44", "198.51.100.44"], EXTERNALIPS_MESSAGE),
    )):
        patch = {"spec": {}}
        if service_type != "ClusterIP":
            patch["spec"]["type"] = service_type
        if external_ips is not None:
            patch["spec"]["externalIPs"] = external_ips
        result = server_update(lab, "saf-test", update_name, patch, developer)
        lab.check("green", f"Enforced UPDATE denies counterfactual {index + 1}",
                  denial(result, expected), result.stderr.strip())

    # An otherwise exact exception fails when the authenticated owner is used
    # outside its approved namespace, or when another identity uses its shape.
    wrong_namespace = authorized_service(
        ENFORCED, "approved-wrong-namespace", service_type="NodePort",
    )
    result = server_create(lab, wrong_namespace, owner)
    lab.check("green", "Owner identity cannot carry exception into another namespace",
              denial(result, NODEPORT_MESSAGE), result.stderr.strip())
    wrong_actor = authorized_service(APPROVED, "approved-wrong-actor", service_type="NodePort")
    result = server_create(lab, wrong_actor, developer)
    lab.check("green", "Developer identity cannot use the owner exception",
              denial(result, NODEPORT_MESSAGE), result.stderr.strip())

    # The approval path remains narrow: the authorized owner may dry-run each
    # approved exposure kind, but only the reserved 192.0.2.0/24 pattern.
    for name, service_type, external_ips in (
        ("approved-nodeport", "NodePort", None),
        ("approved-loadbalancer", "LoadBalancer", None),
        ("approved-externalip", "ClusterIP", ["192.0.2.44"]),
    ):
        obj = authorized_service(APPROVED, name, service_type=service_type,
                                 external_ips=external_ips)
        result = server_create(lab, obj, owner)
        lab.check("positive", f"Scoped owner can dry-run approved {service_type} / ExternalIPs",
                  result.returncode == 0, result.stderr.strip() or "server dry-run admitted")

    # Confirm the same scoped approval can support a controlled transition on
    # an existing owner-marked ClusterIP, without persisting the new exposure.
    update_base = authorized_service(APPROVED, "approved-update-base")
    kubectl(lab, APPROVED, "create", "-f", "-", payload=json.dumps(update_base))
    for label, patch in (
        ("NodePort", {"spec": {"type": "NodePort"}}),
        ("LoadBalancer", {"spec": {"type": "LoadBalancer",
                                    "loadBalancerClass": "saf.example/no-controller-dry-run"}}),
        ("ExternalIPs", {"spec": {"externalIPs": ["192.0.2.44"]}}),
    ):
        result = server_update(lab, APPROVED, "approved-update-base", patch, owner)
        lab.check("positive", f"Scoped owner can dry-run approved {label} UPDATE",
                  result.returncode == 0, result.stderr.strip() or "server dry-run admitted")

    wrong_pattern = authorized_service(
        APPROVED, "approved-wrong-pattern", external_ips=["198.51.100.44"],
    )
    result = server_create(lab, wrong_pattern, owner)
    lab.check("green", "Owner exception rejects addresses outside reserved 192.0.2.0/24",
              denial(result, EXTERNALIPS_MESSAGE), result.stderr.strip())
    wrong_label = authorized_service(
        APPROVED, "approved-wrong-label", service_type="LoadBalancer",
    )
    wrong_label["metadata"]["labels"][OWNER_LABEL] = "application-team"
    result = server_create(lab, wrong_label, owner)
    lab.check("green", "Owner exception requires the platform owner label",
              denial(result, NODEPORT_MESSAGE), result.stderr.strip())
    wrong_approval = authorized_service(
        APPROVED, "approved-wrong-approval", service_type="LoadBalancer",
    )
    wrong_approval["metadata"]["annotations"][APPROVAL_ANNOTATION] = "not-approved"
    result = server_create(lab, wrong_approval, owner)
    lab.check("green", "Owner exception requires the exact approval annotation",
              denial(result, NODEPORT_MESSAGE), result.stderr.strip())

    # Persist one positive Service after policy activation. It has no selector
    # or endpoints and uses ClusterIP, inside the cluster service network.
    harmless = service("saf-test", "saf-0505-clusterip-after-policy")
    result = kubectl(lab, "saf-test", "create", "-f", "-", "-o", "json",
                     identity=developer, payload=json.dumps(harmless), allow_failure=True)
    lab.check("positive", "Ordinary ClusterIP Service remains admissible after policy",
              result.returncode == 0,
              result.stderr.strip() or "selector-less ClusterIP persisted; it has no endpoints or external exposure")



def verify_native_plugin(lab):
    incorrect = lab.kubectl(
        "-n", "kube-system", "exec", f"kube-apiserver-{lab.cluster}-control-plane",
        "-c", "kube-apiserver", "--", "kube-apiserver",
        "--feature-gates=DenyServiceExternalIPs=true", "--secure-port=0",
        "--etcd-servers=http://127.0.0.1:1", "--bind-address=127.0.0.1",
        allow_failure=True, timeout=12,
    )
    output = (incorrect.stdout + incorrect.stderr).casefold()
    gate_rejected = "unrecognized feature gate" in output and "denyserviceexternalips" in output
    lab.check("red", "The exact API server binary rejects the catalogued feature-gate form",
              incorrect.returncode != 0 and gate_rejected, {"unknown_gate_reported": gate_rejected})

    peer = f"{lab.cluster}-plugin"
    with TemporaryDirectory(prefix="saf-0505-native-") as folder:
        root = Path(folder)
        kubeconfig, config = root / "kubeconfig", root / "kind.yaml"
        config.write_text("""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta4
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
    - name: enable-admission-plugins
      value: NodeRestriction,DenyServiceExternalIPs
""")
        def native(*args, payload=None, allow_failure=False):
            return lab.command("kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{peer}",
                               "--request-timeout=20s", *args, payload=payload, allow_failure=allow_failure)

        listed = lab.command("kind", "get", "clusters").stdout.splitlines()
        if peer in listed:
            lab.block("The native plugin cluster name is already present")
        try:
            lab.command("kind", "create", "cluster", "--name", peer, "--config", str(config),
                        "--kubeconfig", str(kubeconfig),
                        "--image", "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5",
                        "--wait", "90s", timeout=300)
            pod = f"kube-apiserver-{peer}-control-plane"
            obj = json.loads(native("-n", "kube-system", "get", "pod", pod, "-o", "json").stdout)
            flags = obj["spec"]["containers"][0]["command"]
            active = any(arg.startswith("--enable-admission-plugins=")
                         and "DenyServiceExternalIPs" in arg.split("=", 1)[1].split(",")
                         for arg in flags)
            ordinary = service("default", "native-ordinary")
            good = native("create", "-f", "-", "-o", "name", payload=json.dumps(ordinary))
            lab.check("positive", "The configured native plugin still permits an ordinary ClusterIP",
                      active and good.stdout.strip() == "service/native-ordinary",
                      {"native_plugin_in_live_args": active, "ordinary_service_created": good.returncode == 0})
            for action in ("create", "update"):
                if action == "create":
                    obj = service("default", "native-rejected", external_ips=["192.0.2.44"])
                    result = native("create", "--dry-run=server", "-f", "-", payload=json.dumps(obj),
                                    allow_failure=True)
                else:
                    patch = json.dumps({"spec": {"externalIPs": ["192.0.2.44"]}})
                    result = native("patch", "service", "native-ordinary", "--type=merge",
                                    "--dry-run=server", "-p", patch, allow_failure=True)
                reason = result.stderr.casefold()
                blocked = "(forbidden)" in reason and ("external ip" in reason or "externalips" in reason)
                lab.check("green", f"The native validating plugin rejects new ExternalIPs on {action.upper()}",
                          result.returncode != 0 and blocked, {"native_external_ip_denial": blocked})
        finally:
            lab.command("kind", "delete", "cluster", "--name", peer, "--kubeconfig", str(kubeconfig), timeout=90)
            if peer in lab.command("kind", "get", "clusters").stdout.splitlines():
                lab.block("The peer cluster with native admission configured was not removed")
    lab.check("positive", "The independent native-plugin cluster was removed", True, {"peer_deleted": True})
