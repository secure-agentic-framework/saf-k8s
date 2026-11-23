"""Verify actual Kind API endpoint routing through loss of an API backend."""

from contextlib import contextmanager
import json
import time

import yaml

SCOPE = "Two Kind API server backends behind the platform's Envoy endpoint with active HTTPS liveness checks; etcd members remain running."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
SAVED = "/run/saf-owned-apiserver-fixture.yaml"
HEALTH = "/readyz"
API = "/api/v1/namespaces/saf-test"


def prepare_kind(_lab, temporary):
    config = temporary / "kind-api-failover.yaml"
    config.write_text("""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: control-plane
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      certSANs:
        - "127.0.0.1"
""")
    return config


def node(lab, backend, *command, allow_failure=False):
    return lab.command("docker", "exec", backend, *command, allow_failure=allow_failure, timeout=20)


def direct(lab, backend, path):
    result = node(lab, backend, "kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
                  "--server=https://127.0.0.1:6443", "--request-timeout=3s",
                  "get", "--raw=" + path, allow_failure=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def namespace(body):
    return bool(body) and json.loads(body).get("metadata", {}).get("name") == "saf-test"


def shared(lab):
    result = lab.kubectl("get", "--raw=" + API, allow_failure=True, timeout=9)
    return result.returncode == 0 and namespace(result.stdout.strip())


def active(lab, backend):
    return node(lab, backend, "crictl", "ps", "--name", "kube-apiserver", "-q").stdout.split()


@contextmanager
def offline(lab, backend):
    existing = active(lab, backend)
    if len(existing) != 1:
        lab.block("The test backend did not have exactly one active API process")
    node(lab, backend, "test", "!", "-e", SAVED)
    node(lab, backend, "mv", MANIFEST, SAVED)
    try:
        if active(lab, backend) == existing:
            node(lab, backend, "crictl", "stop", "--timeout", "1", existing[0], allow_failure=True)
        yield
    finally:
        node(lab, backend, "mv", SAVED, MANIFEST)


def until(probe, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(0.5)
    return False



def envoy_events(lab, balancer, event_type, target_addresses):
    result = lab.command("docker", "logs", balancer, timeout=12)
    found = set()
    camel_type = event_type.split("_")[0] + "".join(part.title() for part in event_type.split("_")[1:])
    for line in (result.stdout + result.stderr).splitlines():
        if not line.lstrip().startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = event.get("host", {})
        address = (host.get("socket_address") or host.get("socketAddress") or {}).get("address")
        if ((event_type in event or camel_type in event) and address in target_addresses
                and (event.get("cluster_name") or event.get("clusterName")) == "kube_apiservers"):
            found.add(event["timestamp"])
    return found

def run(lab):
    found = lab.command("docker", "ps", "--filter", f"label=io.x-k8s.kind.cluster={lab.cluster}",
                        "--format", "{{.Names}}").stdout.split()
    expected = [f"{lab.cluster}-control-plane", f"{lab.cluster}-control-plane2"]
    balancer = f"{lab.cluster}-external-load-balancer"
    if set(found) != {*expected, balancer}:
        lab.block("The intended disposable two-backend load-balancer topology was absent")
    primary, secondary = expected
    configuration = yaml.safe_load(node(lab, balancer, "cat", "/home/envoy/cds.yaml").stdout)
    cluster, = [entry for entry in configuration["resources"] if entry["name"] == "kube_apiservers"]
    probe, = cluster["health_checks"]
    probe_path = probe.get("http_health_check", {}).get("path")
    tls_check = (probe.get("transport_socket_match_criteria") == {"tls_mode": "true"}
                 and any(item.get("match") == {"tls_mode": "true"}
                         and item["transport_socket"]["name"] == "envoy.transport_sockets.tls"
                         for item in cluster["transport_socket_matches"]))
    targets = [entry["endpoint"]["address"]["socket_address"]["address"]
               for group in cluster["load_assignment"]["endpoints"] for entry in group["lb_endpoints"]]
    def addresses(backend):
        networks = lab.command("docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", backend).stdout
        return {backend, *(network[key] for network in json.loads(networks).values()
                            for key in ("IPAddress", "GlobalIPv6Address") if network.get(key))}
    if (probe_path != "/healthz" or not tls_check or len(set(targets)) != 2
            or not all(set(targets) & addresses(backend) for backend in expected)):
        lab.block("The expected Envoy HTTPS probe and two backend targets were unavailable")
    ready = until(lambda: all(direct(lab, item, HEALTH) == "ok" for item in expected), 30)
    available_before = ready and all(namespace(direct(lab, item, API)) for item in expected) and shared(lab)
    if not available_before:
        lab.block("The two direct backend APIs and the shared endpoint must work before the test outage")

    primary_addresses = addresses(primary)
    prior_ejections = envoy_events(lab, balancer, "eject_unhealthy_event", primary_addresses)
    prior_reentries = envoy_events(lab, balancer, "add_healthy_event", primary_addresses)
    start = time.monotonic()
    with offline(lab, primary):
        unavailable = until(lambda: not active(lab, primary) and not direct(lab, primary, HEALTH), 35)
        if not unavailable:
            lab.block("The owned primary API server did not stop serving")
        pinned_failed = not namespace(direct(lab, primary, API))
        lab.check("red", "A client pinned to the unavailable API process loses its authenticated read",
                  pinned_failed, {"pinned_client_failed": pinned_failed, "both_backends_initially_healthy": ready})

        observed = []
        ejected = False
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            observed.append(shared(lab))
            ejected = bool(envoy_events(lab, balancer, "eject_unhealthy_event", primary_addresses) - prior_ejections)
            if ejected:
                break
            time.sleep(0.5)
        time_to_eject = time.monotonic() - start
        steady = []
        if ejected:
            for _ in range(5):
                steady.append(shared(lab))
                time.sleep(0.5)
        stable = len(steady) == 5 and all(steady)
        secondary_ready = direct(lab, secondary, HEALTH) == "ok"
        lab.check("green", "Envoy removes the stopped backend and the shared endpoint then serves sustained reads",
                  ejected and stable and secondary_ready and not active(lab, primary),
                  {"active_health_ejection_observed": ejected, "steady_shared_reads": sum(steady),
                   "healthy_backend_ready": secondary_ready, "https_liveness_backends": 2})

    restored = until(lambda: direct(lab, primary, HEALTH) == "ok", 95)
    reentered = until(lambda: bool(envoy_events(lab, balancer, "add_healthy_event", primary_addresses)
                                   - prior_reentries), 30)
    both = restored and all(namespace(direct(lab, item, API)) for item in expected)
    shared_again = shared(lab)
    lab.check("positive", "The restored backend returns to the eligible pool and authenticated reads succeed",
              both and reentered and shared_again, {"both_backends_readable": both,
                                                     "active_health_reentry_observed": reentered,
                                                     "shared_endpoint_readable": shared_again})
    (lab.evidence / "api-endpoint-failover-observations.json").write_text(json.dumps({
        "both_initial_backends_ready": ready, "pinned_failed": pinned_failed, "shared_reads_after_ejection": stable,
        "initial_outage_probe_attempts": len(observed),
        "initial_outage_probe_errors": observed.count(False),
        "seconds_until_ejection_observed": round(time_to_eject, 3),
        "both_backends_restored": both, "probe_type": "HTTPS", "probe_path": probe_path,
        "healthy_threshold": probe["healthy_threshold"], "unhealthy_threshold": probe["unhealthy_threshold"],
        "production_slo_tested": False,
    }, indent=2) + "\n")
