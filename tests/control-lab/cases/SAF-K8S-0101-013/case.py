"""Check kubeadm API serving-certificate renewal on the owned Kind endpoint."""
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse


SCOPE = (
    "Kubernetes v1.36.1 kubeadm-managed API server serving certificate on the one "
    "fresh runner-owned Kind cluster's host-published loopback endpoint. The case "
    "checks the expiry of a short-lived serving leaf, records out-of-window and due "
    "decisions from two controller-owned CronJob Jobs, then renews within the fixture lead time. "
    "A separate fixture approval record gates the runner's one native renewal call; the synthetic approver "
    "and runner are not a deployed approval service. The scheduler identity cannot renew or access node material. "
    "It observes the live process before and after "
    "the documented static-Pod restart, and validates local TLS trust and IP "
    "identity. External PKI and other certificate paths, replicas, and deployment scheduling "
    "remain separate adoption evidence. A final comparison sequentially "
    "serves the renewed old-CA leaf and a synthetic successor-CA leaf at the same "
    "loopback origin, checking old-only, overlap, and new-only client trust plus "
    "readiness, then restores the renewed leaf. It does not rotate the cluster CA."
)

TIMEOUT = 5
RELOAD_OBSERVATION_SECONDS = 5
POD_STOP_DEADLINE = 60
POD_READY_SECONDS = 120
RENEW_BEFORE_SECONDS = 30 * 60
SCHEDULE_INPUT = "saf-0101-013-schedule-input"
SCHEDULE_NOT_DUE = "saf-0101-013-schedule-not-due"
SCHEDULE_DUE = "saf-0101-013-schedule-due"
SCHEDULER = "saf-0101-013-scheduler"
RENEWAL_REQUEST = "saf-0101-013-renewal-request"
RENEWAL_APPROVAL = "saf-0101-013-renewal-approval"
APPROVER = "saf-0101-013-renewal-approver"


def run_scheduled_decision(lab, initial, node):
    """Require two CronJob-owned decisions, then leave renewal to the runner."""
    directory = Path(__file__).resolve().parent
    scheduler_image = (
        "docker.io/library/python:3.13-slim@sha256:"
        "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
    )
    if f"image: {scheduler_image}" not in (directory / "cronjob.yaml").read_text():
        lab.block("The scheduled Job image does not match the reviewed content pin")
    # Populate this fresh node's image store before starting the Job deadline.
    lab.command("docker", "exec", node, "crictl", "pull", scheduler_image, timeout=120)
    leaf = {"not_after_epoch": str(initial["expiry"]),
            "leaf_sha256": initial["leaf"], "lead_seconds": "60",
            "receipt_name": SCHEDULE_NOT_DUE}
    receipts = (SCHEDULE_NOT_DUE, SCHEDULE_DUE)
    resources = [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": SCHEDULE_INPUT},
         "data": leaf},
        *[{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
           "data": {"decision": "pending"}} for name in receipts],
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": RENEWAL_APPROVAL},
         "data": {"decision": "pending"}},
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": "saf-0101-013-scheduler-code"},
         "data": {"dispatch.py": (directory / "dispatch.py").read_text()}},
    ]
    created = []
    job_selector = f"app.kubernetes.io/name={SCHEDULER}"

    def receipt(name):
        return json.loads(lab.kubectl("get", "configmap", name, "-o", "json").stdout).get("data", {})

    def wait_receipt(name, expected):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            data = receipt(name)
            if data.get("decision") == expected and data.get("job_name"):
                jobs = json.loads(lab.kubectl(
                    "get", "jobs", "-l", job_selector, "-o", "json").stdout)["items"]
                owners = [job for job in jobs if job["metadata"]["name"] == data["job_name"]
                          and job.get("status", {}).get("succeeded") == 1
                          and any(owner.get("kind") == "CronJob" and owner.get("uid") == owner_uid
                                  and owner.get("controller") is True
                                  for owner in job["metadata"].get("ownerReferences", []))]
                if len(owners) == 1:
                    return data, owners[0]
            time.sleep(2)
        latest = json.loads(lab.kubectl(
            "get", "jobs", "-l", job_selector, "-o", "json").stdout)["items"]
        status = [{key: row.get("status", {}).get(key, 0)
                   for key in ("active", "succeeded", "failed")} for row in latest]
        (lab.evidence / "scheduled-renewal-timeout.json").write_text(
            json.dumps({"expected": expected, "jobs": status}, indent=2) + "\n")
        lab.block(f"Timed out waiting for the CronJob-owned {expected} receipt")

    try:
        for resource in resources:
            lab.create(resource)
            created.append(("configmap", resource["metadata"]["name"]))
        created.extend((kind, name) for kind, name in (
            ("serviceaccount", SCHEDULER), ("role", SCHEDULER),
            ("rolebinding", SCHEDULER), ("cronjob", SCHEDULER)))
        lab.apply(directory / "cronjob.yaml")
        role = json.loads(lab.kubectl("get", "role", SCHEDULER, "-o", "json").stdout)
        rules = role.get("rules", [])
        scoped_rules = sorted((tuple(row.get("apiGroups", [])), tuple(row.get("resources", [])),
                               tuple(sorted(row.get("resourceNames", []))), tuple(row.get("verbs", [])))
                              for row in rules)
        expected_rules = sorted([
            (("",), ("configmaps",), (SCHEDULE_INPUT,), ("get",)),
            (("",), ("configmaps",), tuple(sorted(receipts)), ("patch",)),
        ])
        lab.check("positive", "The scheduler identity has only named input and receipt ConfigMap access",
                  scoped_rules == expected_rules,
                  {"exact_named_rbac": scoped_rules == expected_rules,
                   "rule_count": len(rules)})
        cronjob = json.loads(lab.kubectl("get", "cronjob", SCHEDULER, "-o", "json").stdout)
        owner_uid = cronjob["metadata"]["uid"]
        subject = f"system:serviceaccount:saf-test:{SCHEDULER}"
        permission_checks = (
            ("get", f"configmaps/{SCHEDULE_INPUT}", "yes"),
            ("patch", f"configmaps/{SCHEDULE_DUE}", "yes"),
            ("patch", f"configmaps/{SCHEDULE_NOT_DUE}", "yes"),
            ("patch", f"configmaps/{SCHEDULE_INPUT}", "no"),
            ("get", f"configmaps/{RENEWAL_REQUEST}", "no"),
            ("patch", f"configmaps/{RENEWAL_APPROVAL}", "no"),
            ("get", "secrets", "no"),
            ("create", "pods", "no"),
            ("get", "nodes", "no"),
        )
        decisions_match = all(
            lab.kubectl("auth", "can-i", verb, resource, "--as", subject,
                        "--as-group=system:serviceaccounts",
                        "--as-group=system:serviceaccounts:saf-test",
                        "--as-group=system:authenticated",
                        timeout=15, allow_failure=True).stdout.strip() == expected
            for verb, resource, expected in permission_checks
        )
        scheduler_subject = f"system:serviceaccount:saf-test:{SCHEDULER}"
        scheduler_groups = ("--as-group=system:serviceaccounts", "--as-group=system:serviceaccounts:saf-test",
                            "--as-group=system:authenticated")
        unauthorized_patch = lab.kubectl(
            "patch", "configmap", RENEWAL_APPROVAL, "--type=merge",
            "-p", '{"data":{"decision":"approved"}}', "--as", scheduler_subject,
            *scheduler_groups, timeout=15, allow_failure=True)
        scheduler_cannot_approve = (unauthorized_patch.returncode != 0
                                    and "forbidden" in unauthorized_patch.stderr.lower())
        lab.check("positive", "Scheduled identity authorization permits named receipts and denies node, Secret and Pod access",
                  decisions_match and scheduler_cannot_approve,
                  {"all_expected_authorization_decisions": decisions_match,
                   "actual_approval_patch_denied": scheduler_cannot_approve})
        pod = cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        container = pod["containers"][0]
        safe_pod = (pod.get("serviceAccountName") == SCHEDULER
                    and not pod.get("hostNetwork", False)
                    and not pod.get("hostPID", False)
                    and not pod.get("hostIPC", False)
                    and not any("hostPath" in volume for volume in pod.get("volumes", []))
                    and not pod.get("securityContext", {}).get("privileged", False)
                    and not container.get("securityContext", {}).get("privileged", False)
                    and container.get("securityContext", {}).get("readOnlyRootFilesystem") is True
                    and container.get("securityContext", {}).get("allowPrivilegeEscalation") is False
                    and not any("kubeconfig" in mount.get("mountPath", "")
                                or "/etc/kubernetes/pki" in mount.get("mountPath", "")
                                for mount in container.get("volumeMounts", [])))
        lab.check("positive", "The scheduled Pod has no node credentials or host access",
                  safe_pod, {"bounded_nonprivileged_pod": safe_pod})

        first, first_job = wait_receipt(SCHEDULE_NOT_DUE, "not_due")
        first_expiry = int(first["not_after_epoch"])
        first_observed = int(first["observed_at_epoch"])
        first_ok = (first.get("leaf_sha256") == initial["leaf"]
                    and first_expiry == int(initial["expiry"])
                    and int(first["lead_seconds"]) == 60
                    and first_expiry - first_observed > 60
                    and first["job_name"] == first_job["metadata"]["name"]
                    and set(first) == {"decision", "leaf_sha256", "not_after_epoch",
                                       "lead_seconds", "observed_at_epoch", "job_name", "request_id"})
        lab.check("positive", "The first scheduled controller-owned Job records the out-of-window serving leaf",
                  first_ok, {"job_owned_by_cronjob": True, "exact_leaf_bound": first_ok,
                             "decision": first.get("decision")})

        lab.kubectl("patch", "cronjob", SCHEDULER, "--type=merge", "-p",
                    '{"spec":{"suspend":true}}', timeout=15)
        due_input = {**leaf, "lead_seconds": str(RENEW_BEFORE_SECONDS), "receipt_name": SCHEDULE_DUE}
        lab.kubectl("patch", "configmap", SCHEDULE_INPUT, "--type=merge", "-p",
                    json.dumps({"data": due_input}, separators=(",", ":")), timeout=15)
        suspended = json.loads(lab.kubectl("get", "cronjob", SCHEDULER, "-o", "json").stdout)
        if suspended.get("spec", {}).get("suspend") is not True:
            lab.block("Could not suspend scheduling while staging the second named receipt")
        lab.kubectl("patch", "cronjob", SCHEDULER, "--type=merge", "-p",
                    '{"spec":{"suspend":false}}', timeout=15)
        second, second_job = wait_receipt(SCHEDULE_DUE, "renewal_request")
        remaining = int(second["not_after_epoch"]) - int(second["observed_at_epoch"])
        second_ok = (second.get("leaf_sha256") == initial["leaf"]
                     and int(second["not_after_epoch"]) == int(initial["expiry"])
                     and int(second["lead_seconds"]) == RENEW_BEFORE_SECONDS
                     and 0 < remaining <= RENEW_BEFORE_SECONDS
                     and second["request_id"] == initial["leaf"] + ":" + str(initial["expiry"])
                     and second["job_name"] == second_job["metadata"]["name"]
                     and second["job_name"] != first["job_name"]
                     and set(second) == {"decision", "leaf_sha256", "not_after_epoch",
                                         "lead_seconds", "observed_at_epoch", "job_name", "request_id"})
        lab.check("positive", "The second scheduled controller-owned Job requests renewal inside the approved fixture window",
                  second_ok, {"distinct_cronjob_owned_job": second["job_name"] != first["job_name"],
                              "exact_leaf_bound": second_ok, "within_lead_time": 0 < remaining <= RENEW_BEFORE_SECONDS})
        jobs = json.loads(lab.kubectl(
            "get", "jobs", "-l", job_selector, "-o", "json").stdout)["items"]
        successful_names = {job["metadata"]["name"] for job in jobs
                            if job.get("status", {}).get("succeeded") == 1
                            and any(owner.get("kind") == "CronJob" and owner.get("uid") == owner_uid
                                    and owner.get("controller") is True
                                    for owner in job["metadata"].get("ownerReferences", []))}
        lab.check("positive", "Exactly two successful controller-owned Jobs produced the named decisions",
                  successful_names == {first["job_name"], second["job_name"]},
                  {"two_named_controller_jobs": successful_names ==
                   {first["job_name"], second["job_name"]}})
        (lab.evidence / "scheduled-renewal-observations.json").write_text(
            json.dumps({"out_of_window": first, "due": second}, indent=2, sort_keys=True) + "\n")
        return second

    finally:
        lab.kubectl("delete", "cronjob", SCHEDULER, "--ignore-not-found=true", timeout=15,
                    allow_failure=True)
        for kind, name in reversed(created):
            if kind == "cronjob":
                continue
            lab.kubectl("delete", kind, name, "--ignore-not-found=true", timeout=15,
                        allow_failure=True)


def endpoint_and_ca(lab):
    """Read only the endpoint and public CA from this run's generated kubeconfig."""
    context = f"kind-{lab.cluster}"
    common = (
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", context,
        "config", "view", "--minify", "-o",
    )
    server = lab.command(*common, "jsonpath={.clusters[0].cluster.server}").stdout.strip()
    encoded_ca = lab.command(
        *common, "jsonpath={.clusters[0].cluster.certificate-authority-data}", "--raw"
    ).stdout.strip()
    try:
        parsed = urllib.parse.urlsplit(server)
        address = parsed.hostname
        port = parsed.port
        ip = ipaddress.ip_address(address)
        ca_pem = base64.b64decode(encoded_ca, validate=True)
    except (ValueError, TypeError) as error:
        lab.block(f"Invalid generated Kind endpoint or CA ({type(error).__name__})")
    if parsed.scheme != "https" or not ip.is_loopback or not port or not ca_pem:
        lab.block("Refusing certificate probes except HTTPS to the generated loopback endpoint")
    return address, port, ca_pem


def tls_context(ca_pem):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cadata=ca_pem.decode("ascii"))
    return context


def probe(address, port, context, server_name):
    """Read verified leaf identity and expiry for this fixture only."""
    raw = socket.create_connection((address, port), timeout=TIMEOUT)
    tls = None
    try:
        tls = context.wrap_socket(raw, server_hostname=server_name)
        leaf = tls.getpeercert(binary_form=True)
        expiry = ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"])
        return {"verified": True, "leaf": hashlib.sha256(leaf).hexdigest(), "expiry": expiry}
    except ssl.SSLCertVerificationError:
        return {"verified": False, "leaf": None, "certificate_rejected": True}
    except ssl.SSLError:
        return {"verified": False, "leaf": None, "certificate_rejected": False}
    finally:
        if tls is not None:
            tls.close()
        else:
            raw.close()


def make_throwaway_ca(directory):
    """Create a one-day synthetic CA used only as a deliberately wrong trust anchor."""
    key = directory / "wrong-ca.key"
    cert = directory / "wrong-ca.crt"
    result = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1", "-sha256",
         "-subj", "/CN=SAF-K8S-0101-013 throwaway wrong CA"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode:
        raise RuntimeError("Could not create the ephemeral wrong-trust-anchor fixture")
    os.chmod(key, 0o600)
    return cert.read_bytes()


def assert_owned_control_plane_node(lab):
    expected = f"{lab.cluster}-control-plane"
    nodes = lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines()
    if nodes != [expected]:
        lab.block("Expected exactly the one fresh runner-owned Kind control-plane node")
    return expected


def renew_certificate(lab, node):
    """Invoke kubeadm renewal inside only the verified runner-owned node container."""
    config_path = "/etc/kubernetes/saf-serving-renewal.yaml"
    policy = ("apiVersion: kubeadm.k8s.io/v1beta4\n"
              "kind: ClusterConfiguration\n"
              "certificateValidityPeriod: 8760h0m0s\n")
    lab.command("docker", "exec", "-i", node, "sh", "-ceu", 'cat >"$1"',
                "write-fixture-certificate-policy", config_path, payload=policy)
    result = lab.command(
        "docker", "exec", node, "kubeadm", "certs", "renew", "apiserver",
        "--config", config_path, timeout=90,
    )
    lab.check(
        "green", "kubeadm certs renew apiserver completed inside the owned control-plane node",
        result.returncode == 0, {"renewal_command_succeeded": result.returncode == 0},
    )
    return result.returncode == 0


def handoff_allows(request, approval, current_leaf, expected_leaf, expected_expiry, now):
    """Accept only one unexpired due request approved for its exact leaf."""
    request_id = expected_leaf + ":" + str(expected_expiry)
    try:
        due = (request.get("decision") == "renewal_request"
               and request.get("request_id") == request_id
               and request.get("leaf_sha256") == expected_leaf
               and int(request.get("not_after_epoch", "0")) == expected_expiry
               and 0 < expected_expiry - now <= int(request.get("lead_seconds", "0")))
        approved = (approval.get("decision") == "approved"
                    and approval.get("request_id") == request_id
                    and approval.get("leaf_sha256") == expected_leaf
                    and int(approval.get("not_after_epoch", "0")) == expected_expiry
                    and approval.get("approved_by") == f"system:serviceaccount:saf-test:{APPROVER}")
    except (TypeError, ValueError):
        return False
    return due and approved and current_leaf == expected_leaf


def approved_renewal_handoff(lab, node, initial, request, verify_served_leaf):
    """Require a separately authorized exact request before one native renewal."""
    request_id = initial["leaf"] + ":" + str(initial["expiry"])
    resources = [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": RENEWAL_REQUEST, "namespace": "saf-test"},
         "data": {key: str(request.get(key, "")) for key in
                  ("decision", "request_id", "leaf_sha256", "not_after_epoch", "lead_seconds", "job_name")}},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": RENEWAL_APPROVAL, "namespace": "saf-test"},
         "data": {"decision": "pending"}},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": APPROVER, "namespace": "saf-test"},
         "automountServiceAccountToken": False},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
         "metadata": {"name": APPROVER, "namespace": "saf-test"},
         "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                    "resourceNames": [RENEWAL_APPROVAL], "verbs": ["get", "patch"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
         "metadata": {"name": APPROVER, "namespace": "saf-test"},
         "subjects": [{"kind": "ServiceAccount", "name": APPROVER, "namespace": "saf-test"}],
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": APPROVER}},
    ]
    created = []
    subject = f"system:serviceaccount:saf-test:{APPROVER}"
    invoked_request_ids = set()
    groups = ("--as-group=system:serviceaccounts", "--as-group=system:serviceaccounts:saf-test",
              "--as-group=system:authenticated")
    try:
        for resource in resources:
            lab.create(resource)
            created.append((resource["kind"].lower(), resource["metadata"]["name"]))
        role = json.loads(lab.kubectl("get", "role", APPROVER, "-n", "saf-test", "-o", "json").stdout)
        exact_role = role.get("rules") == [{"apiGroups": [""], "resources": ["configmaps"],
                                             "resourceNames": [RENEWAL_APPROVAL], "verbs": ["get", "patch"]}]
        permission = lambda verb, resource, as_subject: lab.kubectl(
            "auth", "can-i", verb, resource, "-n", "saf-test", "--as", as_subject, *groups,
            timeout=15, allow_failure=True).stdout.strip()
        allowed = all(permission(verb, f"configmaps/{RENEWAL_APPROVAL}", subject) == "yes"
                      for verb in ("get", "patch"))
        denied = all(permission(verb, resource, subject) == "no" for verb, resource in (
            ("get", f"configmaps/{RENEWAL_REQUEST}"), ("patch", f"configmaps/{RENEWAL_REQUEST}"),
            ("list", "configmaps"), ("get", "secrets"),
            ("get", "nodes"), ("create", "pods")))
        lab.check("positive", "The approval identity can read and patch only its named renewal approval record",
                  exact_role and allowed and denied,
                  {"exact_named_role": exact_role, "approval_get_and_patch_allowed": allowed,
                   "other_request_secret_node_and_pod_access_denied": denied})

        now = int(time.time())
        empty = {"decision": "pending"}
        mismatch = {"decision": "approved", "request_id": "wrong-request",
                    "leaf_sha256": initial["leaf"], "not_after_epoch": str(initial["expiry"]),
                    "approved_by": subject}
        stale = {"decision": "approved", "request_id": request_id,
                 "leaf_sha256": "0" * 64, "not_after_epoch": str(initial["expiry"]),
                 "approved_by": subject}
        request_matches = (request.get("decision") == "renewal_request"
                           and request.get("request_id") == request_id
                           and request.get("leaf_sha256") == initial["leaf"]
                           and int(request.get("not_after_epoch", "0")) == int(initial["expiry"]))
        denied_controls = {
            "pending_approval_denied": not handoff_allows(request, empty, initial["leaf"], initial["leaf"], int(initial["expiry"]), now),
            "wrong_request_id_denied": not handoff_allows(request, mismatch, initial["leaf"], initial["leaf"], int(initial["expiry"]), now),
            "stale_leaf_denied": not handoff_allows(request, stale, initial["leaf"], initial["leaf"], int(initial["expiry"]), now),
        }
        approved = {"decision": "approved", "request_id": request_id,
                    "leaf_sha256": initial["leaf"], "not_after_epoch": str(initial["expiry"]),
                    "approved_by": subject}
        wrong_approver = {**approved, "approved_by": "system:serviceaccount:saf-test:unapproved"}
        not_due_request = {**request, "decision": "not_due", "request_id": ""}
        denied_controls["changed_current_leaf_denied"] = not handoff_allows(
            request, approved, "f" * 64, initial["leaf"], int(initial["expiry"]), now)
        denied_controls["expired_request_denied"] = not handoff_allows(
            request, approved, initial["leaf"], initial["leaf"], int(initial["expiry"]),
            int(initial["expiry"]) + 1)
        denied_controls["wrong_approver_denied"] = not handoff_allows(
            request, wrong_approver, initial["leaf"], initial["leaf"], int(initial["expiry"]), now)
        denied_controls["out_of_window_request_denied"] = not handoff_allows(
            not_due_request, approved, initial["leaf"], initial["leaf"], int(initial["expiry"]), now)
        no_renewal_before_approval = not invoked_request_ids
        lab.check("red", "Unapproved, mismatched or stale renewal requests cannot reach kubeadm",
                  request_matches and all(denied_controls.values()) and no_renewal_before_approval,
                  {"request_bound_to_current_leaf": request_matches, **denied_controls,
                   "native_renewal_not_invoked_for_denied_cases": no_renewal_before_approval})

        def invoke_native_once(candidate_request, candidate_approval, current_leaf):
            if not handoff_allows(candidate_request, candidate_approval, current_leaf,
                                  initial["leaf"], int(initial["expiry"]), int(time.time())):
                return False
            candidate_id = candidate_request["request_id"]
            if candidate_id in invoked_request_ids:
                return False
            invoked_request_ids.add(candidate_id)
            return renew_certificate(lab, node)

        patch = {"data": {"decision": "approved", "request_id": request_id,
                          "leaf_sha256": initial["leaf"], "not_after_epoch": str(initial["expiry"]),
                          "approved_by": subject}}
        lab.kubectl("patch", "configmap", RENEWAL_APPROVAL, "-n", "saf-test", "--type=merge",
                    "-p", json.dumps(patch, separators=(",", ":")), "--as", subject, *groups, timeout=15)
        approval = json.loads(lab.kubectl("get", "configmap", RENEWAL_APPROVAL, "-n", "saf-test", "-o", "json").stdout).get("data", {})
        actual = verify_served_leaf()
        valid = (actual.get("verified") and actual.get("expiry") == initial["expiry"]
                 and handoff_allows(request, approval, actual["leaf"], initial["leaf"],
                                    int(initial["expiry"]), int(time.time())))
        if not valid:
            lab.block("The scheduled due request lacks an exact live approval; refusing native renewal")
        lab.check("positive", "The separately authorized approval matches the due request and current public leaf",
                  valid, {"exact_request_and_leaf_approved": valid,
                          "approver_identity": APPROVER, "public_key_material_only": True})
        renewed = invoke_native_once(request, approval, actual["leaf"])
        if renewed:
            lab.kubectl("patch", "configmap", RENEWAL_APPROVAL, "-n", "saf-test", "--type=merge",
                        "-p", json.dumps({"data": {"decision": "consumed", "consumed_request_id": request_id}},
                                          separators=(",", ":")), timeout=15)
        consumed = json.loads(lab.kubectl("get", "configmap", RENEWAL_APPROVAL, "-n", "saf-test", "-o", "json").stdout).get("data", {})
        duplicate_attempt_rejected = not invoke_native_once(request, consumed, initial["leaf"])
        renewal_invocation_count = len(invoked_request_ids)
        replay_denied = (renewed and consumed.get("decision") == "consumed"
                         and consumed.get("consumed_request_id") == request_id
                         and duplicate_attempt_rejected and renewal_invocation_count == 1)
        lab.check("positive", "The approved handoff invokes the native kubeadm renewal path exactly once",
                  valid and renewed and renewal_invocation_count == 1,
                  {"approved_request": valid, "renewal_invocation_count": renewal_invocation_count,
                                     "native_command_succeeded": renewed})
        lab.check("positive", "Consumed renewal request cannot authorize a duplicate action",
                  replay_denied, {"request_consumed": consumed.get("decision") == "consumed",
                                  "duplicate_request_denied": replay_denied})
        (lab.evidence / "renewal-approval-handoff.json").write_text(json.dumps({
            "request_matched_due_job": request_matches, "approver_role_exact": exact_role,
            "approval_identity": APPROVER, "approval_matches_leaf": valid,
            "native_renewal_invocations": renewal_invocation_count, "denied_controls": denied_controls,
            "consumed_request_replay_denied": replay_denied,
            "approval_service_account_has_node_credentials": False,
        }, indent=2, sort_keys=True) + "\n")
    finally:
        for kind, name in reversed(created):
            lab.kubectl("delete", kind, name, "-n", "saf-test", "--ignore-not-found=true",
                        timeout=15, allow_failure=True)


def restart_static_apiserver(lab, node, *, record=True):
    """Use kubeadm docs' manifest removal procedure and always restore the manifest."""
    manifest = "/etc/kubernetes/manifests/kube-apiserver.yaml"
    parked = "/etc/kubernetes/kube-apiserver.saf-0101-013.yaml"
    running = ("docker", "exec", node, "crictl", "ps", "--name", "kube-apiserver", "-q")
    previous = lab.command(*running).stdout.splitlines()
    if len(previous) != 1:
        lab.block("Expected one running API server in the owned node before restart")
    moved = False
    stopped = False
    try:
        lab.command(
            "docker", "exec", node, "sh", "-ec",
            f"test -f {manifest}; test ! -e {parked}; mv {manifest} {parked}",
        )
        moved = True
        deadline = time.monotonic() + POD_STOP_DEADLINE
        while time.monotonic() < deadline:
            if not lab.command(*running).stdout.strip():
                stopped = True
                break
            time.sleep(2)
    finally:
        if moved:
            lab.command(
                "docker", "exec", node, "sh", "-ec",
                f"test -f {parked}; mv {parked} {manifest}", timeout=30,
            )
    if record:
        lab.check("green", "The owned static API server stopped while its manifest was parked",
                  stopped, {"previous_container_stopped": stopped})
    return running, previous[0]


def ready_probe(address, port, context):
    """Verify TLS identity and read /readyz, discarding response bytes afterward."""
    connection = http.client.HTTPSConnection(address, port, context=context, timeout=TIMEOUT)
    try:
        connection.request("GET", "/readyz", headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        return {
            "verified": True,
            "ready": response.status == 200 and body.strip() == b"ok",
            "http_status": response.status,
        }
    except ssl.SSLCertVerificationError:
        return {"verified": False, "ready": False, "certificate_rejected": True}
    except (OSError, ssl.SSLError, http.client.HTTPException):
        return {"verified": False, "ready": False, "certificate_rejected": False}
    finally:
        connection.close()


def wait_for_successor(address, port, overlap, fingerprint):
    deadline = time.monotonic() + POD_READY_SECONDS
    while time.monotonic() < deadline:
        if ready_probe(address, port, overlap)["ready"]:
            try:
                served = probe(address, port, overlap, address)
            except OSError:
                pass
            else:
                if served.get("leaf") == fingerprint:
                    return True
        time.sleep(1)
    return False


def make_successor_material(directory, address):
    """Create only temporary fixture keys; callers retain public receipt only."""
    ca_key, ca_cert = directory / "successor-ca.key", directory / "successor-ca.crt"
    leaf_key, csr, leaf_cert = (
        directory / "successor-apiserver.key",
        directory / "successor-apiserver.csr",
        directory / "successor-apiserver.crt",
    )
    extensions = directory / "successor-apiserver.ext"
    extensions.write_text(
        f"subjectAltName=IP:{address}\n"
        "extendedKeyUsage=serverAuth\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "authorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n",
        encoding="ascii",
    )
    commands = [
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "2", "-sha256",
         "-subj", "/CN=SAF-0101-013 fixture successor CA",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash"],
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(leaf_key), "-out", str(csr), "-sha256",
         "-subj", "/CN=kube-apiserver"],
        ["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
         "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(leaf_cert),
         "-days", "1", "-sha256", "-extfile", str(extensions)],
        ["openssl", "verify", "-CAfile", str(ca_cert), "-purpose", "sslserver",
         str(leaf_cert)],
    ]
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=30, check=False)
        if result.returncode:
            raise RuntimeError("Could not create or verify the fixture successor certificate")
    for key in (ca_key, leaf_key):
        os.chmod(key, 0o600)
    fingerprint_result = subprocess.run(
        ["openssl", "x509", "-in", str(leaf_cert), "-noout", "-fingerprint", "-sha256"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    match = re.search(r"(?:sha256 )?Fingerprint=([0-9A-Fa-f:]+)", fingerprint_result.stdout)
    if fingerprint_result.returncode or not match:
        raise RuntimeError("Could not read public successor leaf fingerprint")
    fingerprint = match.group(1).replace(":", "").lower()
    return ca_key, ca_cert, leaf_key, leaf_cert, fingerprint


def install_serving_pair(lab, node, remote_dir):
    lab.command(
        "docker", "exec", node, "sh", "-ceu",
        f"cp {remote_dir}/successor-apiserver.crt /etc/kubernetes/pki/apiserver.crt; "
        f"cp {remote_dir}/successor-apiserver.key /etc/kubernetes/pki/apiserver.key; "
        "chmod 0644 /etc/kubernetes/pki/apiserver.crt; "
        "chmod 0600 /etc/kubernetes/pki/apiserver.key",
        timeout=TIMEOUT + 5,
    )


def check_serving_ca_overlap(lab, node, address, port, old_ca_pem, old_leaf):
    old_only = tls_context(old_ca_pem)
    remote_dir = "/tmp/saf-0101-013-ca-overlap"
    created = False
    backed_up = False
    switched = False
    transition_error = None
    new_leaf_fingerprint = None
    overlap_pem = None
    new_ca_pem = None
    with tempfile.TemporaryDirectory(prefix="saf-0101-013-ca-overlap-") as temp:
        directory = Path(temp)
        try:
            _, ca_cert, leaf_key, leaf_cert, new_leaf_fingerprint = make_successor_material(
                directory, address)
            new_ca_pem = ca_cert.read_bytes()
            overlap_pem = old_ca_pem + b"\n" + new_ca_pem
            overlap = tls_context(overlap_pem)
            new_only = tls_context(new_ca_pem)
            policy_ok = (
                new_leaf_fingerprint != old_leaf
                and hashlib.sha256(new_ca_pem).digest() != hashlib.sha256(old_ca_pem).digest()
            )
            lab.check(
                "positive", "Successor server leaf chains to the distinct fixture successor CA",
                policy_ok,
                {"successor_leaf_fingerprint_differs": new_leaf_fingerprint != old_leaf,
                 "successor_CA_differs": hashlib.sha256(new_ca_pem).digest()
                 != hashlib.sha256(old_ca_pem).digest(),
                 "signature_and_server_purpose_verified": True},
            )

            original_ready = ready_probe(address, port, old_only)
            old_old_only = probe(address, port, old_only, address)
            old_overlap = probe(address, port, overlap, address)
            old_new_only = probe(address, port, new_only, address)
            old_ready_leaf = (old_old_only["verified"] and old_old_only["leaf"] == old_leaf
                              and original_ready["ready"])
            lab.check("positive", "Old served leaf validates under old-only trust before the switch",
                      old_ready_leaf and old_overlap["verified"]
                      and old_overlap["leaf"] == old_leaf,
                      {"old_only_matches_original_leaf": old_old_only.get("leaf") == old_leaf,
                       "ready_status": original_ready.get("http_status"),
                       "overlap_accepts_old_leaf": old_overlap["verified"]
                       and old_overlap["leaf"] == old_leaf})
            lab.check("red", "New-only trust rejects the old served leaf before the switch",
                      not old_new_only["verified"] and old_new_only.get("certificate_rejected", False),
                      {"certificate_rejected": old_new_only.get("certificate_rejected", False)})
            overlap_old_ready = ready_probe(address, port, overlap)
            new_only_old_ready = ready_probe(address, port, new_only)
            lab.check("positive", "Old and overlap clients can read API readiness before the switch",
                      original_ready["ready"] and overlap_old_ready["ready"],
                      {"old_only_http_status": original_ready.get("http_status"),
                       "overlap_http_status": overlap_old_ready.get("http_status")})
            lab.check("red", "New-only readiness client rejects the old served leaf before the switch",
                      not new_only_old_ready["verified"]
                      and new_only_old_ready.get("certificate_rejected", False),
                      {"certificate_rejected": new_only_old_ready.get("certificate_rejected", False)})

            lab.command("docker", "exec", node, "mkdir", "-m", "0700", remote_dir)
            created = True
            lab.command("docker", "exec", node, "cp", "-p",
                        "/etc/kubernetes/pki/apiserver.crt", f"{remote_dir}/original.crt")
            lab.command("docker", "exec", node, "cp", "-p",
                        "/etc/kubernetes/pki/apiserver.key", f"{remote_dir}/original.key")
            backed_up = True
            for material in (leaf_cert, leaf_key):
                # Stream into the node's mounted /tmp and keep fixture keys out of
                # the runner's command transcript, which records stdin.
                result = subprocess.run(
                    ["docker", "exec", "-i", node, "sh", "-ceu",
                     'umask 077; cat > "$1"', "stage-fixture-tls",
                     f"{remote_dir}/{material.name}"],
                    input=material.read_bytes(), capture_output=True, env=lab.env, timeout=TIMEOUT + 5,
                )
                if result.returncode:
                    lab.block("Could not privately stage the fixture serving certificate pair")
            switched = True
            install_serving_pair(lab, node, remote_dir)
            restart_static_apiserver(lab, node)
            if not wait_for_successor(address, port, overlap, new_leaf_fingerprint):
                lab.block("The successor leaf did not become verified and ready through overlap trust")

            new_old_only = probe(address, port, old_only, address)
            new_overlap = probe(address, port, overlap, address)
            new_new_only = probe(address, port, new_only, address)
            lab.check("red", "Old-only trust rejects the new served leaf after the switch",
                      not new_old_only["verified"]
                      and new_old_only.get("certificate_rejected", False),
                      {"certificate_rejected": new_old_only.get("certificate_rejected", False)})
            lab.check("positive", "Overlap trust accepts the new served leaf at the same API origin",
                      new_overlap["verified"] and new_overlap["leaf"] == new_leaf_fingerprint,
                      {"served_leaf_matches_successor": new_overlap.get("leaf") == new_leaf_fingerprint})
            lab.check("positive", "New-only trust accepts the new served leaf after the approved switch",
                      new_new_only["verified"] and new_new_only["leaf"] == new_leaf_fingerprint,
                      {"served_leaf_matches_successor": new_new_only.get("leaf") == new_leaf_fingerprint})
            overlap_ready = ready_probe(address, port, overlap)
            new_only_ready = ready_probe(address, port, new_only)
            old_only_ready = ready_probe(address, port, old_only)
            lab.check("positive", "API readiness succeeds through overlap trust after the switch",
                      overlap_ready["ready"], {"http_status": overlap_ready.get("http_status")})
            lab.check("positive", "API readiness succeeds through new-only trust after the switch",
                      new_only_ready["ready"], {"http_status": new_only_ready.get("http_status")})
            lab.check("red", "Old-only readiness trust rejects the new served leaf after the switch",
                      not old_only_ready["verified"]
                      and old_only_ready.get("certificate_rejected", False),
                      {"certificate_rejected": old_only_ready.get("certificate_rejected", False)})
        except Exception as error:
            transition_error = error
        finally:
            restore_ok = True
            try:
                if switched and backed_up:
                    lab.command(
                        "docker", "exec", node, "sh", "-ceu",
                        f"cp -p {remote_dir}/original.crt /etc/kubernetes/pki/apiserver.crt; "
                        f"cp -p {remote_dir}/original.key /etc/kubernetes/pki/apiserver.key",
                        timeout=TIMEOUT + 5,
                    )
                    restart_static_apiserver(lab, node, record=False)
                    restored = wait_for_verified_endpoint(lab, address, port, old_ca_pem,
                                                          POD_READY_SECONDS)
                    restore_ok = (restored["verified"] and restored.get("leaf") == old_leaf)
            except Exception:
                restore_ok = False
            finally:
                if created:
                    lab.command("docker", "exec", node, "rm", "-rf", remote_dir,
                                timeout=TIMEOUT + 5, allow_failure=True)
            if not restore_ok:
                lab.block("Could not restore and verify the original owned API serving certificate")
        if transition_error:
            raise transition_error

    restored_old = probe(address, port, old_only, address)
    restored_overlap = probe(address, port, tls_context(old_ca_pem + b"\n" + new_ca_pem), address)
    restored_new_only = probe(address, port, tls_context(new_ca_pem), address)
    lab.check("positive", "Cleanup restore serves the original renewed leaf under old-only and overlap trust",
              restored_old["verified"] and restored_old["leaf"] == old_leaf
              and restored_overlap["verified"] and restored_overlap["leaf"] == old_leaf,
              {"old_only_matches_original_leaf": restored_old.get("leaf") == old_leaf,
               "overlap_matches_original_leaf": restored_overlap.get("leaf") == old_leaf})
    lab.check("red", "New-only trust rejects the restored original leaf",
              not restored_new_only["verified"]
              and restored_new_only.get("certificate_rejected", False),
              {"certificate_rejected": restored_new_only.get("certificate_rejected", False)})
    restored_ready = ready_probe(address, port, old_only)
    overlap_restored_ready = ready_probe(address, port, tls_context(old_ca_pem + b"\n" + new_ca_pem))
    new_only_restored_ready = ready_probe(address, port, tls_context(new_ca_pem))
    lab.check("positive", "Restored API endpoint reports ready with old-only and overlap trust",
              restored_ready["ready"] and overlap_restored_ready["ready"],
              {"old_only_http_status": restored_ready.get("http_status"),
               "overlap_http_status": overlap_restored_ready.get("http_status")})
    lab.check("red", "New-only readiness client rejects the restored old leaf",
              not new_only_restored_ready["verified"]
              and new_only_restored_ready.get("certificate_rejected", False),
              {"certificate_rejected": new_only_restored_ready.get("certificate_rejected", False)})
    (lab.evidence / "serving-ca-overlap-observations.json").write_text(json.dumps({
        "origin": "runner-owned loopback API endpoint",
        "old_leaf_sha256": old_leaf,
        "successor_leaf_sha256": new_leaf_fingerprint,
        "old_ca_bundle_sha256": hashlib.sha256(old_ca_pem).hexdigest(),
        "successor_ca_bundle_sha256": hashlib.sha256(new_ca_pem).hexdigest(),
        "trust_matrix": {
            "old_leaf_old_only": old_ready_leaf,
            "old_leaf_overlap": old_overlap["verified"],
            "old_leaf_new_only_rejected": old_new_only.get("certificate_rejected", False),
            "new_leaf_old_only_rejected": new_old_only.get("certificate_rejected", False),
            "new_leaf_overlap": new_overlap["verified"],
            "new_leaf_new_only": new_new_only["verified"],
            "restored_old_leaf_old_only": restored_old["verified"],
            "restored_old_leaf_overlap": restored_overlap["verified"],
            "restored_old_leaf_new_only_rejected": restored_new_only.get("certificate_rejected", False),
        },
        "readiness": {
            "old_state_old_and_overlap_trust": original_ready["ready"] and overlap_old_ready["ready"],
            "new_state_overlap_and_new_trust": overlap_ready["ready"] and new_only_ready["ready"],
            "restored_state_old_and_overlap_trust": restored_ready["ready"] and overlap_restored_ready["ready"],
        },
        "kubeconfig_or_private_key_recorded": False,
        "provider_or_production_change": False,
    }, indent=2) + "\n")


def wait_for_verified_endpoint(lab, address, port, ca_pem, deadline_seconds):
    context = tls_context(ca_pem)
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        try:
            result = probe(address, port, context, address)
        except (OSError, ssl.SSLError):
            time.sleep(1)
            continue
        if result["verified"]:
            ready = lab.kubectl("get", "--raw=/readyz", timeout=10, allow_failure=True)
            if ready.returncode == 0 and ready.stdout.strip() == "ok":
                return result
        time.sleep(1)
    return {"verified": False, "leaf": None}


def run(lab):
    address, port, ca_pem = endpoint_and_ca(lab)
    correct = tls_context(ca_pem)
    initial = probe(address, port, correct, address)
    lab.check(
        "positive", "The generated local API endpoint initially serves a trusted certificate for its IP",
        initial["verified"], {"same_owned_loopback_endpoint": True, "verified": initial["verified"]},
    )
    if not initial["verified"]:
        lab.block("Initial local API certificate did not validate against the fresh Kind CA")

    with tempfile.TemporaryDirectory(prefix="saf-0101-013-") as temp:
        wrong_ca = make_throwaway_ca(Path(temp))
        wrong_trust = tls_context(wrong_ca)
        wrong_ca_result = probe(address, port, wrong_trust, address)
        lab.check(
            "red", "The same local API endpoint rejects a client trust store containing only the throwaway CA",
            not wrong_ca_result["verified"] and wrong_ca_result.get("certificate_rejected", False),
            {"same_owned_loopback_endpoint": True, "certificate_rejected": not wrong_ca_result["verified"]},
        )
        wrong_identity = probe(address, port, correct, "saf-0101-013.invalid")
        lab.check(
            "red", "The same local API endpoint rejects a mismatched client-side server identity",
            not wrong_identity["verified"] and wrong_identity.get("certificate_rejected", False),
            {"same_owned_loopback_endpoint": True, "identity_mismatch_rejected": not wrong_identity["verified"]},
        )

        node = assert_owned_control_plane_node(lab)
        scheduled_request = run_scheduled_decision(lab, initial, node)
        seconds_remaining = initial["expiry"] - time.time()
        lab.check("red", "The original verified certificate is outside the one-minute renewal comparison",
                  seconds_remaining > 60,
                  {"valid_leaf_outside_comparison_window": seconds_remaining > 60})
        lab.check("positive", "The original verified certificate is inside the fixture's thirty-minute renewal policy",
                  0 < seconds_remaining <= RENEW_BEFORE_SECONDS,
                  {"valid_leaf_due_for_renewal": 0 < seconds_remaining <= RENEW_BEFORE_SECONDS})
        approved_renewal_handoff(
            lab, node, initial, scheduled_request, lambda: probe(address, port, correct, address))

        # This short observation reports actual process behavior without assuming
        # that every API server build reloads this certificate dynamically.
        deadline = time.monotonic() + RELOAD_OBSERVATION_SECONDS
        observed_before_restart = None
        while time.monotonic() < deadline:
            try:
                current = probe(address, port, correct, address)
                if current["verified"]:
                    observed_before_restart = current
                    if current["leaf"] != initial["leaf"]:
                        break
            except (OSError, ssl.SSLError):
                pass
            time.sleep(0.5)

        (lab.evidence / "renewal-observation.json").write_text(json.dumps({
            "process_adopted_renewal_before_restart": bool(
                observed_before_restart and observed_before_restart["leaf"] != initial["leaf"]
            )
        }, indent=2) + "\n")

        running, previous = restart_static_apiserver(lab, node)
        after = wait_for_verified_endpoint(lab, address, port, ca_pem, POD_READY_SECONDS)
        current = lab.command(*running).stdout.splitlines()
        replaced = len(current) == 1 and current[0] != previous
        lab.check(
            "green", "Renewed certificate is served at the identical endpoint after the documented static-Pod restart",
            after["verified"] and after.get("leaf") != initial["leaf"] and replaced,
            {
                "same_owned_loopback_endpoint": True,
                "renewal_changed_leaf_fingerprint": after.get("leaf") != initial["leaf"],
                "trusted_identity_after_restart": after["verified"],
                "new_container_ready": replaced and after["verified"],
            },
        )
        if not after["verified"] or after.get("leaf") == initial["leaf"]:
            lab.block("Renewed API server certificate did not become validly served at the same endpoint")
        served_expiry = after["expiry"]
        moved_past_window = served_expiry > initial["expiry"] and (
            served_expiry - time.time() > RENEW_BEFORE_SECONDS
        )
        lab.check("green", "The renewed trusted leaf extends validity beyond the renewal lead time",
                  moved_past_window, {"renewed_leaf_outside_window": moved_past_window})

        post_wrong_ca = probe(address, port, wrong_trust, address)
        post_wrong_identity = probe(address, port, correct, "saf-0101-013.invalid")
        lab.check(
            "positive", "After renewal the same local endpoint still rejects wrong CA and wrong identity",
            not post_wrong_ca["verified"] and post_wrong_ca.get("certificate_rejected", False)
            and not post_wrong_identity["verified"]
            and post_wrong_identity.get("certificate_rejected", False),
            {
                "same_owned_loopback_endpoint": True,
                "wrong_ca_rejected_after_renewal": post_wrong_ca.get("certificate_rejected", False),
                "wrong_identity_rejected_after_renewal": post_wrong_identity.get("certificate_rejected", False),
            },
        )
        check_serving_ca_overlap(lab, node, address, port, ca_pem, after["leaf"])
