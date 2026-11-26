"""Synthetic OIDC reviewer write and digest-bound admission gate."""
import base64
import hashlib
import importlib.util
import ipaddress
import json
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

_HUMAN_SPEC = importlib.util.spec_from_file_location(
    "saf_0905_057_native_human", Path(__file__).with_name("native_human.py"))
human = importlib.util.module_from_spec(_HUMAN_SPEC)
_HUMAN_SPEC.loader.exec_module(human)


NAMESPACE = "saf-test"
REVIEW_RECORD = "authenticated-model-review"
REVIEW_GROUP = "oidc-fixture:reviewers"
REVIEWER = "oidc-fixture:human-trust-reviewer"
POLICY = "authenticated-model-trust-eligibility"
DIGEST_ANNOTATION = "saf.example/model-digest"
GATE_LABEL = "saf.example/trust-review-gate"


def _api_transport(lab):
    config = yaml.safe_load(Path(lab.kubeconfig).read_text())
    context_name = f"kind-{lab.cluster}"
    context = next(row["context"] for row in config["contexts"] if row["name"] == context_name)
    cluster_config = next(row["cluster"] for row in config["clusters"]
                          if row["name"] == context["cluster"])
    server = cluster_config["server"].rstrip("/")
    parsed = urllib.parse.urlparse(server)
    host = parsed.hostname
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except (TypeError, ValueError):
        loopback = False
    if parsed.scheme != "https" or not loopback or not parsed.port:
        raise ValueError("owned Kubernetes API endpoint is not HTTPS loopback")
    ca_data = cluster_config.get("certificate-authority-data")
    ca = (base64.b64decode(ca_data).decode("ascii") if ca_data
          else Path(cluster_config["certificate-authority"]).read_text())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(
                                             context=ssl.create_default_context(cadata=ca)))
    return server, opener


def _review_request(lab, key_dir, digest, assessment_digest, *, user, groups, outcome="approved"):
    claims = {
        "iss": human.ISSUER,
        "aud": human.AUDIENCE,
        "sub": user,
        "iat": int(time.time()) - 5,
        "exp": int(time.time()) + 180,
        "groups": groups,
        "fixture_class": "human-review",
        "session": "synthetic-trust-review-session",
        "approval_path": {"candidate_digest": digest, "assessment_sha256": assessment_digest,
                          "decision": outcome, "criteria_revision": "fixture-trust-v1"},
    }
    token = human.mint_jwt(lab, key_dir / "approved.key", claims)
    record = {
        "candidate": "eligible",
        "digest": digest,
        "decision": outcome,
        "reviewer": "oidc-fixture:" + user,
        "criteria_revision": "fixture-trust-v1",
        "assessment_sha256": assessment_digest,
        "rationale": "fixed synthetic trust criteria reviewed for this candidate",
        "evidence_ref": "case-owned:SAF-K8S-0905-057:synthetic-review",
    }
    expected = {"approvedDigest": digest if outcome == "approved" else "",
                "record.json": json.dumps(record, sort_keys=True, separators=(",", ":"))}
    try:
        base, opener = _api_transport(lab)
        url = (base + f"/api/v1/namespaces/{NAMESPACE}/configmaps/{REVIEW_RECORD}")
        request = urllib.request.Request(
            url, data=json.dumps({"data": expected}, separators=(",", ":")).encode(),
            headers={"Authorization": "Bearer " + token,
                     "Content-Type": "application/merge-patch+json"}, method="PATCH")
        try:
            with opener.open(request, timeout=10) as response:
                status = response.status
                response.read()
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
        if status != 200:
            return status, False
        readback = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
        with opener.open(readback, timeout=10) as response:
            stored = json.load(response).get("data", {})
        return status, stored == expected
    except (OSError, ValueError, KeyError, StopIteration, yaml.YAMLError,
            urllib.error.URLError, json.JSONDecodeError):
        return 0, False
    finally:
        token = None


def _pod_request(lab, digest, candidate):
    from fixtures import container, pod

    obj = pod("review-gate-" + candidate, [container("inert-model-reference")],
              automountServiceAccountToken=False)
    obj["metadata"].update(
        labels={"saf.example/workload": "model", GATE_LABEL: "required"},
        annotations={DIGEST_ANNOTATION: digest})
    return lab.create(obj, dry_run=True, allow_failure=True)


def _policy_resources(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": REVIEW_RECORD, "namespace": NAMESPACE},
                "data": {"approvedDigest": "", "record.json": "{}"}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "authenticated-model-review", "namespace": NAMESPACE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": [REVIEW_RECORD], "verbs": ["get", "patch"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": "authenticated-model-review", "namespace": NAMESPACE},
                "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group",
                              "name": REVIEW_GROUP}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": "authenticated-model-review"}})
    policy = {
        "failurePolicy": "Fail",
        "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
        "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                  "resources": ["pods"], "operations": ["CREATE"]}]},
        "validations": [{
            "expression": (f"params != null && has(object.metadata.annotations) && "
                           f"'{DIGEST_ANNOTATION}' in object.metadata.annotations && "
                           f"object.metadata.annotations['{DIGEST_ANNOTATION}'].matches('^sha256:[a-f0-9]{{64}}$') && "
                           f"object.metadata.annotations['{DIGEST_ANNOTATION}'] == params.data.approvedDigest"),
            "message": "model digest lacks authenticated trust review",
            "reason": "Forbidden",
        }],
    }
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1",
                "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": policy})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1",
                "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                          "paramRef": {"name": REVIEW_RECORD, "namespace": NAMESPACE,
                                       "parameterNotFoundAction": "Deny"},
                          "matchResources": {
                              "namespaceSelector": {"matchLabels": {
                                  "kubernetes.io/metadata.name": NAMESPACE}},
                              "objectSelector": {"matchLabels": {GATE_LABEL: "required"}}}}})


def _wait_api_ready(lab, timeout=70):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready = lab.kubectl("get", "--raw=/readyz", allow_failure=True, timeout=10)
        if ready.returncode == 0 and ready.stdout.strip() == "ok":
            return
        time.sleep(1)
    lab.block("The owned Kubernetes API did not become ready after reviewer-authenticator cleanup")


def run(lab, approved_digest, rejected_digest, assessment):
    """Add a synthetic authenticated-review path after the original 5 checks."""
    assessment_digest = hashlib.sha256(json.dumps(
        assessment, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    _policy_resources(lab)
    precondition = False
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        initially_blocked = _pod_request(lab, approved_digest, "eligible")
        if (initially_blocked.returncode != 0 and POLICY in initially_blocked.stderr
                and "model digest lacks authenticated trust review" in initially_blocked.stderr):
            precondition = True
            break
        time.sleep(0.3)

    node = f"{lab.cluster}-control-plane"
    with tempfile.TemporaryDirectory(prefix="saf-0905-057-oidc-") as temp_name:
        temp = Path(temp_name)
        configured = False
        issuer_started = False
        try:
            issuer_started = True
            human.start_issuer(lab, node, temp, Path(__file__).with_name("issuer.py"))
            previous = human.api_container(lab, node)
            if not previous:
                lab.block("The owned API container is unavailable before reviewer setup")
            configured = True
            human.configure_api(lab, node, temp)
            human.wait_api_replacement(lab, node, previous)

            denied_status, _ = _review_request(
                lab, temp, approved_digest, assessment_digest,
                user="unapproved-probe", groups=[])
            lab.check("green", "An authenticated OIDC identity outside the reviewer group cannot write a disposition",
                      denied_status == 403, {"unapproved_reviewer_write_denied": denied_status == 403})

            allowed_status, readback = _review_request(
                lab, temp, approved_digest, assessment_digest,
                user="human-trust-reviewer", groups=["reviewers"])
            lab.check("identity", "The native OIDC reviewer writes and reads back a disposition bound to the exact candidate digest",
                      allowed_status == 200 and readback,
                      {"reviewer_write_succeeded": allowed_status == 200,
                       "exact_digest_bound_record_readback": readback})

            approved_ok = rejected_ok = False
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                approved = _pod_request(lab, approved_digest, "eligible")
                rejected = _pod_request(lab, rejected_digest, "ineligible")
                approved_ok = approved.returncode == 0
                # Either active trust policy can refuse the ineligible comparison first.
                rejected_ok = rejected.returncode != 0 and any(
                    reason in rejected.stderr
                    for reason in ("model digest lacks authenticated trust review",
                                   "model digest lacks approved trust disposition")
                )
                if approved_ok and rejected_ok:
                    break
                time.sleep(0.3)
            lab.check("positive", "The active review policy admits only the digest approved by the authenticated reviewer",
                      precondition and approved_ok and rejected_ok,
                      {"approval_required_for_previously_eligible_digest": precondition,
                       "eligible_digest_admitted": approved_ok,
                       "unreviewed_digest_denied_by_trust_policy": rejected_ok})
            (lab.evidence / "authenticated-trust-review.json").write_text(json.dumps({
                "unauthorized_reviewer_denied": denied_status == 403,
                "authenticated_review_record_readback": allowed_status == 200 and readback,
                "policy_precondition_denied": precondition,
                "approved_digest_admitted": approved_ok,
                "unreviewed_digest_denied": rejected_ok,
            }, indent=2, sort_keys=True) + "\n")
        finally:
            if issuer_started:
                active = human.api_container(lab, node) if configured else None
                human.restore_api(lab, node)
                if active:
                    human.wait_api_replacement(lab, node, active)
                else:
                    _wait_api_ready(lab)
