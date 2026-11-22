"""Verify native bound-token revocation and an offline external-provider fixture."""
import copy
import json
from pathlib import Path
import subprocess
import time

NAMESPACE = "saf-1005-022-credential-lab"
ACCOUNT = "recovery-fixture"
USERNAME = f"system:serviceaccount:{NAMESPACE}:{ACCOUNT}"
AUDIENCE = "urn:example:saf-k8s-1005-022:verification"
SCOPE = (
    "One disposable single-node Kind cluster using the digest-pinned Kubernetes v1.36.1 node image. "
    "The native check creates one ServiceAccount and case-owned empty marker Secrets, issues two "
    "short-lived Secret-bound tokens, and observes them only through Kubernetes TokenReview before "
    "and after marker retirement/replacement. External access is modeled by an offline fictional "
    "provider fixture with inert identity labels and no credential values or network calls. This "
    "does not prove production runbook authorization, token discovery/inventory, production "
    "workload adoption, provider-side enforcement or revocation latency, or behavior of other "
    "credential kinds."
)


def create(lab, obj):
    return json.loads(lab.kubectl(
        "-n", NAMESPACE, "create", "-f", "-", "-o", "json",
        payload=json.dumps(obj),
    ).stdout)


def private_kubectl(lab, *args, payload=None):
    """Call kubectl without routing token-bearing data through the evidence logger."""
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", NAMESPACE, "--request-timeout=8s", *args,
    ]
    try:
        result = subprocess.run(
            command, input=payload, text=True, capture_output=True, env=lab.env, timeout=12,
        )
    except (OSError, subprocess.TimeoutExpired):
        lab.block("Private fixture credential operation could not complete")
    if result.returncode:
        # Never echo stderr: TokenReview inputs and implementation diagnostics are private.
        operation = "TokenReview" if payload is not None else "TokenRequest"
        lab.block(f"Private fixture {operation} failed (response suppressed)")
    return result.stdout.strip()


def marker_secret(lab, name):
    return create(lab, {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {"saf-k8s.example/fixture": "1005-022-marker-only"},
        },
        "type": "Opaque",
    })


def issue_bound_token(lab, marker_name, marker_uid):
    # The returned bearer value exists only in this process and is never logged or serialized.
    token = private_kubectl(
        lab, "create", "token", ACCOUNT, "--duration=10m", "--audience", AUDIENCE,
        "--bound-object-kind", "Secret", "--bound-object-name", marker_name,
        "--bound-object-uid", marker_uid,
    )
    if not token or "\n" in token:
        lab.block("TokenRequest returned no single fixture credential")
    return token


def token_review(lab, token):
    request = {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "spec": {"token": token, "audiences": [AUDIENCE]},
    }
    response = json.loads(private_kubectl(
        lab, "create", "-f", "-", "-o", "json", payload=json.dumps(request),
    ))
    status = response.get("status", {})
    authenticated = bool(status.get("authenticated", False))
    # Only bounded identity and outcome fields leave this function; token and errors do not.
    observed = {
        "authenticated": authenticated,
        "username_matches_case_service_account": (
            status.get("user", {}).get("username") == USERNAME if authenticated else False
        ),
        "audience_matches": AUDIENCE in status.get("audiences", []) if authenticated else False,
    }
    if authenticated and not all((
        observed["username_matches_case_service_account"], observed["audience_matches"],
    )):
        lab.block("TokenReview authenticated a fixture token with an unexpected identity or audience")
    return observed


def fictional_provider_verify(fixture, identity_label):
    """Offline policy fixture: an inert label is accepted only while its state is active."""
    record = fixture["identities"].get(identity_label)
    return bool(record and record.get("state") in fixture["allowed_states"])


def verify_native(lab):
    create(lab, {
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {"name": ACCOUNT, "namespace": NAMESPACE},
        "automountServiceAccountToken": False,
    })
    old_name = "retired-token-marker"
    replacement_name = "replacement-token-marker"
    old_marker = marker_secret(lab, old_name)
    replacement_marker = marker_secret(lab, replacement_name)
    old_token = issue_bound_token(lab, old_name, old_marker["metadata"]["uid"])
    replacement_token = issue_bound_token(
        lab, replacement_name, replacement_marker["metadata"]["uid"],
    )

    old_before = token_review(lab, old_token)
    replacement_before = token_review(lab, replacement_token)
    lab.check(
        "red", "Before retirement both independently issued fixture credentials authenticate",
        old_before["authenticated"] and replacement_before["authenticated"],
        {"retired_candidate": old_before, "replacement": replacement_before,
         "audience": AUDIENCE, "credential_values_recorded": False},
    )

    lab.kubectl("-n", NAMESPACE, "delete", "secret", old_name, "--wait=true")
    deadline = time.monotonic() + 75
    old_after = token_review(lab, old_token)
    while old_after["authenticated"] and time.monotonic() < deadline:
        time.sleep(1)
        old_after = token_review(lab, old_token)
    replacement_after = token_review(lab, replacement_token)
    lab.check(
        "green", "Deleting the old bound marker makes its token fail TokenReview while replacement stays valid",
        not old_after["authenticated"] and replacement_after["authenticated"],
        {"retired_candidate": old_after, "replacement": replacement_after,
         "retirement_action": "deleted case-owned Secret marker",
         "credential_values_recorded": False},
    )

    recreated_marker = marker_secret(lab, old_name)
    same_name_different_uid = recreated_marker["metadata"]["uid"] != old_marker["metadata"]["uid"]
    old_after_recreate = token_review(lab, old_token)
    replacement_after_recreate = token_review(lab, replacement_token)
    lab.check(
        "positive", "A same-name marker replacement does not revive the retired token",
        same_name_different_uid and not old_after_recreate["authenticated"]
        and replacement_after_recreate["authenticated"],
        {"same_name_recreated": True, "uid_changed": same_name_different_uid,
         "retired_candidate": old_after_recreate, "replacement": replacement_after_recreate,
         "credential_values_recorded": False},
    )

    lab.kubectl("-n", NAMESPACE, "delete", "secret", replacement_name, "--wait=true")
    lab.kubectl("-n", NAMESPACE, "delete", "secret", old_name, "--wait=true")
    return {
        "service_account": f"{NAMESPACE}/{ACCOUNT}",
        "retired_marker_uid": old_marker["metadata"]["uid"],
        "replacement_marker_uid": replacement_marker["metadata"]["uid"],
        "same_name_replacement_uid": recreated_marker["metadata"]["uid"],
        "old_valid_before": old_before["authenticated"],
        "replacement_valid_before": replacement_before["authenticated"],
        "old_valid_after_retirement": old_after["authenticated"],
        "replacement_valid_after_retirement": replacement_after["authenticated"],
        "old_valid_after_same_name_recreate": old_after_recreate["authenticated"],
        "replacement_valid_after_same_name_recreate": replacement_after_recreate["authenticated"],
        "audience": AUDIENCE,
        "token_values_recorded": False,
        "review_error_details_recorded": False,
    }


def verify_fictional_provider(lab):
    fixture_path = Path(__file__).with_name("fictional-provider.json")
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    if fixture.get("mode") != "in-memory verifier fixture; no network client or endpoint":
        lab.block("External provider fixture is not explicitly offline")
    if fixture.get("labels_are_credentials") is not False:
        lab.block("External provider labels must remain inert, non-credential identifiers")

    retired = "fictional-label-001"
    replacement = "fictional-label-002"
    unrelated = "fictional-label-003"
    initial = {label: fictional_provider_verify(fixture, label)
               for label in (retired, replacement, unrelated)}
    lab.check(
        "red", "Offline fictional provider verifier accepts old, replacement and unrelated labels before rotation",
        all(initial.values()),
        {"provider_mode": "offline-fictional-fixture", "accepted": initial,
         "labels_are_credentials": False},
    )

    transitioned = copy.deepcopy(fixture)
    transitioned["identities"][retired]["state"] = "retired"
    after = {label: fictional_provider_verify(transitioned, label)
             for label in (retired, replacement, unrelated)}
    lab.check(
        "green", "Retiring the old provider label denies it while replacement remains accepted",
        not after[retired] and after[replacement],
        {"provider_mode": "offline-fictional-fixture",
         "retired_identity": {"label": retired, "state": "retired", "accepted": after[retired]},
         "replacement_identity": {"label": replacement, "state": "active", "accepted": after[replacement]},
         "retire_and_replace": True, "credential_values_recorded": False},
    )
    lab.check(
        "positive", "Provider fixture transition leaves unrelated identity accepted and retired identity denied",
        after[unrelated] and not after[retired],
        {"unrelated_identity": {"label": unrelated, "accepted": after[unrelated]},
         "retired_identity": {"label": retired, "accepted": after[retired]},
         "external_service_contacted": False},
    )
    return {
        "fixture_id": fixture["fixture_id"],
        "provider_mode": "offline-fictional-fixture",
        "initial_acceptance": initial,
        "post_transition_acceptance": after,
        "old_identity_state_after": "retired",
        "replacement_identity_state_after": "active",
        "identity_labels_are_credentials": False,
        "external_service_contacted": False,
    }


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    native = verify_native(lab)
    provider = verify_fictional_provider(lab)
    evidence = {
        "control_id": "SAF-K8S-1005-022",
        "scope": "case-owned Kubernetes Secret-bound TokenRequest tokens and offline fictional provider fixture only",
        "native_observations": native,
        "external_fixture_observations": provider,
        "checks": lab.checks,
        "secrets_included": False,
        "bearer_tokens_included": False,
    }
    (lab.evidence / "credential-observations.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
