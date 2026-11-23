"""Reconcile covered Kubernetes binding and Vault issuance metadata without retaining values."""

import base64
import json
from pathlib import Path
import runpy
import time
from types import SimpleNamespace

from fixtures import ready

HERE = Path(__file__).resolve().parent
vault = SimpleNamespace(**runpy.run_path(str(HERE / "vault_fixture.py")))
WORKLOAD = "fixture-inventory-workload"
COLLECTOR = "fixture-inventory-reader"
LABEL = "owned-credential-inventory"
SCOPE = (
    "Collect actual metadata for a known projected Kubernetes credential and enumerated "
    "Vault service tokens. Verify issuer state, Pod identity, defined expiry, explicit missing "
    "coverage and failure handling. Kubernetes cluster-wide TokenRequest enumeration, "
    "Vault dynamic secret lease inventory, cloud and external issuers need separate evidence."
)


def issue(lab, token, owner, label, ttl):
    payload = {"policies": ["fixture-empty-token"], "no_default_policy": True, "ttl": ttl,
               "meta": {"source": LABEL, "owner": owner, "name": label}}
    return vault.required(lab, "auth/token/create", token=token, body=payload)["auth"]["accessor"]


def vault_records(lab, credential):
    status, listing = vault.request(lab, "auth/token/accessors", token=credential, method="LIST")
    if status != 200:
        return {"coverage": "unavailable", "rows": None}
    records = []
    for cursor in listing["data"]["keys"]:
        code, info = vault.request(lab, "auth/token/lookup-accessor", token=credential, body={"accessor": cursor})
        if code != 200:
            # A concurrent lapse makes this collection incomplete.
            return {"coverage": "unavailable", "rows": None}
        data = info["data"]
        meta = data.get("meta") or {}
        if meta.get("source") != LABEL or data.get("ttl", 0) <= 0:
            continue
        records.append({"source": "vault-service-token", "owner_uid": meta["owner"], "label": meta["name"],
                         "expires_at": data["expire_time"]})
    return {"coverage": "collected", "rows": sorted(records, key=lambda row: row["label"])}


def k8s_status(lab, token):
    payload = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
               "spec": {"token": token, "audiences": [vault.AUDIENCE]}}
    output = vault.private(lab, "create", "-f", "-", "-o", "json", payload=json.dumps(payload))
    if not output:
        lab.block("The owned token metadata check could not finish")
    return json.loads(output)["status"]


def projected(lab):
    token = vault.private(lab, "exec", WORKLOAD, "--", "cat", "/fixture-identity/token")
    if not token:
        lab.block("The known fixture workload token was unavailable")
    encoded = token.strip().split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    identity = claims["kubernetes.io"]
    review = k8s_status(lab, token.strip())
    pod_uid = lab.kubectl("get", "pod/" + WORKLOAD, "-o", "jsonpath={.metadata.uid}").stdout.strip()
    valid = (review.get("authenticated") is True and review.get("audiences") == [vault.AUDIENCE]
             and review.get("user", {}).get("username") == f"system:serviceaccount:{vault.NS}:{WORKLOAD}"
             and identity["pod"]["uid"] == pod_uid)
    if not valid:
        lab.block("The observed projected metadata did not match the actual owned Pod and issuer decision")
    return {"source": "known-kubernetes-projection", "owner_uid": pod_uid, "audiences": claims["aud"],
            "issuer": claims["iss"], "expires_at": claims["exp"]}


def snapshot(lab, sources, namespace="saf-test"):
    doc = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "fixture-credential-metadata", "namespace": namespace},
           "data": {"inventory": json.dumps(sources, sort_keys=True)}}
    lab.create(doc)
    value = lab.kubectl("get", "configmap/fixture-credential-metadata", "-o",
                        "jsonpath={.data.inventory}").stdout
    return json.loads(value)


def run(lab):
    root = vault.start(lab)
    vault.workload(lab, WORKLOAD, identity=True)
    ready(lab, WORKLOAD)
    kubernetes = projected(lab)
    native_secret_objects = lab.kubectl("get", "secrets", "--field-selector",
                                       "type=kubernetes.io/service-account-token", "-o", "name").stdout.strip()
    resource_list = json.loads(lab.kubectl("get", "--raw=/api/v1").stdout)["resources"]
    verbs = next(row["verbs"] for row in resource_list if row["name"] == "serviceaccounts/token")
    covered_not_listable = "create" in verbs and "list" not in verbs
    lab.check("red", "Secret inventory misses a valid projected token and the native subresource does not enumerate issued tokens",
              not native_secret_objects and covered_not_listable,
              {"known_projected_token_authenticates": True, "legacy_token_secret_list_empty": not native_secret_objects,
               "token_request_list_not_available": covered_not_listable})

    vault.permissions(lab, root, COLLECTOR, {"auth/token/accessors": ["list", "sudo"],
                                            "auth/token/lookup-accessor": ["update", "sudo"]})
    vault.permissions(lab, root, "fixture-empty-token", {"transit/keys/fixture-unused": ["read"]})
    inventory = vault.scoped_token(lab, root, COLLECTOR)
    denied_identity = vault.scoped_token(lab, root, "fixture-empty-token")
    issue(lab, root, kubernetes["owner_uid"], "longer", "10m")
    expires = issue(lab, root, kubernetes["owner_uid"], "short", "18s")
    first = vault_records(lab, inventory)
    labels = {row["label"] for row in first["rows"] or []}
    all_bound = all(row["owner_uid"] == kubernetes["owner_uid"] for row in first["rows"] or [])
    failed = vault_records(lab, denied_identity)
    saved = snapshot(lab, {
        "vault": first, "kubernetes": {"coverage": "known-projection-only", "rows": [kubernetes]},
        "unconnected_cloud": {"coverage": "unavailable", "rows": None},
    })
    fresh = (first["coverage"] == "collected" and labels == {"longer", "short"} and all_bound
             and saved["vault"] == first and saved["kubernetes"]["rows"] == [kubernetes])
    unavailable = failed == saved["unconnected_cloud"] == {"coverage": "unavailable", "rows": None}
    lab.check("green", "The collector records covered metadata and marks denied or unconnected sources as unavailable",
              fresh and unavailable, {"matched_known_source_metadata": fresh, "failed_or_absent_is_unknown": unavailable})

    deadline = time.monotonic() + 50
    expired = False
    after = {}
    while time.monotonic() < deadline:
        code, _ = vault.request(lab, "auth/token/lookup-accessor", token=inventory, body={"accessor": expires})
        after = vault_records(lab, inventory)
        expired = code in (400, 404) and after["coverage"] == "collected" and {
            row["label"] for row in after["rows"] or []} == {"longer"}
        if expired:
            break
        time.sleep(1)
    historical = {row["label"] for row in saved["vault"]["rows"]} == {"longer", "short"}
    lab.check("positive", "The provider expires the short-lived credential while a separate active token remains in inventory",
              expired and historical, {"released_from_active_inventory": expired, "prior_metadata_remains_available": historical})
    (lab.evidence / "credential-inventory-observations.json").write_text(json.dumps({
        "observed_projected_identity": True, "vault_active_after_issue": sorted(labels),
        "vault_active_after_expiration": [row["label"] for row in after["rows"]],
        "known_sources_metadata_only": fresh, "unavailable_sources_explicit": unavailable,
        "prior_inventory_available": historical,
    }, indent=2) + "\n")
