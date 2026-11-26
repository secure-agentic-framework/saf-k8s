"""Verify separated aggregation inputs and a distinct release decision."""
import importlib.util
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
NS = "saf-test"
RBAC = "rbac.authorization.k8s.io/v1"
GROUP = "rbac.authorization.k8s.io"
ACTORS = ("alpha", "beta", "east", "west", "release")
LANES = ("east", "west")
MEMBERS = ("alpha", "beta")
CODE = "fixture-aggregate-code"
PLAINTEXT = "fixture-original-public-input"
RUNTIME = "SAF-K8S-0908-001"
SCOPE = (
    "Two temporary contributors create complementary modular shares with fresh masks in actual pods. "
    "Separately authenticated aggregators process only their respective share records. A release "
    "principal reads only lane totals, withholds an undersized cohort, and returns the correct "
    "two-contributor sum. A second fixed vector round checks ServiceAccount-to-member binding, "
    "named-share write denial, sequential replay rejection, and a mismatched-lane dropout hold. "
    "This is a reference share lifecycle, not a cryptographic secure-aggregation protocol. "
    "Production protocol review, collusion resistance, atomic replay fencing, dropout recovery, "
    "release privacy and managed operator isolation require their own evidence."
)


def runtime_fixture():
    path = HERE.parent / RUNTIME / "case.py"
    spec = importlib.util.spec_from_file_location("saf_fixture_runtime", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def principal(actor):
    return "fixture-aggregate-"+actor


def rule(names, verbs):
    return {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": names, "verbs": verbs}


def grant(lab, label, actor, rules):
    create(lab, "Role", label, RBAC, rules=rules)
    create(lab, "RoleBinding", label, RBAC, roleRef={"apiGroup": GROUP, "kind": "Role", "name": label},
           subjects=[{"kind": "ServiceAccount", "name": principal(actor), "namespace": NS}])


def share(lane, member):
    return f"fixture-share-{lane}-{member}"


def total(lane):
    return f"fixture-total-{lane}"


def vector_share(lane, member):
    return f"fixture-vector-{lane}-{member}"


def vector_total(lane):
    return f"fixture-vector-total-{lane}"


def vector_receipt(member):
    return f"fixture-vector-receipt-{member}"


def deploy(lab, image):
    create(lab, "ConfigMap", CODE, immutable=True,
           data={"aggregation.py": (HERE/"aggregation.py").read_text()})
    for actor in ACTORS:
        name = principal(actor)
        create(lab, "ServiceAccount", name, automountServiceAccountToken=True)
        unit = container("fixture", image=image, imagePullPolicy="Never", command=["sleep", "300"],
                         volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True}])
        lab.create(pod(name, [unit], serviceAccountName=name,
                       volumes=[{"name": "code", "configMap": {"name": CODE}}]))

    for lane in LANES:
        for member in MEMBERS:
            create(lab, "ConfigMap", share(lane, member), data={"round": "fixture-round",
                                                               "member": member, "value": ""})
        create(lab, "ConfigMap", total(lane), data={"round": "fixture-round", "cohort": "[]", "total": "0"})
        grant(lab, principal(lane), lane, [rule([share(lane, member) for member in MEMBERS], ["get"]),
                                          rule([total(lane)], ["patch"])])
    for member in MEMBERS:
        grant(lab, principal(member), member, [rule([share(lane, member) for lane in LANES], ["patch"])])
    grant(lab, principal("release"), "release", [rule([total(lane) for lane in LANES], ["get"])])


def execute(lab, actor, *args):
    out = lab.kubectl("exec", principal(actor), "--", "python",
                      "/fixture/aggregation.py", *args, timeout=20)
    return json.loads(out.stdout)


def sum_lanes(lab, expected):
    return all(result == {"named_share_record_count": expected}
               for result in [execute(lab, lane, "summarize", lane) for lane in LANES])


def vector_round(lab):
    for lane in LANES:
        for member in MEMBERS:
            create(lab, "ConfigMap", vector_share(lane, member), data={
                "round": "fixture-vector-round-v1", "member": member,
                "submission_id": "", "value": "",
            })
        create(lab, "ConfigMap", vector_total(lane), data={
            "round": "fixture-vector-round-v1", "cohort": "[]", "total": "[]",
        })
        grant(lab, "fixture-vector-lane-"+lane, lane, [
            rule([vector_share(lane, member) for member in MEMBERS], ["get"]),
            rule([vector_total(lane)], ["patch"]),
        ])
    for member in MEMBERS:
        create(lab, "ConfigMap", vector_receipt(member), data={
            "round": "fixture-vector-round-v1", "submission_id": "",
        })
        grant(lab, "fixture-vector-member-"+member, member, [
            rule([vector_share(lane, member) for lane in LANES], ["get"]),
            rule([vector_share(lane, member) for lane in LANES] + [vector_receipt(member)], ["patch"]),
            rule([vector_receipt(member)], ["get"]),
        ])
    grant(lab, "fixture-vector-release", "release", [
        rule([vector_total(lane) for lane in LANES], ["get"]),
    ])
    review_role = {
        "apiGroups": ["authentication.k8s.io"],
        "resources": ["selfsubjectreviews"],
        "verbs": ["create"],
    }
    create(lab, "ClusterRole", "fixture-aggregate-self-identity", RBAC,
           rules=[review_role])
    create(lab, "ClusterRoleBinding", "fixture-aggregate-self-identity", RBAC,
           roleRef={"apiGroup": GROUP, "kind": "ClusterRole",
                    "name": "fixture-aggregate-self-identity"},
           subjects=[{"kind": "ServiceAccount", "name": principal(actor),
                      "namespace": NS} for actor in ACTORS])


def vector_identity_replay_dropout(lab):
    vector_round(lab)
    alpha_id = "fixture-vector-round-v1-alpha"
    beta_id = "fixture-vector-round-v1-beta"
    alpha_value = "[11,3]"
    beta_value = "[7,5]"

    beta_before = execute(lab, "beta", "observe-vector", "beta", "east", "")
    foreign_patch = execute(lab, "alpha", "attempt-foreign-vector")
    beta_after = execute(lab, "beta", "observe-vector", "beta", "east", "")

    alpha = execute(lab, "alpha", "contribute-vector", "alpha", alpha_id, alpha_value)
    beta_identity_mismatch = execute(lab, "beta", "contribute-vector", "alpha", alpha_id,
                                     "[11,3]")
    beta_blank_after_mismatch = execute(lab, "beta", "observe-vector", "beta", "east", "")
    beta = execute(lab, "beta", "contribute-vector", "beta", beta_id, beta_value)
    replay = execute(lab, "alpha", "replay-probe", "alpha", alpha_id, alpha_value)

    lane_counts = [execute(lab, lane, "summarize-vector", lane)["named_share_record_count"]
                   for lane in LANES]
    approved = execute(lab, "release", "release-vector")
    dropout = execute(lab, "beta", "drop-vector", "beta", "west")
    after_dropout_counts = [execute(lab, lane, "summarize-vector", lane)["named_share_record_count"]
                            for lane in LANES]
    held = execute(lab, "release", "release-vector")

    observed = {
        "foreign_named_share_patch_forbidden": foreign_patch.get("status") == 403
        and foreign_patch.get("identity_bound") is True,
        "foreign_patch_left_target_record_unchanged": beta_before.get("matches") is True
        and beta_after.get("matches") is True,
        "request_member_must_match_authenticated_serviceaccount":
        beta_identity_mismatch == {"decision": "held", "reason": "identity-mismatch", "status": 403}
        and beta_blank_after_mismatch.get("matches") is True,
        "authenticated_participants_submit_once": alpha.get("identity_bound") is True
        and beta.get("identity_bound") is True and lane_counts == [2, 2],
        "sequential_replay_rejected_before_state_change": replay == {
            "decision": "held", "status": 409, "state_unchanged": True},
        "approved_fixed_vector_aggregate": approved == {
            "decision": "released", "contributors": 2, "vector": [18, 8]},
        "asymmetric_dropout_makes_lane_cohorts_mismatch": dropout.get("status") == 200
        and after_dropout_counts == [2, 1]
        and held == {"decision": "held", "reason": "cohort-policy"},
    }
    return observed


def run(lab):
    image = runtime_fixture().load_runtime(lab)
    deploy(lab, image)
    create(lab, "ConfigMap", PLAINTEXT, data={"value": "37"})
    grant(lab, "fixture-direct-input", "release", [rule([PLAINTEXT], ["get"])])
    for actor in ACTORS:
        ready(lab, principal(actor))

    direct = execute(lab, "release", "observe", PLAINTEXT, "37")
    baseline = {"direct_aggregate_boundary_has_access_to_original_input": direct == {
        "status": 200, "marker_matches": True}}
    lab.check("red", "A directly granted path exposes an individual synthetic input",
              all(baseline.values()), baseline)

    lab.kubectl("delete", "rolebinding", "fixture-direct-input", "--wait=true")
    for _ in range(8):
        denied = execute(lab, "release", "observe", PLAINTEXT)
        if denied == {"status": 403}:
            break
        time.sleep(.5)
    submitted = execute(lab, "alpha", "contribute", "alpha", "37")
    summed_single = sum_lanes(lab, 1)
    withheld = execute(lab, "release", "release")
    isolated = {"contributor_submitted_two_shares": submitted["submitted_two_lanes"],
                "separated_lanes_summed_only_one_contributor": summed_single,
                "release_cannot_read_original_or_shares": denied == {"status": 403}
                and execute(lab, "release", "observe", share("east", "alpha")) == {"status": 403},
                "lane_cannot_read_the_other_share": execute(lab, "east", "observe", share("west", "alpha"))
                == {"status": 403} and execute(lab, "west", "observe", share("east", "alpha")) == {"status": 403},
                "undersized_cohort_has_no_result": withheld == {"decision": "held", "reason": "cohort-policy"}}
    lab.check("green", "Share and result boundaries independently enforce their configured conditions",
              all(isolated.values()), isolated)

    second = execute(lab, "beta", "contribute", "beta", "52")
    summed_full = sum_lanes(lab, 2)
    full = execute(lab, "release", "release")
    approved = {"second_contributor_submits_two_shares": second["submitted_two_lanes"],
                "both_lanes_process_the_two_named_inputs": summed_full,
                "exact_aggregate_only_result": full == {"decision": "released", "contributors": 2, "sum": 89}}
    lab.check("positive", "The intended cohort receives only the correct released aggregate",
              all(approved.values()), approved)

    binding = vector_identity_replay_dropout(lab)
    lab.check("supplement", "Authenticated vector participants, replay, and dropout stay scoped",
              all(binding.values()), binding)
    (lab.evidence/"secure-aggregation-observations.json").write_text(json.dumps({
        "baseline": baseline, "enforcement": isolated, "release": approved, "result": full,
        "vector_binding_replay_dropout": binding,
    }, indent=2)+"\n")
