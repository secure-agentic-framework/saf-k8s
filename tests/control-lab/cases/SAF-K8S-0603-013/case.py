"""Require exact signed build, promotion and runtime observations at each transition."""
import base64
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA = "https://slsa.dev/provenance/v1"
LINK = "https://in-toto.io/attestation/link/v0.3"
BUILD_ID = "https://saf-k8s.example/lab/package-builder/v1"
BUILD_TYPE = "https://saf-k8s.example/lab/build-types/import-pinned-image/v1"
TO = "promotion/verified"
ACTORS = ("build", "promotion", "deploy")
SCOPE = (
    "One disposable Kind cluster and an owned OCI registry. The trusted fixture packages a "
    "pinned harmless image, verifies independent signed build and promotion records before "
    "release and deployment, and verifies a signed destination observation before downstream "
    "use. Registry replication, target platform identity and operational key custody stay "
    "under their own deployment review."
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def descriptor(name, digest):
    return {"name": name, "digest": {"sha256": digest.removeprefix("sha256:")}}


def envelope_digest(record):
    return sha256(canonical(record)).hexdigest()


def load_image_fixture():
    file = HERE.parent / "SAF-K8S-0602-004" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_chain_registry_fixture", file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Signers:
    def __init__(self, lab):
        self.lab = lab
        self.root = lab.kubeconfig.parent / "chain-keys"
        self.root.mkdir(mode=0o700)
        public = set()
        for role in ACTORS:
            private = self.root / (role + ".key")
            pub = self.root / (role + ".pub")
            lab.command("openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private))
            private.chmod(0o600)
            lab.command("openssl", "pkey", "-in", str(private), "-pubout", "-out", str(pub))
            public.add(sha256(pub.read_bytes()).hexdigest())
        if len(public) != len(ACTORS):
            lab.block("Each stage must have a distinct public key")
        self.message = self.root / "verified-message"
        self.signature = self.root / "verified-signature"

    def dsse_message(self, payload):
        preamble = f"DSSEv1 {len(PAYLOAD_TYPE)} {PAYLOAD_TYPE} {len(payload)} ".encode("ascii")
        self.message.write_bytes(preamble + payload)

    def sign(self, role, statement):
        payload = canonical(statement)
        self.dsse_message(payload)
        self.lab.command("openssl", "dgst", "-sha256", "-sign", str(self.root / (role + ".key")),
                         "-out", str(self.signature), str(self.message))
        return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode("ascii"),
                "signatures": [{"sig": base64.b64encode(self.signature.read_bytes()).decode("ascii")}]}

    def verify(self, role, record):
        if record["payloadType"] != PAYLOAD_TYPE or len(record["signatures"]) != 1:
            return None
        payload = base64.b64decode(record["payload"], validate=True)
        self.dsse_message(payload)
        self.signature.write_bytes(base64.b64decode(record["signatures"][0]["sig"], validate=True))
        result = self.lab.command("openssl", "dgst", "-sha256", "-verify", str(self.root / (role + ".pub")),
                                  "-signature", str(self.signature), str(self.message), allow_failure=True)
        return json.loads(payload) if result.returncode == 0 and "Verified OK" in result.stdout else None


def statement(kind, subject, predicate):
    return {"_type": STATEMENT_TYPE, "predicateType": kind, "subject": [subject], "predicate": predicate}


def build_statement(source, subject, issued):
    return statement(SLSA, subject, {
        "buildDefinition": {"buildType": BUILD_TYPE, "externalParameters": {"source": source["name"]},
                            "resolvedDependencies": [source]},
        "runDetails": {"builder": {"id": BUILD_ID}, "metadata": {"invocationId": "saf-0603-013",
                                                               "fixtureIssuedEpoch": issued}},
    })


def link_statement(stage, subject, previous, prior_subject, time_value, **byproducts):
    return statement(LINK, subject, {
        "name": stage, "command": [], "materials": [prior_subject],
        "byproducts": byproducts, "environment": {"predecessorDigest": envelope_digest(previous),
                                                 "fixtureIssuedEpoch": time_value},
    })


def record_at(signers, record, role, subject, predicate_type):
    content = signers.verify(role, record)
    if (content is None or content.get("_type") != STATEMENT_TYPE
            or content.get("predicateType") != predicate_type or content.get("subject") != [subject]):
        return None
    return content["predicate"]


def build_ok(signers, record, source, subject, now):
    data = record_at(signers, record, "build", subject, SLSA)
    if not data:
        return False
    when = data["runDetails"]["metadata"]["fixtureIssuedEpoch"]
    return (
        0 <= now - when <= 600 and data["buildDefinition"]["resolvedDependencies"] == [source]
        and data["buildDefinition"]["buildType"] == BUILD_TYPE
        and data["runDetails"]["builder"]["id"] == BUILD_ID
    )


def link_ok(signers, record, role, subject, predecessor, previous_subject, now, **byproducts):
    content = record_at(signers, record, role, subject, LINK)
    if not content:
        return False
    context = content["environment"]
    return (
        content["name"] == role and content["materials"] == [previous_subject]
        and content["byproducts"] == byproducts
        and context["predecessorDigest"] == envelope_digest(predecessor)
        and 0 <= now - context["fixtureIssuedEpoch"] <= 600
    )


def promote(lab, image, registry, net, record, *, target_repository=TO):
    target = f"{registry}:5000/{target_repository}:verified"
    origin = f"{registry}:5000/{record['repository']}@{record['digest']}"
    lab.command("docker", "run", "--rm", "--network", net, "--cap-drop=ALL",
                "--security-opt=no-new-privileges", image.SKOPEO, "copy", "--preserve-digests",
                "--src-tls-verify=false", "--dest-tls-verify=false",
                f"docker://{origin}", f"docker://{target}", timeout=100)
    return {**record, "repository": target_repository}


def stored(image, port, repo, ref):
    status, data, _ = image.request(port, "GET", f"/v2/{repo}/manifests/{ref}",
                                    headers={"Accept": image.IMAGE_MANIFEST})
    return status, image.content_digest(data)


def gate_deployment(lab, image, registry, evidence, validated):
    if not validated:
        return False
    image.deploy(lab, registry, evidence)
    return True


def exercise(lab, image, registry, node, net):
    port = image.registry_port(lab, registry)
    lab.command("docker", "pull", BUSYBOX_IMAGE, timeout=140)
    output = image.seed_image(lab, node, net, registry)
    staged, result_digest = output["repository"], output["digest"]
    if stored(image, port, staged, result_digest) != (200, result_digest):
        lab.block("Lab packaging did not publish the verified image bytes")
    source = descriptor(BUSYBOX_IMAGE, BUSYBOX_IMAGE.rsplit("@", 1)[1])
    build_subject = descriptor(staged, result_digest)
    prod_subject = descriptor(TO, result_digest)
    signers = Signers(lab)
    fixture_time = int(time.time())
    build = signers.sign("build", build_statement(source, build_subject, fixture_time))
    stale = signers.sign("build", build_statement(source, build_subject, fixture_time - 601))
    wrong_material = descriptor(BUSYBOX_IMAGE, "0" * 64)
    wrong = signers.sign("build", build_statement(wrong_material, build_subject, fixture_time))

    ungated = "promotion/baseline"
    promote(lab, image, registry, net, output, target_repository=ungated)
    no_gate = stored(image, port, ungated, "verified") == (200, result_digest)
    lab.check("red", "The registry alone copies the image without an attestation check",
              no_gate, {"unverified_registry_copy_observed": no_gate})

    def verified_promotion(envelope):
        if not build_ok(signers, envelope, source, build_subject, int(time.time())):
            return None
        return promote(lab, image, registry, net, output)

    guards = {"unapproved_build_material_rejected": verified_promotion(wrong) is None,
              "stale_build_rejected": verified_promotion(stale) is None,
              "promotion_output_still_absent": stored(image, port, TO, "verified")[0] == 404}
    lab.check("green", "Signed stale and incorrect build material cannot authorize promotion", all(guards.values()), guards)
    release = verified_promotion(build)
    lab.check("positive", "The approved signing identity binds the actual staging subject to the expected input",
              release is not None, {"build_verified_before_promotion": release is not None})
    copied = stored(image, port, TO, "verified") == (200, result_digest)
    lab.check("positive", "Promotion preserves the exact verified image bytes in a separate OCI repository",
              copied, {"promoted_digest_matches_build": copied})

    promotion_message = link_statement("promotion", prod_subject, build, build_subject, fixture_time)
    promotion = signers.sign("promotion", promotion_message)
    wrong_key = signers.sign("build", promotion_message)
    wrong_prior = signers.sign("promotion", link_statement("promotion", prod_subject, stale,
                                                           build_subject, fixture_time))
    def verified_deployment(build_record, promotion_record):
        now = int(time.time())
        eligible = build_ok(signers, build_record, source, build_subject, now) and link_ok(
            signers, promotion_record, "promotion", prod_subject, build_record, build_subject, now)
        return gate_deployment(lab, image, registry, release, eligible)

    rejected = {
        "wrong_stage_key_rejected": not verified_deployment(build, wrong_key),
        "wrong_predecessor_rejected": not verified_deployment(build, wrong_prior),
        "stale_build_rejected_at_deploy": not verified_deployment(stale, wrong_prior),
        "deployment_still_absent": not lab.kubectl(
            "get", "deployment", "retained-release", "--ignore-not-found", "-o", "name"
        ).stdout.strip(),
    }
    lab.check("green", "The deployment gate rejects the wrong identity, predecessor or stale upstream build",
              all(rejected.values()), rejected)
    deployed = verified_deployment(build, promotion)
    lab.check("green", "The deployment transition verifies the exact build and promotion chain",
              deployed, {"correct_predecessor_and_promotion_identity": deployed})

    actual = json.loads(lab.kubectl("get", "deployment", "retained-release", "-o", "json").stdout)
    exact = actual["spec"]["template"]["spec"]["containers"][0]["image"].endswith(f"/{TO}@{result_digest}")
    logged_uid = actual["metadata"]["uid"]
    destination = descriptor("kubernetes:saf-test/retained-release", result_digest)
    deployment = signers.sign("deploy", link_statement(
        "deploy", destination, promotion, prod_subject, fixture_time, deploymentUid=logged_uid))
    expected = link_ok(signers, deployment, "deploy", destination, promotion, prod_subject,
                       fixture_time, deploymentUid=logged_uid)
    different_uid = link_ok(signers, deployment, "deploy", destination, promotion, prod_subject,
                            fixture_time, deploymentUid="different-deployment")
    lab.check("positive", "Downstream use verifies the runtime stage's signed observation for the exact deployment",
              exact and expected and not different_uid,
              {"runtime_digest_matches_promoted_digest": exact, "destination_observation_verified": expected,
               "different_workload_uid_rejected": not different_uid})
    (lab.evidence / "attestation-chain.json").write_text(json.dumps({
        "descriptors": {"build": build_subject, "promotion": prod_subject, "deploy": destination},
        "bound_envelope_digests": {"build": envelope_digest(build), "promotion": envelope_digest(promotion),
                                  "deploy": envelope_digest(deployment)},
        "kubernetes_deployment_uid_verified": True, "signer_count": len(ACTORS),
    }, indent=2, sort_keys=True) + "\n")


def run(lab):
    image = load_image_fixture()
    node = f"{lab.cluster}-control-plane"
    registry, network = f"{lab.cluster}-chain-registry", f"{lab.cluster}-chain-net"
    lab.command("docker", "network", "create", network)
    started = False
    try:
        lab.command("docker", "network", "connect", network, node)
        lab.command("docker", "run", "--detach", "--name", registry, "--network", network,
                    "--network-alias", registry, "--publish", "127.0.0.1::5000", image.REGISTRY)
        started = True
        exercise(lab, image, registry, node, network)
    finally:
        if started:
            lab.command("docker", "rm", "-fv", registry)
        lab.command("docker", "network", "disconnect", "-f", network, node, allow_failure=True)
        lab.command("docker", "network", "rm", network)
