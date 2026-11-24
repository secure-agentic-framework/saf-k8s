"""Scan registry-addressed image bytes twice and enforce the latest disposition."""
import base64
import importlib.util
import json
from pathlib import Path
import time
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / "SAF-K8S-0601-008"
NS = "fixture-registry-consumers"
POLICY = "fixture-current-registry-disposition"
DECISIONS = "fixture-registry-current-approval"
ADMISSION = "admissionregistration.k8s.io/v1"
DENIED = "image does not have a current approved scan for the exact manifest digest"
REGISTRY = "fixture-scan-registry.saf-test.svc:5000/fixtures/prerelease"
SCOPE = (
    "A pinned Distribution registry holds inert image manifests. A separate registry reader retrieves "
    "the actual manifest, config and layer bytes by digest. Pinned OSV-Scanner rescans those bytes "
    "offline after the trusted synthetic advisory revision changes. Native Kubernetes admission "
    "requires the current approved exact digest in a test consumer namespace. The demonstration "
    "uses server-side Pod dry-run for admission because these images contain metadata only."
)
FETCH = r"""
import base64
import json
import sys
sys.path.insert(0, "/fixture")
from promotion_fixture import REPO, request
from image_fixture import digest
subject = sys.argv[1]
start = f"/v2/{REPO}/"
status, manifest, headers = request("GET", start + "manifests/" + subject)
if status != 200 or digest(manifest) != subject or headers["Docker-Content-Digest"] != subject:
    raise RuntimeError("Registry returned an unexpected manifest")
document = json.loads(manifest)
result = {"manifest.json": manifest}
for filename, descriptor in (("config.json", document["config"]), ("layer.tar.gz", document["layers"][0])):
    status, raw, _ = request("GET", start + "blobs/" + descriptor["digest"])
    if status != 200 or digest(raw) != descriptor["digest"] or len(raw) != descriptor["size"]:
        raise RuntimeError("Registry returned an unexpected blob")
    result[filename] = raw
print(json.dumps({name: base64.b64encode(value).decode() for name, value in result.items()}))
"""


def installed_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def publish(lab, companion, tag, version):
    data = {"tag": tag, "version": version, "mode": "baseline", "report": None, "exception": None}
    result = lab.kubectl("exec", "-i", companion.PROMOTER, "--", "python", "/fixture/promotion_fixture.py",
                         "promote", payload=json.dumps(data), timeout=35)
    return json.loads(result.stdout)["subject"]


def fetch(lab, companion, fixture, subject):
    result = lab.kubectl("exec", companion.OBSERVER, "--", "python", "-c", FETCH, subject, timeout=30)
    asset = {name: base64.b64decode(value, validate=True) for name, value in json.loads(result.stdout).items()}
    if fixture.digest(asset["manifest.json"]) != subject:
        lab.block("The downloaded manifest did not match the requested digest")
    return asset


def scan(lab, companion, fixture, asset, subject, folder, name, version, expected):
    archive = folder / (name + ".tar")
    archive.write_bytes(fixture.docker_archive(asset))
    scanned = companion.run_scanner(lab, folder, archive.name)
    if scanned.returncode != (1 if expected else 0):
        lab.block("The pinned scanner did not produce the expected completed assessment")
    entries = json.loads(scanned.stdout)
    metadata = entries["image_metadata"]["layer_metadata"]
    layer_ids = [entry["diff_id"] for entry in metadata]
    if json.loads(asset["config.json"])["rootfs"]["diff_ids"] != layer_ids:
        lab.block("The scanner analyzed different layers from the downloaded image")
    packages = [entry for result in entries["results"] for entry in result["packages"]
                if entry["package"]["name"] == fixture.PACKAGE]
    if len(packages) != 1 or packages[0]["package"]["version"] != version:
        lab.block("The observed scanner inventory differs from the target")
    found = [item["id"] for item in packages[0].get("vulnerabilities", [])]
    if found != expected:
        lab.block("The reported advisory set differs from the fixed baseline")
    return {"subject": subject, "manifest_sha256": fixture.digest(asset["manifest.json"]),
            "archive_sha256": fixture.digest(archive.read_bytes()), "layers": layer_ids, "advisories": found,
            "outcome": "quarantined" if found else "approved",
            "raw_scan_sha256": fixture.digest(scanned.stdout.encode())}


def api(lab, image, name):
    payload = json.dumps({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": NS},
                          "spec": {"automountServiceAccountToken": False,
                                   "containers": [{"name": "metadata-only", "image": image}]}})
    command = lab.kubectl("-n", NS, "create", "--dry-run=server", "-f", "-", "-o", "json", payload=payload,
                           allow_failure=True)
    if command.returncode == 0:
        admitted = json.loads(command.stdout)["spec"]["containers"][0]["image"]
        return {"status": "admitted", "image": admitted}
    return {"status": "denied" if DENIED in command.stderr else "unexpected-error"}


def save_state(lab, state):
    body = {"data": state}
    return lab.kubectl("patch", "configmap", DECISIONS, "--type=merge", "-p", json.dumps(body))


def setup_policy(lab, state):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": DECISIONS},
                "data": state})
    lab.create({
        "apiVersion": ADMISSION, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
            "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                      "operations": ["CREATE"], "resources": ["pods"]}]},
            "matchConditions": [{"name": "owned-consumer-namespace",
                                 "expression": f'request.namespace == "{NS}"'}],
            "validations": [{"expression": 'params != null && has(params.data) && '
                             'params.data["scan-generation"] == params.data["required-generation"] && '
                             'object.spec.containers.all(c, c.image == params.data["approved-image"])',
                             "message": DENIED}],
        },
    })
    lab.create({
        "apiVersion": ADMISSION, "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": POLICY},
        "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                 "paramRef": {"name": DECISIONS, "namespace": "saf-test", "parameterNotFoundAction": "Deny"}},
    })


def wait_observation(lab, image, predicate):
    deadline = time.monotonic() + 18
    while True:
        observed = api(lab, image, "fixture-rescan-operand")
        if predicate(observed):
            return observed
        if time.monotonic() >= deadline:
            lab.block("The expected active admission decision did not become visible")
        time.sleep(0.25)


def run(lab):
    fixture = installed_module(SOURCE / "image_fixture.py", "saf_rescan_image_fixture")
    companion = installed_module(SOURCE / "case.py", "saf_rescan_tooling")
    runtime = installed_module(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_rescan_runtime")
    companion.deploy(lab, runtime.load_runtime(lab))
    previous = publish(lab, companion, "candidate", "1.0.0")
    clean = publish(lab, companion, "clean", "1.0.1")
    image = lambda subject: REGISTRY + "@" + subject
    lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NS}})
    initial = api(lab, image(previous), "fixture-initial-admission")
    lab.check("red", "The unchecked consumer admits an already-pushed, unscanned digest",
              initial == {"status": "admitted", "image": image(previous)}, initial)

    root = lab.kubeconfig.parent
    older, newer = root / "prior-advisory", root / "updated-advisory"
    older.mkdir()
    newer.mkdir()
    fixture.database(older / "db")
    fixture.database(newer / "db")
    previous_db = next((older / "db").rglob("all.zip"))
    old_advisory = json.loads(json.dumps(fixture.ADVISORY_RECORD))
    changes = old_advisory["affected"][0]["ranges"][0]["events"]
    changes[:] = [{"introduced": "0.9.0"}, {"fixed": "1.0.0"}]
    with ZipFile(previous_db, "w") as database:
        from zipfile import ZipInfo
        database.writestr(ZipInfo(fixture.ADVISORY + ".json"), fixture.encode(old_advisory))
    current_db = next((newer / "db").rglob("all.zip"))
    generations = {"old": fixture.digest(previous_db.read_bytes()), "new": fixture.digest(current_db.read_bytes())}
    if generations["old"] == generations["new"]:
        lab.block("The advisory refresh did not change the database")

    asset = fetch(lab, companion, fixture, previous)
    original = scan(lab, companion, fixture, asset, previous, older, "candidate", "1.0.0", [])
    approved = {"approved-image": image(previous), "scan-generation": generations["old"],
                "required-generation": generations["old"]}
    setup_policy(lab, approved)
    wait_observation(lab, REGISTRY + ":candidate", lambda value: value["status"] == "denied")
    initial_approved = api(lab, image(previous), "fixture-approved-old-scan")
    save_state(lab, {"required-generation": generations["new"]})
    stale = wait_observation(lab, image(previous), lambda value: value["status"] == "denied")

    advanced = publish(lab, companion, "candidate", "1.0.1")
    if advanced != clean:
        lab.block("Registry alias did not advance to the independent clean digest")
    second = fetch(lab, companion, fixture, previous)
    flagged = scan(lab, companion, fixture, second, previous, newer, "candidate", "1.0.0",
                   [fixture.ADVISORY])
    clean_result = scan(lab, companion, fixture, fetch(lab, companion, fixture, clean), clean,
                        newer, "clean", "1.0.1", [])
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "fixture-rescan-receipts"},
                "immutable": True, "data": {"flagged.json": json.dumps(flagged, sort_keys=True),
                                             "clean.json": json.dumps(clean_result, sort_keys=True)}})
    save_state(lab, {"approved-image": image(clean), "scan-generation": generations["new"]})
    current = wait_observation(lab, image(clean), lambda value: value["status"] == "admitted")
    denied = api(lab, image(previous), "fixture-quarantined-rescan")
    alias = api(lab, REGISTRY + ":candidate", "fixture-mutable-alias")
    green = {
        "older_clean_scan_previously_approved": initial_approved == {"status": "admitted", "image": image(previous)},
        "stale_approval_denied": stale["status"] == "denied",
        "same_registry_archive_reassessed_after_refresh": original["archive_sha256"] == flagged["archive_sha256"],
        "quarantined_digest_denied_even_after_retag": marked_quarantined(flagged, previous)
        and advanced == clean and denied["status"] == "denied",
        "mutable_alias_denied": alias["status"] == "denied",
    }
    lab.check("green", "Refreshing the advisory invalidates stale approval and quarantines the exact prior digest",
              all(green.values()), green)
    lab.check("positive", "The separately rescanned clean digest remains admissible",
              current == {"status": "admitted", "image": image(clean)}
              and clean_result["manifest_sha256"] == clean, current)
    (lab.evidence / "registry-rescan-observations.json").write_text(json.dumps({
        "scanner": companion.SCANNER, "generations": generations,
        "original_scan": original, "updated_scan": flagged, "separate_clean_scan": clean_result,
        "stale_state": stale, "later_admission": {"flagged": denied, "alias": alias, "clean": current},
        "registry_alias_digest_after_change": advanced, "checks": green,
    }, sort_keys=True, indent=2) + "\n")


def marked_quarantined(result, subject):
    return result["outcome"] == "quarantined" and result["manifest_sha256"] == subject
