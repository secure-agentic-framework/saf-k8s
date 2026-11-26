"""Separate fixture consumer for actual collected build records; emits booleans only."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main(argv):
    root = Path(argv[1])
    policy_path = Path(argv[2]) if len(argv) > 2 else root / "policy.json"
    policy = json.loads(policy_path.read_text())
    outcomes = {}
    for category in ("environment", "process"):
        payload = (root / f"{category}.json").read_bytes()
        public = root / f"{category}.pub"
        signature = root / f"{category}.sig"
        kind = policy["payload_type"].encode()
        pae = b"DSSEv1 " + str(len(kind)).encode() + b" " + kind + b" " + str(len(payload)).encode() + b" " + payload
        pae_path = root / f"consumer-{category}.pae"
        pae_path.write_bytes(pae)
        verified = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public),
                                   "-signature", str(signature), str(pae_path)],
                                  capture_output=True, text=True, timeout=10).returncode == 0
        statement = json.loads(payload)
        expected = policy["categories"][category]
        subject_ok = statement.get("subject") == [{"name": policy["subject_name"],
                                                      "digest": {"sha256": policy["subject_sha256"]}}]
        signer_ok = "sha256:" + hashlib.sha256(public.read_bytes()).hexdigest() == expected["public_key_sha256"]
        type_ok = statement.get("_type") == "https://in-toto.io/Statement/v1" and statement.get("predicateType") == expected["predicate_type"]
        predicate = statement.get("predicate", {})
        if category == "environment":
            observed = policy["observed_runtime"]
            facts_ok = (predicate.get("job_uid") == observed["job_uid"] and predicate.get("pod_uid") == observed["pod_uid"]
                        and predicate.get("node_name") == observed["node_name"] and predicate.get("image") == policy["image"]
                        and predicate.get("image_id") == observed["image_id"] and bool(predicate.get("started_at")))
        else:
            facts_ok = (predicate.get("tool_sha256") == policy["tool_sha256"]
                        and predicate.get("input_sha256") == policy["input_sha256"]
                        and predicate.get("output_sha256") == policy["subject_sha256"]
                        and predicate.get("collector_recomputed_output_sha256") == policy["subject_sha256"]
                        and predicate.get("test_passed") is True and predicate.get("tool") == "python"
                        and bool(predicate.get("python_version")) and "/app/build.py" in predicate.get("argv", []))
        outcomes[category] = verified and signer_ok and type_ok and subject_ok and facts_ok
    accepted = all(outcomes.values())
    print(json.dumps({"consumer_accept": accepted, "categories": outcomes}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
