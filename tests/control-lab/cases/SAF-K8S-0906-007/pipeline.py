"""Finite deterministic fixture transforms and downstream consumer."""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path("/fixture")
OUT = Path("/pipeline")
APPROVED = {
    "input": "08a362b6a4f86ca8e61c2b7bccd4dca72c731af1338dfd796bb6d8871d2e8a0e",
    "stage1": "332ef3e0470b05b5d95355b9a838b6ee42b5e11c7fac6e36b21944fdbf4b5c6b",
    "stage2": "928f96382e91d258b9902faaf75a5475385d59eb112f18c80e0d4680379758b2",
}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def trusted():
    values = {key: (Path("/trust") / (key + "_sha256")).read_text().strip()
              for key in ("input", "stage1", "stage2")}
    if values != APPROVED:
        raise ValueError("mounted immutable trust record differs from code lock")
    return values


def transform_one(data):
    source = json.loads(data)
    if source.get("schema") != "fixture-v1" or not isinstance(source.get("examples"), list):
        raise ValueError("fixture schema rejected")
    clean = {"schema": "fixture-v1", "examples": [
        {"text": row["text"].strip().lower(), "label": row["label"].strip().lower()}
        for row in source["examples"]
    ]}
    return encode(clean)


def transform_two(data):
    stage1 = json.loads(data)
    features = {"schema": "features-v1", "rows": [
        {"label": row["label"], "tokens": row["text"].split()}
        for row in stage1["examples"]
    ]}
    return encode(features)


def execute(mode, fixture):
    locks = trusted()
    raw = (ROOT / ("approved.json" if fixture == "approved" else "alternate.json")).read_bytes()
    d0 = digest(raw)
    governed = mode in {"checked", "publish"}
    if governed and d0 != locks["input"]:
        print(json.dumps({"decision": "rejected", "transition": "input", "writes": 0}, sort_keys=True))
        return 0
    s1 = transform_one(raw)
    d1 = digest(s1)
    if governed and d1 != locks["stage1"]:
        print(json.dumps({"decision": "rejected", "transition": "stage1", "writes": 0}, sort_keys=True))
        return 0
    s2 = transform_two(s1)
    d2 = digest(s2)
    if governed and d2 != locks["stage2"]:
        print(json.dumps({"decision": "rejected", "transition": "stage2", "writes": 0}, sort_keys=True))
        return 0
    if mode in {"unchecked", "publish"}:
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / (fixture + "-stage1.json")).write_bytes(s1)
        (OUT / (fixture + "-stage2.json")).write_bytes(s2)
    print(json.dumps({"fixture": fixture, "mode": mode, "stages": 2,
                      "stage1_sha256": d1, "stage2_sha256": d2,
                      "advanced": True, "published": mode in {"unchecked", "publish"}}, sort_keys=True))
    return 0


def decide():
    locks = trusted()
    payload = (OUT / "approved-stage2.json").read_bytes()
    observed = digest(payload)
    features = json.loads(payload)
    valid = observed == locks["stage2"] and features == {
        "rows": [{"label": "fruit", "tokens": ["apple"]},
                 {"label": "fruit", "tokens": ["pear"]}],
        "schema": "features-v1",
    }
    # This process is a separate downstream consumer; it reports the decision only.
    print(json.dumps({"consumer": "fixture-downstream", "decision": "accept" if valid else "reject",
                      "stage2_sha256": observed}, sort_keys=True))
    return 0 if valid else 3


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "decide":
        raise SystemExit(decide())
    if len(sys.argv) == 3 and sys.argv[1] in {"checked", "unchecked", "publish"} and sys.argv[2] in {"approved", "alternate"}:
        raise SystemExit(execute(sys.argv[1], sys.argv[2]))
    raise SystemExit("usage: pipeline.py checked|unchecked|publish approved|alternate | decide")
