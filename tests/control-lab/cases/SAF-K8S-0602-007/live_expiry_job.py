"""Read one owned approval record and evaluate expiry using this Job's UTC clock."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import ssl
import time
import urllib.error
import urllib.request

from expiry_consumer import decide

NS = "saf-test"
RECORD = "saf-0602-007-live-expiry-review"
REQUEST_ID = "saf-0602-007-live-expiry-synthetic-request"
TARGET_DIGEST = "sha256:" + "c" * 64
EXPECTED_KEYS = {"requestId", "targetDigest", "expiresAt", "security", "operations"}
API = f"https://kubernetes.default.svc/api/v1/namespaces/{NS}/configmaps/{RECORD}"
TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")


def utc_now():
    return datetime.now(timezone.utc)


def stamp(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def fingerprint(data):
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def read_record():
    request = urllib.request.Request(
        API, headers={"Authorization": "Bearer " + TOKEN.read_text().strip(),
                      "Accept": "application/json"})
    context = ssl.create_default_context(cafile=str(CA))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    with opener.open(request, timeout=4) as response:
        return json.load(response)


def main():
    deadline = time.monotonic() + 25
    record_obj = None
    while time.monotonic() < deadline:
        try:
            candidate = read_record()
        except urllib.error.HTTPError as error:
            if error.code != 404:
                emit({"status": "blocked", "stage": "record-read"})
                return 1
        except (OSError, ValueError, KeyError, urllib.error.URLError):
            emit({"status": "blocked", "stage": "record-read"})
            return 1
        else:
            data = candidate.get("data", {})
            if (set(data) == EXPECTED_KEYS and data.get("requestId") == REQUEST_ID
                    and data.get("targetDigest") == TARGET_DIGEST
                    and data.get("security") == "approved"
                    and data.get("operations") == "approved"):
                record_obj = candidate
                break
        time.sleep(0.2)
    if record_obj is None:
        emit({"status": "blocked", "stage": "approved-record-not-observed"})
        return 1

    record = record_obj["data"]
    request = {"requestId": REQUEST_ID, "targetDigest": TARGET_DIGEST}
    try:
        expiration = datetime.fromisoformat(record["expiresAt"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        emit({"status": "blocked", "stage": "invalid-expiry"})
        return 1
    if expiration.tzinfo is None or not record["expiresAt"].endswith("Z"):
        emit({"status": "blocked", "stage": "invalid-expiry"})
        return 1

    before = utc_now()
    before_result = decide({"record": record, "request": request, "evaluatedAt": stamp(before)})
    if before_result != {"permitted": True, "reason": "approved-unexpired"}:
        emit({"status": "blocked", "stage": "not-permitted-before-expiry",
              "before_utc": stamp(before), "expires_at": record["expiresAt"]})
        return 1

    # A short bounded poll is necessary to observe real expiry; it sleeps rather
    # than busy-spinning and never changes the record or clock.
    wait_deadline = time.monotonic() + max(2.0, (expiration - before).total_seconds() + 15.0)
    while utc_now() < expiration and time.monotonic() < wait_deadline:
        time.sleep(0.2)
    if utc_now() < expiration:
        emit({"status": "blocked", "stage": "expiry-not-reached-within-bound",
              "before_utc": stamp(before), "expires_at": record["expiresAt"]})
        return 1

    try:
        after_obj = read_record()
    except (OSError, ValueError, KeyError, urllib.error.URLError):
        emit({"status": "blocked", "stage": "record-read-after-expiry",
              "before_utc": stamp(before), "expires_at": record["expiresAt"]})
        return 1
    after = utc_now()
    after_record = after_obj.get("data", {})
    unchanged = (after_obj.get("metadata", {}).get("uid") == record_obj.get("metadata", {}).get("uid")
                 and after_record == record
                 and fingerprint(after_record) == fingerprint(record))
    after_result = decide({"record": after_record, "request": request, "evaluatedAt": stamp(after)})
    expired_denial = (after >= expiration
                      and after_result == {"permitted": False, "reason": "expired"})
    passed = unchanged and expired_denial
    emit({"status": "passed" if passed else "blocked",
          "stage": "complete" if passed else "post-expiry-predicate",
          "record_uid": record_obj.get("metadata", {}).get("uid"),
          "record_created_at": record_obj.get("metadata", {}).get("creationTimestamp"),
          "record_sha256": fingerprint(record), "expires_at": record["expiresAt"],
          "before_utc": stamp(before), "before_decision": before_result,
          "after_utc": stamp(after), "after_decision": after_result,
          "record_unchanged": unchanged, "after_expiry": after >= expiration})
    return 0 if passed else 1


def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
