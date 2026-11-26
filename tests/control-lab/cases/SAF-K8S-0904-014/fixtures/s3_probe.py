"""Fixed-path SigV4 SeaweedFS probe; standard library only, no network egress."""
import datetime
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
import xml.etree.ElementTree as ET

ENDPOINT = "http://artifact-store:8333"
BUCKET_A = "saf0904014-stage-a"
BUCKET_B = "saf0904014-stage-b"
BUCKETS = {"a": BUCKET_A, "b": BUCKET_B}
ADMIN = ("SAF0904014ADMIN", "saf-0904-014-public-fixture-admin-key-never-for-production")
STAGE = {
    "a": ("SAF0904014STAGEA", "saf-0904-014-public-fixture-stage-a-key-never-for-production"),
    "b": ("SAF0904014STAGEB", "saf-0904-014-public-fixture-stage-b-key-never-for-production"),
}
MARKERS = {
    BUCKET_A: Path("/fixture/stage-a-marker.txt").read_bytes(),
    BUCKET_B: Path("/fixture/stage-b-marker.txt").read_bytes(),
}
MARKER_KEYS = {BUCKET_A: "artifacts/stage-a/marker.txt", BUCKET_B: "artifacts/stage-b/marker.txt"}
CROSS_WRITES = {
    "a": (BUCKET_B, "artifacts/stage-b/from-stage-a.txt", b"SAF-K8S-0904-014 inert cross-stage write by A v1\n"),
    "b": (BUCKET_A, "artifacts/stage-a/from-stage-b.txt", b"SAF-K8S-0904-014 inert cross-stage write by B v1\n"),
}
ALLOWED_WRITES = {
    "a": (BUCKET_A, "artifacts/stage-a/allowed-after-scope.txt", b"SAF-K8S-0904-014 allowed stage-a write v1\n"),
    "b": (BUCKET_B, "artifacts/stage-b/allowed-after-scope.txt", b"SAF-K8S-0904-014 allowed stage-b write v1\n"),
}
EXPIRY_KEY = "lifecycle-probe/expired/one-marker.txt"
RETAINED_KEY = "lifecycle-probe/retained/one-marker.txt"
EXPIRY_BODY = b"SAF-K8S-0904-014 synthetic expiration witness v1\n"
RETAINED_BODY = b"SAF-K8S-0904-014 nonmatching retained comparator v1\n"


def hmac_bytes(key, value):
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()


def signed_headers(method, path, body, credentials, query=""):
    access_key, secret_key = credentials
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    host = "artifact-store:8333"
    canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = f"{method}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}"
    scope = f"{day}/us-east-1/s3/aws4_request"
    to_sign = "\n".join(("AWS4-HMAC-SHA256", amz_date, scope,
                          hashlib.sha256(canonical_request.encode()).hexdigest()))
    key = hmac_bytes(("AWS4" + secret_key).encode(), day)
    key = hmac_bytes(key, "us-east-1")
    key = hmac_bytes(key, "s3")
    key = hmac_bytes(key, "aws4_request")
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    return {"Host": host, "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash,
            "Authorization": f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                             f"SignedHeaders={signed}, Signature={signature}"}


def request(method, bucket, key="", body=b"", credentials=None, query="", content_type=None):
    path = f"/{bucket}" + (f"/{key}" if key else "")
    headers = {}
    if content_type:
        headers["Content-Type"] = content_type
    if credentials:
        headers.update(signed_headers(method, path, body, credentials, query))
    url = ENDPOINT + path + ("?" + query if query else "")
    req = urllib.request.Request(url, data=body if method in ("PUT", "POST") else None,
                                 method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def error_code(body):
    try:
        return ET.fromstring(body).findtext("Code") or "unknown S3 error"
    except ET.ParseError:
        return "missing XML error response"


def marker_sha(bucket):
    return hashlib.sha256(MARKERS[bucket]).hexdigest()


def lifecycle_result(bucket, config_path, expected_id, expected_days):
    body = Path(config_path).read_bytes()
    put_status, _ = request("PUT", bucket, body=body, credentials=ADMIN,
                             query="lifecycle=", content_type="application/xml")
    get_status, returned = request("GET", bucket, credentials=ADMIN, query="lifecycle=")
    rules = []
    if get_status == 200:
        root = ET.fromstring(returned)
        ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
        for rule in root.findall("s3:Rule", ns):
            rules.append({
                "id": rule.findtext("s3:ID", namespaces=ns),
                "status": rule.findtext("s3:Status", namespaces=ns),
                "prefix": rule.findtext("s3:Filter/s3:Prefix", namespaces=ns),
                "days": rule.findtext("s3:Expiration/s3:Days", namespaces=ns),
                "date": rule.findtext("s3:Expiration/s3:Date", namespaces=ns),
            })
    expected = [{"id": expected_id, "status": "Enabled", "prefix": "artifacts/",
                 "days": str(expected_days), "date": None}]
    if bucket == BUCKET_A:
        expected.append({"id": "saf-0904-014-expiry-witness", "status": "Enabled",
                         "prefix": "lifecycle-probe/expired/", "days": None,
                         "date": "2020-01-01T00:00:00Z"})
    return {"bucket": bucket, "put_status": put_status, "get_status": get_status,
            "rules": rules, "expected_rules": expected, "matches": rules == expected}


def output(operation, **fields):
    print(json.dumps({"operation": operation, **fields}, sort_keys=True))


def main(operation):
    if operation == "seed":
        created = {}
        seeded = {}
        for bucket in (BUCKET_A, BUCKET_B):
            created[bucket], response = request("PUT", bucket, credentials=ADMIN)
            if created[bucket] != 200:
                raise RuntimeError(f"fixture bucket creation failed with HTTP {created[bucket]}: {error_code(response)}")
            seeded[bucket], _ = request("PUT", bucket, MARKER_KEYS[bucket], MARKERS[bucket], ADMIN,
                                        content_type="text/plain")
            if seeded[bucket] != 200:
                raise RuntimeError(f"fixture marker seeding failed with HTTP {seeded[bucket]}")
            status, content = request("GET", bucket, MARKER_KEYS[bucket], credentials=ADMIN)
            if status != 200 or content != MARKERS[bucket]:
                raise RuntimeError(f"fixture marker failed to round-trip in {bucket}")
        output(operation, buckets_created=created, markers_seeded=seeded,
               marker_sha256={BUCKET_A: marker_sha(BUCKET_A), BUCKET_B: marker_sha(BUCKET_B)})
        return

    if operation == "broad":
        identities = {}
        for stage, credentials in STAGE.items():
            gets = {}
            for bucket in (BUCKET_A, BUCKET_B):
                status, body = request("GET", bucket, MARKER_KEYS[bucket], credentials=credentials)
                gets[bucket] = {"status": status,
                                "sha256": hashlib.sha256(body).hexdigest() if status == 200 else None}
            target_bucket, target_key, payload = CROSS_WRITES[stage]
            put_status, _ = request("PUT", target_bucket, target_key, payload, credentials,
                                    content_type="text/plain")
            identity_name = "stage-" + stage
            identities[identity_name] = {"gets": gets, "cross_put_status": put_status,
                                         "cross_target_bucket": target_bucket,
                                         "cross_target_key": target_key,
                                         "cross_write_sha256": hashlib.sha256(payload).hexdigest()}
        output(operation, identities=identities)
        return

    if operation == "scoped":
        identities = {}
        for stage, credentials in STAGE.items():
            own_bucket = BUCKETS[stage]
            other_bucket = BUCKETS["b" if stage == "a" else "a"]
            get_own_status, own_body = request("GET", own_bucket, MARKER_KEYS[own_bucket],
                                               credentials=credentials)
            get_other_status, _ = request("GET", other_bucket, MARKER_KEYS[other_bucket],
                                          credentials=credentials)
            cross_bucket, cross_key, cross_payload = CROSS_WRITES[stage]
            cross_put_status, _ = request("PUT", cross_bucket, cross_key, cross_payload,
                                          credentials, content_type="text/plain")
            allowed_bucket, allowed_key, allowed_payload = ALLOWED_WRITES[stage]
            allowed_put_status, _ = request("PUT", allowed_bucket, allowed_key, allowed_payload,
                                            credentials, content_type="text/plain")
            readback_status, readback = request("GET", allowed_bucket, allowed_key,
                                                credentials=credentials)
            preserved_status, preserved = request("GET", cross_bucket, cross_key,
                                                  credentials=ADMIN)
            identities["stage-" + stage] = {
                "own_get_status": get_own_status,
                "own_get_sha256": hashlib.sha256(own_body).hexdigest() if get_own_status == 200 else None,
                "cross_get_status": get_other_status,
                "cross_put_status": cross_put_status,
                "cross_put_target": f"{cross_bucket}/{cross_key}",
                "cross_put_preserved_status": preserved_status,
                "cross_put_preserved_sha256": hashlib.sha256(preserved).hexdigest()
                    if preserved_status == 200 else None,
                "cross_put_expected_sha256": hashlib.sha256(cross_payload).hexdigest(),
                "allowed_put_status": allowed_put_status,
                "allowed_readback_status": readback_status,
                "allowed_readback_sha256": hashlib.sha256(readback).hexdigest()
                    if readback_status == 200 else None,
                "allowed_expected_sha256": hashlib.sha256(allowed_payload).hexdigest(),
            }
        lifecycle = [
            lifecycle_result(BUCKET_A, "/fixture/stage-a-lifecycle.xml",
                             "saf-0904-014-stage-a-classification-window", 1),
            lifecycle_result(BUCKET_B, "/fixture/stage-b-lifecycle.xml",
                             "saf-0904-014-stage-b-classification-window", 2),
        ]
        output(operation, identities=identities, lifecycle=lifecycle)
        return

    if operation == "config-hash":
        config = Path("/fixture/s3-config.json").read_bytes()
        output(operation, sha256=hashlib.sha256(config).hexdigest())
        return

    if operation == "verify-admin-data":
        result = {}
        for bucket in (BUCKET_A, BUCKET_B):
            status, body = request("GET", bucket, MARKER_KEYS[bucket], credentials=ADMIN)
            result[bucket] = {"status": status,
                              "sha256": hashlib.sha256(body).hexdigest() if status == 200 else None}
        output(operation, markers=result)
        return

    if operation == "expiry-seed":
        target_status, _ = request("PUT", BUCKET_A, EXPIRY_KEY, EXPIRY_BODY, ADMIN,
                                   content_type="text/plain")
        retained_status, _ = request("PUT", BUCKET_B, RETAINED_KEY, RETAINED_BODY, ADMIN,
                                     content_type="text/plain")
        target_read, target_body = request("GET", BUCKET_A, EXPIRY_KEY, credentials=ADMIN)
        retained_read, retained_body = request("GET", BUCKET_B, RETAINED_KEY,
                                               credentials=ADMIN)
        output(operation, target_put_status=target_status,
               target_before_status=target_read,
               target_before_sha256=hashlib.sha256(target_body).hexdigest()
                   if target_read == 200 else None,
               target_expected_sha256=hashlib.sha256(EXPIRY_BODY).hexdigest(),
               retained_put_status=retained_status,
               retained_before_status=retained_read,
               retained_before_sha256=hashlib.sha256(retained_body).hexdigest()
                   if retained_read == 200 else None,
               retained_expected_sha256=hashlib.sha256(RETAINED_BODY).hexdigest())
        return

    if operation == "expiry-verify":
        target_status, _ = request("GET", BUCKET_A, EXPIRY_KEY, credentials=ADMIN)
        retained_status, retained_body = request("GET", BUCKET_B, RETAINED_KEY,
                                                 credentials=ADMIN)
        output(operation, target_after_status=target_status,
               retained_after_status=retained_status,
               retained_after_sha256=hashlib.sha256(retained_body).hexdigest()
                   if retained_status == 200 else None,
               retained_expected_sha256=hashlib.sha256(RETAINED_BODY).hexdigest())
        return

    raise ValueError(f"unknown fixed fixture operation: {operation}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("expected exactly one fixed fixture operation")
    main(sys.argv[1])
