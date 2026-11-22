"""Fixed-path SigV4 client using only owned, inert fixture credentials and bytes."""
import datetime
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ENDPOINT = "http://artifact-store:8333"
BUCKET = "saf-artifacts-0904"
KEY = "evidence/marker.bin"
ADMIN = ("SAF0904013FIXTUREADMIN",
         "saf-0904-013-public-fixture-admin-key-never-for-production")
PIPELINE = ("SAF0904013PIPELINE",
            "saf-0904-013-public-fixture-pipeline-key-never-for-production")
MARKER = Path("/fixture/marker.bin").read_bytes()
MARKER_SHA = "7ef23877d2d11a502f6d9433ce2d666b9a66263115b5dad1d105e0711407cdfc"
APPROVED_WRITE = b"SAF-K8S-0904-013 approved fixture write v1\n"
POLICY = json.loads(Path("/fixture/public-bucket-policy.json").read_text())


def hmac_bytes(key, value):
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()


def signed_headers(method, path, body, credentials, query=""):
    access_key, secret_key = credentials
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    host = "artifact-store:8333"
    canonical_headers = (f"host:{host}\n" f"x-amz-content-sha256:{payload_hash}\n"
                         f"x-amz-date:{amz_date}\n")
    signed = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = (f"{method}\n{path}\n{query}\n{canonical_headers}"
                         f"\n{signed}\n{payload_hash}")
    scope = f"{day}/us-east-1/s3/aws4_request"
    to_sign = "\n".join(("AWS4-HMAC-SHA256", amz_date, scope,
                           hashlib.sha256(canonical_request.encode()).hexdigest()))
    key = hmac_bytes(("AWS4" + secret_key).encode(), day)
    key = hmac_bytes(key, "us-east-1")
    key = hmac_bytes(key, "s3")
    key = hmac_bytes(key, "aws4_request")
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    return {"Host": host, "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
            "Authorization": (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                              f"SignedHeaders={signed}, Signature={signature}")}


def request(method, path, body=b"", credentials=None, query="", extra_headers=None):
    url = ENDPOINT + path + ("?" + query if query else "")
    headers = dict(extra_headers or {})
    if credentials:
        headers.update(signed_headers(method, path, body, credentials, query))
    req = urllib.request.Request(url, data=body if method in ("PUT", "POST") else None,
                                 method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def error_code(body):
    try:
        return ET.fromstring(body).findtext("Code")
    except ET.ParseError:
        return None


def emit(operation, **fields):
    print(json.dumps({"operation": operation, "bucket": BUCKET, **fields}, sort_keys=True))


def roundtrip(operation, credentials):
    if hashlib.sha256(MARKER).hexdigest() != MARKER_SHA or len(MARKER) != 65536:
        raise RuntimeError("fixed marker fixture hash/length mismatch")
    bucket_status, bucket_body = request("PUT", f"/{BUCKET}", credentials=ADMIN)
    if bucket_status != 200:
        raise RuntimeError(f"case bucket create returned HTTP {bucket_status}: {error_code(bucket_body)}")
    put_status, put_body = request("PUT", f"/{BUCKET}/{KEY}", MARKER, credentials=credentials,
                                   extra_headers={"Content-Type": "application/octet-stream"})
    if put_status != 200:
        raise RuntimeError(f"case marker PUT returned HTTP {put_status}: {error_code(put_body)}")
    get_status, content = request("GET", f"/{BUCKET}/{KEY}", credentials=credentials)
    if get_status != 200 or content != MARKER:
        raise RuntimeError(f"signed S3 readback failed: HTTP {get_status}")
    emit(operation, bucket_status=bucket_status, put_status=put_status, get_status=get_status,
         marker_length=len(content), marker_sha256=hashlib.sha256(content).hexdigest(),
         content_type="application/octet-stream", key=KEY)


def normalized_policy(policy):
    statements = []
    for entry in policy["Statement"]:
        statement = dict(entry)
        for key in ("Action", "Resource"):
            value = statement[key]
            statement[key] = [value] if isinstance(value, str) else sorted(value)
        statements.append(statement)
    return {**policy, "Statement": statements}


def main(operation):
    if operation in ("volume-off", "volume-on"):
        roundtrip(operation, ADMIN)
        return
    if operation == "policy-public":
        policy_bytes = json.dumps(POLICY, separators=(",", ":")).encode()
        put_status, put_body = request("PUT", f"/{BUCKET}", policy_bytes, ADMIN, query="policy=",
                                        extra_headers={"Content-Type": "application/json"})
        read_status, read_body = request("GET", f"/{BUCKET}", credentials=ADMIN, query="policy=")
        try:
            returned_policy = json.loads(read_body)
            read_matches = normalized_policy(returned_policy) == normalized_policy(POLICY)
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError):
            returned_policy = None
            read_matches = False
        get_status, content = request("GET", f"/{BUCKET}/{KEY}")
        anon_put, anon_body = request("PUT", f"/{BUCKET}/evidence/anonymous-write.bin", MARKER,
                                      extra_headers={"Content-Type": "application/octet-stream"})
        emit(operation, policy_put_status=put_status, policy_put_error=error_code(put_body),
             policy_read_status=read_status, policy_read_matches=read_matches,
             returned_policy=returned_policy,
             anonymous_get_status=get_status,
             anonymous_get_sha256=hashlib.sha256(content).hexdigest() if get_status == 200 else None,
             anonymous_put_status=anon_put, anonymous_put_error=error_code(anon_body))
        return
    if operation == "policy-private":
        delete_status, delete_body = request("DELETE", f"/{BUCKET}", credentials=ADMIN,
                                              query="policy=")
        read_status, read_body = request("GET", f"/{BUCKET}", credentials=ADMIN, query="policy=")
        get_status, get_body = request("GET", f"/{BUCKET}/{KEY}")
        put_status, put_body = request("PUT", f"/{BUCKET}/evidence/anonymous-write.bin", MARKER,
                                       extra_headers={"Content-Type": "application/octet-stream"})
        emit(operation, policy_delete_status=delete_status,
             policy_delete_error=error_code(delete_body), policy_read_status=read_status,
             policy_read_error=error_code(read_body), anonymous_get_status=get_status,
             anonymous_get_error=error_code(get_body), anonymous_put_status=put_status,
             anonymous_put_error=error_code(put_body))
        return
    if operation == "policy-absent":
        status, body = request("GET", f"/{BUCKET}", credentials=ADMIN, query="policy=")
        emit(operation, policy_read_status=status, policy_read_error=error_code(body))
        return
    if operation == "approved-positive":
        get_status, body = request("GET", f"/{BUCKET}/{KEY}", credentials=PIPELINE)
        put_status, put_body = request("PUT", f"/{BUCKET}/evidence/approved-write.bin",
                                       APPROVED_WRITE, PIPELINE,
                                       extra_headers={"Content-Type": "text/plain"})
        read_status, read_body = request("GET", f"/{BUCKET}/evidence/approved-write.bin",
                                         credentials=PIPELINE)
        emit(operation, get_status=get_status,
             get_sha256=hashlib.sha256(body).hexdigest() if get_status == 200 else None,
             put_status=put_status, put_error=error_code(put_body),
             readback_status=read_status,
             readback_sha256=hashlib.sha256(read_body).hexdigest() if read_status == 200 else None,
             expected_readback_sha256=hashlib.sha256(APPROVED_WRITE).hexdigest())
        return
    raise ValueError("unsupported fixed fixture operation")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("expected exactly one fixture operation")
    main(sys.argv[1])
