"""In-process OIDC-to-STS check; never emits tokens or session credentials."""
import base64
import datetime
import hashlib
import hmac
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ENDPOINT = "http://artifact-store:8333"
TOKEN_PATH = Path("/var/run/oidc/token")
AUDIENCE = "saf-0904-014-seaweed-s3"
BUCKETS = {"a": "saf0904014-stage-a", "b": "saf0904014-stage-b"}
MARKER_KEYS = {"a": "artifacts/stage-a/marker.txt", "b": "artifacts/stage-b/marker.txt"}
OWN_WRITE_KEYS = {"a": "artifacts/stage-a/federated-probe.txt",
                  "b": "artifacts/stage-b/federated-probe.txt"}
OWN_PAYLOADS = {"a": b"SAF-K8S-0904-014 federated stage-a marker v1\n",
                "b": b"SAF-K8S-0904-014 federated stage-b marker v1\n"}
SNAPSHOT_BASE = "https://oidc-jwks-snapshot.saf-test.svc:8443"
SNAPSHOT_CA = "/fixture/snapshot-ca.crt"


def output(operation, **values):
    # Callers pass only sanitized booleans, statuses, and fixed fixture hashes.
    print(json.dumps({"operation": operation, **values}, sort_keys=True), flush=True)


def token_claims():
    token = TOKEN_PATH.read_text().strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise RuntimeError("projected identity token has invalid JWT shape")
    raw = parts[1] + "=" * (-len(parts[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(raw.encode()))
    aud = claims.get("aud", [])
    if isinstance(aud, str):
        aud = [aud]
    return claims, set(aud)


def http_call(request):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=3) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        # The body is parsed locally for a fixed error code only and never emitted.
        return error.code, error.read()


def assume_role(role_arn):
    token = TOKEN_PATH.read_text().strip()
    form = urllib.parse.urlencode({
        "Action": "AssumeRoleWithWebIdentity",
        "Version": "2011-06-15",
        "RoleArn": role_arn,
        "RoleSessionName": "saf0904014",
        "WebIdentityToken": token,
    }).encode()
    request = urllib.request.Request(ENDPOINT + "/", data=form, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    status, body = http_call(request)
    if status != 200:
        code = "unknown"
        try:
            code = ET.fromstring(body).findtext(".//{https://sts.amazonaws.com/doc/2011-06-15/}Code") or "unknown"
        except ET.ParseError:
            pass
        return status, None, code
    try:
        root = ET.fromstring(body)
        values = {}
        for name in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration",
                     "SubjectFromWebIdentityToken"):
            node = root.find(f".//{{https://sts.amazonaws.com/doc/2011-06-15/}}{name}")
            if node is None:
                node = root.find(f".//{name}")
            values[name] = node.text if node is not None else None
        if not all(values[name] for name in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration")):
            return status, None, "malformed-success-response"
        values["subject"] = values.pop("SubjectFromWebIdentityToken")
        return status, values, None
    except (ET.ParseError, AttributeError):
        return status, None, "malformed-success-response"


def signing_key(secret, day):
    value = hmac.new(("AWS4" + secret).encode(), day.encode(), hashlib.sha256).digest()
    value = hmac.new(value, b"us-east-1", hashlib.sha256).digest()
    value = hmac.new(value, b"s3", hashlib.sha256).digest()
    return hmac.new(value, b"aws4_request", hashlib.sha256).digest()


def s3_request(method, bucket, key, credentials, body=b""):
    path = f"/{bucket}/{key}"
    access, secret, session = credentials["AccessKeyId"], credentials["SecretAccessKey"], credentials["SessionToken"]
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    host = "artifact-store:8333"
    canonical_headers = (f"host:{host}\n"
                         f"x-amz-content-sha256:{payload_hash}\n"
                         f"x-amz-date:{amz_date}\n"
                         f"x-amz-security-token:{session}\n")
    signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    canonical_request = f"{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    scope = f"{day}/us-east-1/s3/aws4_request"
    string_to_sign = "\n".join(("AWS4-HMAC-SHA256", amz_date, scope,
                                  hashlib.sha256(canonical_request.encode()).hexdigest()))
    signature = hmac.new(signing_key(secret, day), string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers = {
        "Host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        "x-amz-security-token": session,
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
                          f"SignedHeaders={signed_headers}, Signature={signature}"),
    }
    request = urllib.request.Request(ENDPOINT + path, data=body if method == "PUT" else None,
                                     method=method, headers=headers)
    return http_call(request)


def role(stage):
    return f"arn:aws:iam::role/stage-{stage}-federated"


def fixed_role_denial(role_arn):
    status, credentials, error = assume_role(role_arn)
    output("deny", sts_status=status, denied=status != 200,
           no_session_issued=credentials is None, error_class=error or "none")


def positive(stage, wait_for_expiry=False):
    claims, audiences = token_claims()
    expected_sub = f"system:serviceaccount:saf-test:stage-{stage}"
    sts_status, credentials, error = assume_role(role(stage))
    if credentials is None:
        output("positive-expiry" if wait_for_expiry else "positive",
               sts_status=sts_status, error_class=error or "none")
        return
    subject_ok = credentials.get("subject") == expected_sub
    bucket, marker_key = BUCKETS[stage], MARKER_KEYS[stage]
    get_status, content = s3_request("GET", bucket, marker_key, credentials)
    expected_marker_hash = hashlib.sha256(Path(f"/fixture/stage-{stage}-marker.txt").read_bytes()).hexdigest()
    get_ok = get_status == 200 and hashlib.sha256(content).hexdigest() == expected_marker_hash
    put_status, _ = s3_request("PUT", bucket, OWN_WRITE_KEYS[stage], credentials, OWN_PAYLOADS[stage])
    read_status, readback = s3_request("GET", bucket, OWN_WRITE_KEYS[stage], credentials)
    expected_write_hash = hashlib.sha256(OWN_PAYLOADS[stage]).hexdigest()
    write_ok = put_status == 200 and read_status == 200 and hashlib.sha256(readback).hexdigest() == expected_write_hash
    expiration = None
    try:
        expiration = datetime.datetime.fromisoformat(credentials["Expiration"].replace("Z", "+00:00"))
        remaining = (expiration - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    except (TypeError, ValueError):
        remaining = -1
    expiry_window_ok = 20 <= remaining <= 35
    if not wait_for_expiry:
        output("positive", sts_status=sts_status, subject_matches=subject_ok,
               token_claims_match=(claims.get("sub") == expected_sub and AUDIENCE in audiences),
               get_status=get_status, get_digest_matches=get_ok,
               put_status=put_status, readback_status=read_status,
               write_digest_matches=write_ok, short_session_window=expiry_window_ok)
        return

    if not expiry_window_ok or expiration is None:
        output("positive-expiry", sts_status=sts_status,
               short_session_window=expiry_window_ok, expiry_parse_failed=expiration is None)
        return
    before_expiry_status = s3_request("GET", bucket, marker_key, credentials)[0]
    # The expiry is measured from STS's returned timestamp; time.sleep only
    # waits for real wall time and never changes the host or API server clock.
    remaining = max(0.0, (expiration - datetime.datetime.now(datetime.timezone.utc)).total_seconds())
    time.sleep(remaining + 2.0)
    after_expiry_status, _ = s3_request("GET", bucket, marker_key, credentials)
    output("positive-expiry", sts_status=sts_status, subject_matches=subject_ok,
           get_status=get_status, get_digest_matches=get_ok,
           put_status=put_status, readback_status=read_status,
           write_digest_matches=write_ok, short_session_window=expiry_window_ok,
           before_expiry_status=before_expiry_status,
           after_expiry_status=after_expiry_status,
           expired_denied=after_expiry_status in (401, 403))


def inspect():
    claims, audiences = token_claims()
    # Callers pass expected claims explicitly; raw values are never returned.
    expected = sys.argv[2] if len(sys.argv) > 2 else ""
    expected_aud = sys.argv[3] if len(sys.argv) > 3 else AUDIENCE
    snapshot = inspect_public_key_snapshot(sys.argv[4] if len(sys.argv) > 4 else "")
    output("inspect", subject_matches=claims.get("sub") == expected,
           audience_matches=expected_aud in audiences,
           issuer_matches=claims.get("iss") == (sys.argv[4] if len(sys.argv) > 4 else ""),
           snapshot_tls_verified=snapshot["tls_verified"],
           snapshot_issuer_matches=snapshot["issuer_matches"],
           snapshot_discovery_path_matches=snapshot["discovery_path_matches"],
           snapshot_jwks_digest_matches=snapshot["jwks_digest_matches"],
           snapshot_public_keys_only=snapshot["public_keys_only"],
           snapshot_failure=snapshot.get("failure"),
           expiration_window_matches=(isinstance(claims.get("exp"), int)
                                      and 0 < claims["exp"] - int(time.time()) <= 660))


def inspect_public_key_snapshot(expected_issuer):
    """Verify the case HTTPS endpoint serves the API-authenticated public snapshot."""
    context = ssl.create_default_context(cafile=SNAPSHOT_CA)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    fetched = {}
    try:
        for name, path in (("discovery", "/.well-known/openid-configuration"),
                           ("jwks", "/openid/v1/jwks"), ("status", "/status")):
            with opener.open(SNAPSHOT_BASE + path, timeout=3) as response:
                if response.status != 200:
                    raise RuntimeError("snapshot returned non-200")
                fetched[name] = response.read()
        discovery = json.loads(fetched["discovery"])
        jwks = json.loads(fetched["jwks"])
        status = json.loads(fetched["status"])
        discovered_jwks = urllib.parse.urlsplit(discovery.get("jwks_uri", ""))
        keys = jwks.get("keys")
        private_names = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
        public_only = (isinstance(keys, list) and bool(keys)
                       and all(isinstance(key, dict)
                               and not private_names.intersection(key) for key in keys))
        return {
            "tls_verified": True,
            "issuer_matches": (discovery.get("issuer") == expected_issuer
                               and status.get("issuer_matches") is True),
            "discovery_path_matches": (
                discovery.get("jwks_uri") == "https://kubernetes.default.svc/openid/v1/jwks"
                and
                discovered_jwks.scheme == "https"
                and discovered_jwks.path == "/openid/v1/jwks"
                and not discovered_jwks.query and not discovered_jwks.fragment
                and status.get("jwks_uri_path_matches") is True
                and status.get("api_bearer_auth_used") is True
                and status.get("api_tls_verified") is True),
            "jwks_digest_matches": (
                hashlib.sha256(fetched["jwks"]).hexdigest() == status.get("jwks_sha256")
                and status.get("jwks_http") == 200),
            "public_keys_only": public_only and status.get("private_fields_absent") is True,
        }
    except (OSError, ValueError, TimeoutError, RuntimeError) as error:
        cause = error.reason if isinstance(error, urllib.error.URLError) else error
        failure = ("certificate_validation_failed" if isinstance(cause, ssl.SSLCertVerificationError)
                   else "unexpected_snapshot_http_status" if isinstance(error, urllib.error.HTTPError)
                   else "snapshot_transport_or_format_failed")
        return {"tls_verified": False, "issuer_matches": False,
                "discovery_path_matches": False, "jwks_digest_matches": False,
                "public_keys_only": False, "failure": failure}


def main():
    if len(sys.argv) < 2:
        raise SystemExit("expected one fixed operation")
    operation = sys.argv[1]
    if operation == "inspect":
        inspect()
    elif operation == "positive-a":
        positive("a")
    elif operation == "positive-b":
        positive("b")
    elif operation == "positive-expiry":
        positive("a", wait_for_expiry=True)
    elif operation == "deny-stage-b-role":
        fixed_role_denial(role("b"))
    elif operation == "deny-stage-a-role":
        fixed_role_denial(role("a"))
    else:
        raise SystemExit("unknown fixed identity operation")


if __name__ == "__main__":
    main()
