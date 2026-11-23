"""Prove authenticated repository permissions on a disposable Distribution registry."""
import base64
from hashlib import sha256
import hmac
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import subprocess
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit

SCOPE = (
    "A disposable Kind cluster, a private loopback OCI Distribution 3.0.0 registry, and a "
    "local fixture token issuer using a per-run signing key. The registry validates real "
    "signed repository scopes. The same authenticated identity can publish before the scoped "
    "rules and can only pull afterward. An authorized publisher can write only its approved "
    "repository. The test also rejects unauthenticated requests and bad credentials. "
    "Identity lifecycle, transport policy and production IAM remain separate."
)
REGISTRY = (
    "docker.io/library/registry:3.0.0@sha256:"
    "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
ISSUER = "saf-fixture-issuer"
AUDIENCE = "saf-fixture-registry"
KEY_ID = "saf-fixture-rsa"
REPOSITORY = "owned/release"
ADJACENT = "owned/adjacent"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"


def compact(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def request(port, method, path, body=None, headers=None):
    connection = HTTPConnection("127.0.0.1", port, timeout=9)
    try:
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        return response.status, response.read(1048576), dict(response.getheaders())
    finally:
        connection.close()


class TokenIssuer(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path != "/token":
            self.reply(404, b"{}")
            return
        user = self.authenticate()
        if user is None:
            self.reply(401, b"{}")
            return
        claim = parse_qs(parsed.query)
        if claim.get("service") != [AUDIENCE] or len(claim.get("scope", [])) != 1:
            self.reply(400, b"{}")
            return
        fields = claim["scope"][0].split(":")
        if len(fields) != 3 or fields[0] != "repository" or fields[1] not in {REPOSITORY, ADJACENT}:
            self.reply(400, b"{}")
            return
        repository = fields[1]
        allowed = self.server.roles.get(user, {}).get(repository, [])
        granted = sorted(set(fields[2].split(",")).intersection(allowed))
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": user, "iat": now,
                  "nbf": now - 5, "exp": now + 90, "jti": secrets.token_hex(12),
                  "access": [{"type": "repository", "name": repository, "actions": granted}]}
        unsigned = b64url(compact({"typ": "JWT", "alg": "RS256", "kid": KEY_ID})) + "." + b64url(compact(claims))
        signed = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.server.key)],
                                input=unsigned.encode(), capture_output=True, timeout=5)
        if signed.returncode:
            self.reply(500, b"{}")
            return
        self.reply(200, compact({"token": unsigned + "." + b64url(signed.stdout)}))

    def authenticate(self):
        scheme, _, value = self.headers.get("Authorization", "").partition(" ")
        if scheme != "Basic":
            return None
        try:
            decoded = base64.b64decode(value, validate=True).decode("utf-8")
        except (ValueError, UnicodeError):
            return None
        user, _, password = decoded.partition(":")
        expected = self.server.credentials.get(user)
        if expected is not None and hmac.compare_digest(password.encode(), expected.encode()):
            return user
        return None

    def reply(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        return


def access(issuer, user, password, repo, action):
    credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
    parameters = urlencode({"service": AUDIENCE, "scope": f"repository:{repo}:{action}"})
    return request(issuer.server_port, "GET", f"/token?{parameters}",
                   headers={"Authorization": f"Basic {credentials}"})


def bearer(lab, issuer, user, repo, action):
    status, payload, _ = access(issuer, user, issuer.credentials[user], repo, action)
    if status != 200:
        lab.block("The fixture token issuer did not return the requested response")
    return {"Authorization": "Bearer " + json.loads(payload)["token"]}


def server_key(lab):
    temporary = lab.kubeconfig.parent
    key = temporary / "issuer.key"
    lab.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key))
    key.chmod(0o600)
    modulus = lab.command("openssl", "rsa", "-in", str(key), "-noout", "-modulus").stdout.strip()
    jwks = temporary / "issuer.jwks"
    jwks.write_bytes(compact({"keys": [{"kty": "RSA", "kid": KEY_ID, "use": "sig", "alg": "RS256",
                                       "n": b64url(bytes.fromhex(modulus.split("=", 1)[1])), "e": "AQAB"}]}))
    return key, jwks


def put_artifact(lab, port, issuer, user, repository):
    write = bearer(lab, issuer, user, repository, "pull,push")
    marker = b"{}"
    identifier = "sha256:" + sha256(marker).hexdigest()
    status, _, meta = request(port, "POST", f"/v2/{repository}/blobs/uploads/", b"", write)
    if status != 202:
        lab.block(f"Unable to begin the approved fixture upload: {status}")
    location = urlsplit(meta["Location"])
    separator = "&" if location.query else "?"
    suffix = f"?{location.query}" if location.query else ""
    upload = f"{location.path}{suffix}{separator}{urlencode({'digest': identifier})}"
    result, _, _ = request(port, "PUT", upload, marker, {**write, "Content-Type": "application/octet-stream"})
    if result != 201:
        lab.block(f"Unable to seed the fixture blob: {result}")
    return compact({
        "schemaVersion": 2, "mediaType": MANIFEST, "artifactType": "application/vnd.saf.fixture",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": identifier, "size": len(marker)},
        "layers": [],
    })


def put_manifest(lab, port, issuer, user, repository, tag, content):
    auth = bearer(lab, issuer, user, repository, "pull,push")
    return request(port, "PUT", f"/v2/{repository}/manifests/{tag}", content,
                   {**auth, "Content-Type": MANIFEST})


def get_manifest(lab, port, issuer, user, repository, tag):
    auth = bearer(lab, issuer, user, repository, "pull")
    return request(port, "GET", f"/v2/{repository}/manifests/{tag}",
                   headers={**auth, "Accept": MANIFEST})


def insufficient(result):
    status, _, headers = result
    challenge = headers.get("Www-Authenticate", headers.get("WWW-Authenticate", ""))
    return status == 401 and 'insufficient_scope' in challenge


def apply_roles(lab, issuer):
    policy = {
        "reader": {REPOSITORY: ["pull"]},
        "publisher": {REPOSITORY: ["pull", "push"]},
        "other-publisher": {ADJACENT: ["pull", "push"]},
    }
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "registry-roles"},
        "data": {"roles.json": compact(policy).decode()},
    })
    installed = json.loads(lab.kubectl("get", "configmap", "registry-roles", "-o", "json").stdout)
    issuer.roles = json.loads(installed["data"]["roles.json"])


def exercise(lab, registry, issuer):
    address = lab.command("docker", "port", registry, "5000/tcp").stdout.strip()
    match = re.fullmatch(r"127\.0\.0\.1:(\d+)", address)
    if not match:
        lab.block("The registry did not publish on owned loopback")
    port = int(match[1])
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            ping = request(port, "GET", "/v2/")
            if ping[0] in (200, 401):
                break
        except OSError:
            pass
        time.sleep(0.4)
    else:
        lab.block("The owned registry did not start")

    content = put_artifact(lab, port, issuer, "publisher", REPOSITORY)
    adjacent = put_artifact(lab, port, issuer, "other-publisher", ADJACENT)
    for user, repository, manifest in (("publisher", REPOSITORY, content), ("other-publisher", ADJACENT, adjacent)):
        if put_manifest(lab, port, issuer, user, repository, "original", manifest)[0] != 201:
            lab.block("Unable to seed the owned release fixture")

    baseline = put_manifest(lab, port, issuer, "reader", REPOSITORY, "before-policy", content)[0]
    lab.check("red", "The authenticated reader can publish before repository roles restrict it",
              baseline == 201, {"manifest_status": baseline})
    apply_roles(lab, issuer)

    anonymous = request(port, "GET", f"/v2/{REPOSITORY}/manifests/original",
                        headers={"Accept": MANIFEST})
    challenge = anonymous[2].get("Www-Authenticate", anonymous[2].get("WWW-Authenticate", ""))
    rejected_password = access(issuer, "reader", "invalid-fixture-password", REPOSITORY, "pull")[0] == 401
    anonymous_write = request(port, "PUT", f"/v2/{REPOSITORY}/manifests/anonymous-write", content,
                              {"Content-Type": MANIFEST})[0] == 401
    challenged = anonymous[0] == 401 and challenge.startswith("Bearer ")
    lab.check("green", "The registry protects both operations and the issuer rejects bad credentials",
              challenged and anonymous_write and rejected_password,
              {"anonymous_read_challenged": challenged, "anonymous_write_challenged": anonymous_write,
               "bad_credentials_rejected": rejected_password})

    reader_write = insufficient(put_manifest(lab, port, issuer, "reader", REPOSITORY, "reader-write", content))
    reader_read = get_manifest(lab, port, issuer, "reader", REPOSITORY, "original")
    lab.check("green", "Registry scope prevents the authenticated reader from publishing", reader_write,
              {"reader_write_insufficient_scope": reader_write})
    lab.check("positive", "The reader still fetches the exact original manifest",
              reader_read[:2] == (200, content), {"reader_got_original": reader_read[:2] == (200, content)})

    denied_read = insufficient(get_manifest(lab, port, issuer, "publisher", ADJACENT, "original"))
    denied_write = insufficient(put_manifest(lab, port, issuer, "publisher", ADJACENT, "adjacent-write", adjacent))
    lab.check("green", "The publisher lacks read and write permissions in the other owned repository",
              denied_read and denied_write, {"cross_repo_pull_denied": denied_read, "cross_repo_push_denied": denied_write})
    published = put_manifest(lab, port, issuer, "publisher", REPOSITORY, "publisher-write", content)[0] == 201
    readback = get_manifest(lab, port, issuer, "reader", REPOSITORY, "publisher-write")[:2] == (200, content)
    lab.check("positive", "The publisher can publish in its approved repository and the reader can fetch it",
              published and readback, {"approved_publish": published, "approved_readback": readback})
    (lab.evidence / "registry-authorization.json").write_text(
        json.dumps({"baseline_write": baseline, "reader_write_denied": reader_write,
                    "cross_repo_pull_denied": denied_read, "cross_repo_push_denied": denied_write,
                    "publisher_write_allowed": published, "original_content_readable": readback},
                   indent=2, sort_keys=True) + "\n")


def run(lab):
    import yaml

    registry = f"{lab.cluster}-scoped-registry"
    key, jwks = server_key(lab)
    with ThreadingHTTPServer(("127.0.0.1", 0), TokenIssuer) as issuer:
        issuer.key = key
        issuer.credentials = {role: secrets.token_hex(20) for role in ("reader", "publisher", "other-publisher")}
        issuer.roles = {
            "reader": {REPOSITORY: ["pull", "push"]},
            "publisher": {REPOSITORY: ["pull", "push"]},
            "other-publisher": {ADJACENT: ["pull", "push"]},
        }
        server = threading.Thread(target=issuer.serve_forever, daemon=True)
        server.start()
        started = False
        try:
            config = lab.kubeconfig.parent / "registry.yml"
            config.write_text(yaml.safe_dump({
                "version": "0.1", "storage": {"filesystem": {"rootdirectory": "/var/lib/registry"}},
                "http": {"addr": "0.0.0.0:5000"},
                "auth": {"token": {"realm": f"http://127.0.0.1:{issuer.server_port}/token",
                                   "issuer": ISSUER, "service": AUDIENCE, "jwks": "/fixture.jwks"}},
            }))
            lab.command("docker", "run", "--detach", "--name", registry, "--publish", "127.0.0.1::5000",
                        "--volume", f"{config}:/fixture.yml:ro", "--volume", f"{jwks}:/fixture.jwks:ro",
                        REGISTRY, "serve", "/fixture.yml")
            started = True
            exercise(lab, registry, issuer)
        finally:
            if started:
                result = lab.command("docker", "rm", "-fv", registry, allow_failure=True)
                lab.check("positive", "The owned registry and its temporary storage were removed",
                          result.returncode == 0, {"fixture_resources_removed": result.returncode == 0})
            issuer.shutdown()
            server.join(5)
