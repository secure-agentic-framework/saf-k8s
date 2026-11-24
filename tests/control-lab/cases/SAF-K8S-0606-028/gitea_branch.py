#!/usr/bin/env python3
"""Disposable Gitea branch-protection fixture for the standard SAF Lab runner."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from typing import Optional
import urllib.error
import urllib.request


GITEA_IMAGE = ("docker.gitea.com/gitea:1.23.8-rootless@sha256:"
               "331875f35bdcc3c1110fc8410a4e809e3103ebb091ef424fec2df53ac1b658fc")
EXPECTED_VERSION = "1.23.8"
OWNER, WRITER, REVIEWER, READER = (
    "fixture-owner", "fixture-writer", "fixture-reviewer", "fixture-flux-reader"
)
REPO = "fixture-deployment"
STATUS_CONTEXT = "saf-fixture/promotion"
MAIN = "main"
SIGNATURE_BRANCH = "fixture-signature-probe"
SCOPE = (
    "One fresh standard-Lab Kind cluster and one disposable Gitea 1.23.8 Community "
    "Edition instance. Synthetic users and one private repository; inert text only; "
    "HTTP Git/API through an owned 127.0.0.1 port-forward and Flux Git reads through "
    "an owned ClusterIP Service. The .3 flow uses Flux v2.9.0 with source-controller "
    "v1.9.1 and kustomize-controller v1.9.1. Does not assess production provider "
    "policy, external repositories, or production key custody."
)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def safe_run(argv: list[str], *, env: Optional[dict[str, str]] = None,
             cwd: Optional[pathlib.Path] = None, input_bytes: Optional[bytes] = None,
             timeout: int = 45, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    """Capture all output; errors never include arguments, output, or API/key data."""
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, input=input_bytes,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("A fixture-local command failed or timed out") from exc
    if check and result.returncode:
        raise RuntimeError("A fixture-local command returned a nonzero status")
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, url):
        return None


def api(base: str, method: str, path: str, *, token: Optional[str] = None,
        basic: Optional[tuple[str, str]] = None,
        body: Optional[dict[str, object]] = None,
        error_reason: bytes = b"") -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "token " + token
    if basic is not None:
        headers["Authorization"] = "Basic " + base64.b64encode(
            f"{basic[0]}:{basic[1]}".encode()).decode()
    payload = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(base + "/api/v1" + path, data=payload,
                                     headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=12) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        # Retain only the known reason from an explicitly inspected denial.
        with exc:
            matches = error_reason and error_reason in exc.read(8192)
        return exc.code, error_reason if matches else b""
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError("The loopback Gitea API request failed") from exc


def json_call(base: str, method: str, path: str, *, token: str,
              body: Optional[dict[str, object]] = None,
              expected: tuple[int, ...] = (200,)) -> dict[str, object]:
    status, payload = api(base, method, path, token=token, body=body)
    require(status in expected, f"Gitea API {method} {path}: HTTP {status}")
    if not payload:
        return {}
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Gitea returned an invalid JSON response") from exc
    require(isinstance(value, dict), "Gitea returned an unexpected JSON shape")
    return value


def configure_server_signer(lab):
    # The Gitea merge service checks its configured signer even for Fast Forward Only.
    # The key is generated in the Pod's emptyDir and never exported.
    script = """
set -eu
export HOME=/var/lib/gitea/fixture-git-home
export GNUPGHOME="$HOME/.gnupg"
umask 077
mkdir -p "$GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
    'Synthetic merge signer <fixture-server@example.invalid>' rsa2048 sign 0
key=$(gpg --batch --with-colons --list-secret-keys fixture-server@example.invalid | awk -F: '$1=="fpr" {print $10; exit}')
test -n "$key"
git config --global user.signingkey "$key"
git config --global user.name 'Synthetic merge signer'
git config --global user.email fixture-server@example.invalid
git config --global commit.gpgsign true
"""
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               f"kind-{lab.cluster}", "-n", "saf-test", "exec", "pod/fixture-gitea",
               "--", "sh", "-c", script]
    result = safe_run(command, env=lab.env, check=False)
    require(result.returncode == 0, "Could not initialize the ephemeral Gitea merge signer")


def create_user(lab, username: str, password: str, *, admin: bool = False) -> None:
    # Password is delivered only on stdin; Lab.command would persist payloads.
    script = ('IFS= read -r secret; exec gitea admin user create --username "$1" '
              '--password "$secret" --email "$1@example.invalid" '
              '--must-change-password=false "$2"')
    argv = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
            f"kind-{lab.cluster}", "-n", "saf-test", "exec", "-i",
            "pod/fixture-gitea", "--", "sh", "-c", script,
            "create-user", username, "--admin" if admin else "--admin=false"]
    result = safe_run(argv, env=lab.env, input_bytes=(password + "\n").encode())
    require(result.returncode == 0, f"Could not create synthetic account {username}")


def create_token(base: str, username: str, password: str,
                 name: str, scopes: list[str]) -> str:
    status, payload = api(base, "POST", f"/users/{username}/tokens",
                          basic=(username, password),
                          body={"name": name, "scopes": scopes})
    require(status == 201, f"Could not create ephemeral token for {username}")
    try:
        token = json.loads(payload).get("sha1")
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
        raise RuntimeError("Gitea did not return a token object") from exc
    require(isinstance(token, str) and bool(token), "Gitea token response was empty")
    return token


def git_env(askpass: pathlib.Path, username: str, password: str,
            gnupg_home: pathlib.Path | None = None) -> dict[str, str]:
    env = os.environ.copy()
    for key in tuple(env):
        if (key.startswith(("GIT_TRACE", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")) or
                key in {"GIT_CURL_VERBOSE", "GIT_CONFIG_PARAMETERS", "GIT_DIR",
                        "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                        "GIT_ALTERNATE_OBJECT_DIRECTORIES"}):
            env.pop(key, None)
    env.update({
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "credential.helper", "GIT_CONFIG_VALUE_0": "",
        "GIT_CONFIG_KEY_1": "http.followRedirects", "GIT_CONFIG_VALUE_1": "false",
        "GIT_ASKPASS": str(askpass), "SAF_GIT_USERNAME": username,
        "SAF_GIT_PASSWORD": password, "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
        "GIT_AUTHOR_NAME": "SAF fixture writer",
        "GIT_AUTHOR_EMAIL": f"{WRITER}@example.invalid",
        "GIT_COMMITTER_NAME": "SAF fixture writer",
        "GIT_COMMITTER_EMAIL": f"{WRITER}@example.invalid",
        "GIT_AUTHOR_DATE": "2025-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2025-01-01T00:00:00Z",
    })
    if gnupg_home is not None:
        env["GNUPGHOME"] = str(gnupg_home)
    else:
        env.pop("GNUPGHOME", None)
    return env


def git(path: pathlib.Path, *args: str, env: dict[str, str],
        check: bool = True) -> subprocess.CompletedProcess[bytes]:
    # Empty helper-list and no global/system config are active on every invocation.
    return safe_run(["git", "-c", "credential.helper=", *args], cwd=path,
                    env=env, check=check)


def gpg_wrapper(path: pathlib.Path) -> None:
    path.write_text("#!/bin/sh\nexec gpg --batch --yes --pinentry-mode loopback --passphrase '' \"$@\"\n")
    path.chmod(0o700)


def make_commit(repo: pathlib.Path, filename: Optional[str], text: str = "", *,
                env: dict[str, str], signed: bool, gpg_program: Optional[pathlib.Path],
                signing_key: Optional[str]) -> str:
    if filename is not None:
        (repo / filename).parent.mkdir(parents=True, exist_ok=True)
        (repo / filename).write_text(text, encoding="utf-8")
    git(repo, "add", "-A", env=env)
    config = ["-c", "commit.gpgsign=true", "-c", f"gpg.program={gpg_program}",
              "-c", f"user.signingkey={signing_key}"] if signed else ["-c", "commit.gpgsign=false"]
    safe_run(["git", *config, "-c", "credential.helper=", "commit", "-m",
              "fixture: inert deployment marker"], cwd=repo, env=env)
    sha = git(repo, "rev-parse", "HEAD", env=env).stdout.decode().strip()
    require(bool(re.fullmatch(r"[0-9a-f]{40,64}", sha)), "Git returned an invalid fixture commit id")
    return sha


def push_branch(repo: pathlib.Path, branch: str, *, env: dict[str, str],
                expected_sha: str) -> bool:
    result = git(repo, "push", "origin", f"HEAD:refs/heads/{branch}", env=env, check=False)
    require(result.returncode == 0, f"HTTP Git push to fixture branch {branch} failed")
    require(git(repo, "rev-parse", "HEAD", env=env).stdout.decode().strip() == expected_sha,
            "Local fixture commit changed before its HTTP Git push")
    return True


def remote_sha(repo: pathlib.Path, branch: str, *, env: dict[str, str]) -> Optional[str]:
    result = git(repo, "ls-remote", "origin", f"refs/heads/{branch}", env=env)
    lines = result.stdout.decode().splitlines()
    require(len(lines) <= 1, "Remote returned duplicate refs for one fixture branch")
    if not lines:
        return None
    sha, ref = lines[0].split("\t", 1)
    require(ref == f"refs/heads/{branch}", "Remote returned a different fixture ref")
    return sha


def commit_record(base: str, token: str, sha: str) -> dict[str, object]:
    return json_call(base, "GET", f"/repos/{OWNER}/{REPO}/git/commits/{sha}", token=token)


def require_verified(base: str, token: str, sha: str) -> bool:
    record = commit_record(base, token, sha)
    require(record.get("sha") == sha, "Gitea returned a different fixture commit")
    verification = record.get("commit", {}).get("verification")
    verified = isinstance(verification, dict) and verification.get("verified") is True
    require(verified, "Gitea did not report the generated fixture signature as verified")
    return verified


def exact_rule(base: str, token: str, branch: str,
               expected: dict[str, object]) -> dict[str, object]:
    rule = json_call(base, "GET",
                     f"/repos/{OWNER}/{REPO}/branch_protections/{branch}", token=token)
    for field, value in expected.items():
        require(rule.get(field) == value, f"Gitea effective {branch} rule mismatched field {field}")
    require(rule.get("rule_name") == branch and rule.get("branch_name") == branch,
            f"Gitea returned a non-exact {branch} rule")
    return {key: rule.get(key) for key in sorted(expected | {"rule_name": branch,
                                                              "branch_name": branch})}


def create_pr(base: str, token: str, head: str) -> tuple[int, str]:
    pr = json_call(base, "POST", f"/repos/{OWNER}/{REPO}/pulls", token=token,
                   body={"title": "Synthetic protected promotion", "head": head,
                         "base": MAIN, "body": "Inert fixture change."}, expected=(201,))
    index = pr.get("number")
    head_obj = pr.get("head")
    commit = head_obj.get("sha") if isinstance(head_obj, dict) else None
    require(isinstance(index, int) and isinstance(commit, str),
            "Gitea pull request omitted number or exact head SHA")
    return index, commit


def post_status(base: str, token: str, sha: str, *, success: bool) -> dict[str, object]:
    value = json_call(base, "POST", f"/repos/{OWNER}/{REPO}/statuses/{sha}", token=token,
                      body={"state": "success" if success else "failure",
                            "context": STATUS_CONTEXT,
                            "description": "Synthetic fixture status"}, expected=(201,))
    require(value.get("context") == STATUS_CONTEXT and
            value.get("status") == ("success" if success else "failure"),
            "Gitea status response did not match exact context/state")
    return value


def post_approval(base: str, token: str, index: int, head: str) -> dict[str, object]:
    review = json_call(base, "POST", f"/repos/{OWNER}/{REPO}/pulls/{index}/reviews",
                       token=token, body={"event": "APPROVED", "commit_id": head,
                                         "body": "Synthetic independent fixture approval."},
                       expected=(200,))
    require(review.get("state", "").upper() == "APPROVED",
            "Gitea review response did not report approval")
    require(review.get("commit_id") == head,
            "Gitea approval was not bound to the exact pull-request head SHA")
    reviewer = review.get("user")
    require(isinstance(reviewer, dict) and reviewer.get("login") == REVIEWER,
            "Gitea approval was not submitted by the separate synthetic reviewer")
    list_status, list_payload = api(base, "GET", f"/repos/{OWNER}/{REPO}/pulls/{index}/reviews", token=token)
    require(list_status == 200, "Could not read back the synthetic pull-request reviews")
    try:
        reviews = json.loads(list_payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Gitea returned an invalid review list") from exc
    require(isinstance(reviews, list) and any(
        isinstance(item, dict) and item.get("id") == review.get("id") and
        item.get("state", "").upper() == "APPROVED" and
        item.get("commit_id") == head and isinstance(item.get("user"), dict) and
        item["user"].get("login") == REVIEWER for item in reviews),
        "Gitea review list did not corroborate the exact approved head SHA")
    return review


def attempt_merge(base: str, token: str, index: int, head: str,
                  error_reason: bytes = b"") -> tuple[int, bytes]:
    return api(base, "POST", f"/repos/{OWNER}/{REPO}/pulls/{index}/merge",
               token=token, error_reason=error_reason,
               body={"Do": "fast-forward-only", "head_commit_id": head})


def merge_denied(base: str, token: str, index: int, head: str, read_main,
                 expected_main: str, reason: bytes) -> tuple[int, bool]:
    status, matched_reason = attempt_merge(base, token, index, head, reason)
    require(status == 405 and matched_reason == reason,
            f"Expected exact required gate denial {reason.decode()} (HTTP {status})")
    after = read_main()
    require(after == expected_main, "Denied merge changed protected main SHA")
    pr = json_call(base, "GET", f"/repos/{OWNER}/{REPO}/pulls/{index}", token=token)
    require(pr.get("merged") is False, "Denied pull request is reported merged")
    return status, after == expected_main


def make_repo(base: str, writer_token: str, owner_token: str,
              askpass: pathlib.Path, scratch: pathlib.Path,
              main_rule: dict[str, object], sig_rule: dict[str, object], *,
              writer_env: dict[str, str], gpg_program: pathlib.Path,
              signing_key: str) -> dict[str, object]:
    status, _ = api(base, "POST", "/user/repos", token=owner_token,
                    body={"name": REPO, "private": True, "auto_init": False,
                          "default_branch": MAIN})
    require(status == 201, f"Could not create the private synthetic repository (HTTP {status})")
    json_call(base, "PATCH", f"/repos/{OWNER}/{REPO}", token=owner_token,
              body={"allow_fast_forward_only_merge": True}, expected=(200,))
    repository = json_call(base, "GET", f"/repos/{OWNER}/{REPO}", token=owner_token)
    require(repository.get("private") is True and
            repository.get("allow_fast_forward_only_merge") is True,
            "Gitea repository is not private or Fast Forward Only is not enabled")
    status, _ = api(base, "PUT", f"/repos/{OWNER}/{REPO}/collaborators/{WRITER}",
                    token=owner_token, body={"permission": "write"})
    require(status == 204, "Could not grant writer access to the owned fixture repository")
    status, _ = api(base, "PUT", f"/repos/{OWNER}/{REPO}/collaborators/{REVIEWER}",
                    token=owner_token, body={"permission": "write"})
    require(status == 204, "Could not grant synthetic reviewer access to the owned fixture repository")
    status, _ = api(base, "PUT", f"/repos/{OWNER}/{REPO}/collaborators/{READER}",
                    token=owner_token, body={"permission": "read"})
    require(status == 204, "Could not grant read-only access to the Flux fixture collaborator")

    env = git_env(askpass, WRITER, writer_token)
    url = f"{base}/{OWNER}/{REPO}.git"
    seed = scratch / "seed"
    seed.mkdir(mode=0o700)
    safe_run(["git", "init", "--template=", "--initial-branch=" + MAIN], cwd=seed, env=env)
    source = seed / "flux-source"
    source.mkdir(mode=0o700)
    (source / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - marker.yaml\n",
        encoding="utf-8")
    (source / "marker.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: saf-gitea-guard-marker\n  namespace: saf-test\ndata:\n  value: saf-gitea-protected-baseline\n",
        encoding="utf-8")
    baseline = make_commit(seed, None,
                           env=writer_env, signed=True, gpg_program=gpg_program,
                           signing_key=signing_key)
    safe_run(["git", "-c", "credential.helper=", "remote", "add", "origin", url], cwd=seed, env=env)
    # Ordinary pre-protection application flow: real HTTP Git push and exact ref readback.
    safe_run(["git", "-c", "credential.helper=", "push", "-u", "origin", "HEAD:refs/heads/main"], cwd=seed, env=env)
    require(remote_sha(seed, MAIN, env=env) == baseline,
            "Pre-protection HTTP Git baseline did not resolve to the exact expected SHA")
    baseline_signature_verified = require_verified(base, owner_token, baseline)

    for branch, body in ((MAIN, main_rule), (SIGNATURE_BRANCH, sig_rule)):
        result = json_call(base, "POST", f"/repos/{OWNER}/{REPO}/branch_protections",
                           token=owner_token, body=body, expected=(201,))
        require(result.get("branch_name") == branch and result.get("rule_name") == branch,
                f"Created rule did not preserve exact rule and branch names for {branch}")
    effective_main = exact_rule(base, owner_token, MAIN, main_rule)
    effective_sig = exact_rule(base, owner_token, SIGNATURE_BRANCH, sig_rule)
    return {"repo_private": True, "fast_forward_only_enabled": True,
            "baseline_http_git_write": True, "baseline_sha": baseline,
            "baseline_signature_verified": baseline_signature_verified,
            "main_rule": effective_main, "signature_rule": effective_sig,
            "git_env": env, "git_repo": seed, "git_url": url}


def observe(lab, base: str, scratch: pathlib.Path, askpass: pathlib.Path,
            gpg_home: pathlib.Path, gpg_program: pathlib.Path,
            flux_checkpoint=None) -> dict[str, object]:
    required_tools = ("git", "gpg", "gpgconf")
    require(all(shutil.which(name) for name in required_tools),
            "git and GnuPG are required for the synthetic fixture")
    gpg_home.mkdir(mode=0o700)
    passwords = {name: secrets.token_urlsafe(32) for name in (OWNER, WRITER, REVIEWER, READER)}
    create_user(lab, OWNER, passwords[OWNER], admin=True)
    create_user(lab, WRITER, passwords[WRITER])
    create_user(lab, REVIEWER, passwords[REVIEWER])
    create_user(lab, READER, passwords[READER])
    owner_token = create_token(base, OWNER, passwords[OWNER], "saf-fixture-owner", ["write:repository", "write:user"])
    writer_token = create_token(base, WRITER, passwords[WRITER], "saf-fixture-writer", ["write:repository", "write:user"])
    reviewer_token = create_token(base, REVIEWER, passwords[REVIEWER], "saf-fixture-reviewer", ["write:repository"])
    reader_token = create_token(base, READER, passwords[READER], "saf-flux-read-only", ["read:repository"])
    version = json_call(base, "GET", "/version", token=owner_token)
    require(version.get("version") == EXPECTED_VERSION, "Runtime Gitea version differs from the pinned release")

    # A clean, private GNUPGHOME is used only for this generated fixture key.
    key_email = f"{WRITER}@example.invalid"
    safe_run(["gpg", "--homedir", str(gpg_home), "--batch", "--passphrase", "",
              "--quick-generate-key", f"SAF fixture writer <{key_email}>", "rsa2048", "sign", "0"], timeout=90)
    keylist = safe_run(["gpg", "--homedir", str(gpg_home), "--batch", "--with-colons",
                        "--list-secret-keys", "--keyid-format", "long", key_email]).stdout.decode()
    key_ids = [line.split(":")[4] for line in keylist.splitlines()
               if line.startswith("sec:") and len(line.split(":")) > 4]
    require(len(key_ids) == 1 and bool(key_ids[0]), "Generated fixture signing key was not available")
    signing_key = key_ids[0]
    armored = safe_run(["gpg", "--homedir", str(gpg_home), "--batch", "--armor",
                        "--export", key_email]).stdout.decode()
    require("BEGIN PGP PUBLIC KEY BLOCK" in armored, "Generated public key export was empty")
    status, _ = api(base, "POST", "/user/gpg_keys", token=writer_token,
                    body={"armored_public_key": armored})
    require(status == 201, "Could not register the generated public signing key")
    gpg_wrapper(gpg_program)

    main_rule = {
        "branch_name": MAIN, "rule_name": MAIN, "enable_push": False,
        "enable_push_whitelist": False, "push_whitelist_usernames": [],
        "enable_force_push": False, "enable_force_push_allowlist": False,
        "force_push_allowlist_usernames": [], "require_signed_commits": True,
        "required_approvals": 1, "enable_status_check": True,
        "status_check_contexts": [STATUS_CONTEXT], "block_admin_merge_override": True,
        "block_on_rejected_reviews": True, "dismiss_stale_approvals": True,
        "enable_approvals_whitelist": False, "approvals_whitelist_username": [],
        "enable_merge_whitelist": False, "merge_whitelist_usernames": [],
    }
    sig_rule = {
        "branch_name": SIGNATURE_BRANCH, "rule_name": SIGNATURE_BRANCH,
        "enable_push": True, "enable_push_whitelist": True,
        "push_whitelist_usernames": [WRITER], "enable_force_push": False,
        "require_signed_commits": True, "required_approvals": 0,
        "enable_status_check": False, "status_check_contexts": [],
        "enable_force_push_allowlist": False, "force_push_allowlist_usernames": [],
        "enable_approvals_whitelist": False, "approvals_whitelist_username": [],
        "enable_merge_whitelist": False, "merge_whitelist_usernames": [],
    }
    env = git_env(askpass, WRITER, writer_token, gpg_home)
    repo = make_repo(base, writer_token, owner_token, askpass, scratch, main_rule, sig_rule,
                     writer_env=env, gpg_program=gpg_program, signing_key=signing_key)
    git_repo = repo["git_repo"]

    def read_main():
        result = remote_sha(git_repo, MAIN, env=env)
        require(result is not None, "The fixture lost its protected main ref")
        return result

    protected_baseline = read_main()
    require(protected_baseline == repo["baseline_sha"],
            "Protected main differs from the signed pre-protection baseline")
    if flux_checkpoint is not None:
        flux_checkpoint("protected-signed-baseline", protected_baseline, reader=READER,
                        reader_token=reader_token, writer_public_key=armored)

    # Authenticated writer's HTTP push is allowed only on this exact signature test branch.
    sig_local = scratch / "signature-probe"
    safe_run(["git", "-c", "credential.helper=", "clone", "--no-checkout", repo["git_url"], str(sig_local)], env=env)
    safe_run(["git", "-c", "credential.helper=", "checkout", MAIN], cwd=sig_local, env=env)
    unsigned_sha = make_commit(sig_local, "fixture/unsigned-marker.txt", "unsigned inert probe\n",
                               env=env, signed=False, gpg_program=None, signing_key=None)
    unsigned_result = git(sig_local, "push", "origin", f"HEAD:refs/heads/{SIGNATURE_BRANCH}", env=env, check=False)
    require(unsigned_result.returncode != 0, "Unsigned commit unexpectedly passed the exact signature rule")
    unsigned_denial_text = (unsigned_result.stdout + unsigned_result.stderr).decode(errors="replace").lower()
    unsigned_denial_corroborated = ("protected from unverified commit" in unsigned_denial_text and
                                    unsigned_sha.lower() in unsigned_denial_text)
    require(unsigned_denial_corroborated,
            "Gitea did not identify the unsigned fixture commit as the signed-rule denial reason")
    unsigned_ref_unchanged = remote_sha(sig_local, SIGNATURE_BRANCH, env=env) is None
    require(unsigned_ref_unchanged,
            "Unsigned signature denial created or changed the protected branch")
    if flux_checkpoint is not None:
        flux_checkpoint("unsigned-signature-denied", read_main(), reader=READER,
                        reader_token=reader_token, writer_public_key=armored)
    git(sig_local, "reset", "--hard", "origin/main", env=env)
    git(sig_local, "clean", "-fd", env=env)
    signed_sha = make_commit(sig_local, "fixture/signed-marker.txt", "signed inert probe\n",
                             env=env, signed=True, gpg_program=gpg_program, signing_key=signing_key)
    signed_ok = push_branch(sig_local, SIGNATURE_BRANCH, env=env, expected_sha=signed_sha)
    require(remote_sha(sig_local, SIGNATURE_BRANCH, env=env) == signed_sha,
            "Signed HTTP Git push did not create the exact signature-probe ref")
    signature_verified = require_verified(base, owner_token, signed_sha)

    # Direct push to main uses a valid signature so only the disabled direct-push gate is tested.
    main_probe = scratch / "main-direct-probe"
    safe_run(["git", "-c", "credential.helper=", "clone", "--branch", MAIN,
              repo["git_url"], str(main_probe)], env=env)
    protected_main_before = read_main()
    direct_sha = make_commit(main_probe, "fixture/direct-push-probe.txt", "signed direct push probe\n",
                             env=env, signed=True, gpg_program=gpg_program, signing_key=signing_key)
    direct = git(main_probe, "push", "origin", "HEAD:refs/heads/main", env=env, check=False)
    require(direct.returncode != 0, "Signed direct push unexpectedly passed protected main")
    direct_denial_text = (direct.stdout + direct.stderr).decode(errors="replace").lower()
    direct_denial_corroborated = "not allowed to push to protected branch main" in direct_denial_text
    require(direct_denial_corroborated,
            "Gitea did not identify protected main as the direct-push denial reason")
    protected_main_after = read_main()
    require(protected_main_after == protected_main_before,
            "Denied direct push changed protected main SHA")
    if flux_checkpoint is not None:
        flux_checkpoint("signed-direct-push-denied", protected_main_after, reader=READER,
                        reader_token=reader_token, writer_public_key=armored)

    # Three independent PR heads share the unchanged base. Each failure has only one missing gate.
    prs: dict[str, tuple[int, str, pathlib.Path]] = {}
    for label in ("status-denied", "approval-denied", "promotion"):
        branch = "fixture/" + label
        path = scratch / label
        safe_run(["git", "-c", "credential.helper=", "clone", "--branch", MAIN,
                  repo["git_url"], str(path)], env=env)
        if label == "promotion":
            (path / "flux-source" / "marker.yaml").write_text(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: saf-gitea-guard-marker\n  namespace: saf-test\ndata:\n  value: saf-gitea-approved-promotion\n",
                encoding="utf-8")
        head = make_commit(path, f"fixture/{label}.txt", f"synthetic {label} bytes\n",
                           env=env, signed=True, gpg_program=gpg_program, signing_key=signing_key)
        push_branch(path, branch, env=env, expected_sha=head)
        require(remote_sha(path, branch, env=env) == head and require_verified(base, owner_token, head),
                f"Signed PR branch {branch} did not retain its exact verified Git commit")
        index, api_head = create_pr(base, writer_token, branch)
        require(api_head == head, f"Pull request {branch} head differs from pushed commit")
        prs[label] = (index, head, path)

    status_index, status_head, _ = prs["status-denied"]
    approval = post_approval(base, reviewer_token, status_index, status_head)
    status_pr = json_call(base, "GET", f"/repos/{OWNER}/{REPO}/pulls/{status_index}", token=owner_token)
    require(status_pr.get("head", {}).get("sha") == status_head,
            "Prior approval case changed PR head before the status denial")
    status_denied, status_unchanged = merge_denied(
        base, writer_token, status_index, status_head, read_main, protected_main_before,
        b"Not all required status checks successful")
    if flux_checkpoint is not None:
        flux_checkpoint("missing-status-denied", read_main(), reader=READER,
                        reader_token=reader_token, writer_public_key=armored)
    status_positive = post_status(base, owner_token, status_head, success=True)

    approval_index, approval_head, _ = prs["approval-denied"]
    status_ok = post_status(base, owner_token, approval_head, success=True)
    approval_denied, approval_unchanged = merge_denied(
        base, writer_token, approval_index, approval_head, read_main, protected_main_before,
        b"Does not have enough approvals")
    if flux_checkpoint is not None:
        flux_checkpoint("missing-approval-denied", read_main(), reader=READER,
                        reader_token=reader_token, writer_public_key=armored)
    approval_positive = post_approval(base, reviewer_token, approval_index, approval_head)

    promotion_index, promotion_head, _ = prs["promotion"]
    promotion_approval = post_approval(base, reviewer_token, promotion_index, promotion_head)
    promotion_status = post_status(base, owner_token, promotion_head, success=True)
    current_before_merge = read_main()
    require(current_before_merge == protected_main_before,
            "Protected main changed before final fast-forward promotion")
    merge_status, signing_error = attempt_merge(
        base, writer_token, promotion_index, promotion_head, b"requires signed commits")
    require(not signing_error, "Gitea requires its merge-signing configuration for this protected target")
    require(merge_status == 200, f"Fully gated fast-forward promotion failed (HTTP {merge_status})")
    promotion_after = read_main()
    merged_pr = json_call(base, "GET", f"/repos/{OWNER}/{REPO}/pulls/{promotion_index}", token=owner_token)
    require(merged_pr.get("merged") is True and promotion_after == promotion_head,
            "Fast-forward-only merge did not preserve the exact signed PR head as main")
    final_verified = require_verified(base, owner_token, promotion_after)
    if flux_checkpoint is not None:
        flux_checkpoint("fully-gated-signed-promotion", promotion_after, reader=READER,
                        reader_token=reader_token, writer_public_key=armored)

    return {
        "gitea_version": EXPECTED_VERSION,
        "fixture_repo_private": repo["repo_private"],
        "allow_fast_forward_only_merge": repo["fast_forward_only_enabled"],
        "ordinary_baseline_http_git_write": True,
        "baseline_sha": repo["baseline_sha"],
        "baseline_signature_verified": repo["baseline_signature_verified"],
        "effective_main_rule": repo["main_rule"],
        "effective_signature_rule": repo["signature_rule"],
        "unsigned_signature_push_denied_ref_unchanged": unsigned_result.returncode != 0 and
        unsigned_denial_corroborated and unsigned_ref_unchanged,
        "signed_signature_push_accepted": signed_ok,
        "signed_signature_push_verified": signature_verified,
        "signed_direct_push_denied": direct.returncode != 0 and direct_denial_corroborated,
        "direct_push_candidate_sha": direct_sha,
        "direct_push_main_sha_unchanged": protected_main_after == protected_main_before,
        "status_case": {"prior_approval_recorded": approval.get("state", "APPROVED").upper() == "APPROVED",
                         "approval_head_sha": status_head, "missing_status_denied_http": status_denied,
                         "missing_status_denied_main_unchanged": status_unchanged,
                         "exact_success_status_recorded": status_positive.get("context") == STATUS_CONTEXT and
                         status_positive.get("status") == "success"},
        "approval_case": {"exact_success_status_recorded_first": status_ok.get("context") == STATUS_CONTEXT and
                          status_ok.get("status") == "success",
                          "missing_approval_denied_http": approval_denied,
                          "missing_approval_denied_main_unchanged": approval_unchanged,
                          "approval_recorded": approval_positive.get("state", "").upper() == "APPROVED"},
        "promotion": {"prior_exact_approval": promotion_approval.get("state", "").upper() == "APPROVED",
                      "prior_exact_success_status": promotion_status.get("context") == STATUS_CONTEXT and
                      promotion_status.get("status") == "success",
                      "merge_http": merge_status, "merged": merged_pr.get("merged") is True,
                      "main_equals_exact_signed_pr_head": promotion_after == promotion_head,
                      "final_head_signature_verified": final_verified,
                      "final_main_sha": promotion_after},
    }


def setup_server(lab) -> None:
    settings = {
        "GITEA__database__DB_TYPE": "sqlite3",
        "GITEA__database__PATH": "/var/lib/gitea/data/gitea.db",
        "GITEA__security__INSTALL_LOCK": "true",
        "GITEA__service__DISABLE_REGISTRATION": "true",
        "GITEA__service__REQUIRE_SIGNIN_VIEW": "true",
        "GITEA__server__DOMAIN": "127.0.0.1",
        "GITEA__server__ROOT_URL": "http://127.0.0.1:3000/",
        "GITEA__repository__DEFAULT_BRANCH": MAIN,
        "GITEA__git__HOME_PATH": "/var/lib/gitea/fixture-git-home",
        "GITEA__repository_0X2E_signing__MERGES": "headsigned",
    }
    lab.create({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "fixture-gitea", "labels": {"app": "fixture-gitea"}},
        "spec": {"automountServiceAccountToken": False,
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                     "runAsGroup": 1000, "fsGroup": 1000,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [{"name": "gitea", "image": GITEA_IMAGE,
                                  "imagePullPolicy": "IfNotPresent",
                                  "env": [{"name": name, "value": value}
                                          for name, value in settings.items()],
                                  "securityContext": {"allowPrivilegeEscalation": False,
                                                      "capabilities": {"drop": ["ALL"]}},
                                  "ports": [{"containerPort": 3000}],
                                  "readinessProbe": {"tcpSocket": {"port": 3000},
                                                     "periodSeconds": 2,
                                                     "failureThreshold": 20},
                                  "volumeMounts": [{"name": "data", "mountPath": "/var/lib/gitea"},
                                                   {"name": "config", "mountPath": "/etc/gitea"}]}],
                 "volumes": [{"name": "data", "emptyDir": {}},
                             {"name": "config", "emptyDir": {}}]}})
    lab.create({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": "fixture-gitea"},
                "spec": {"type": "ClusterIP",
                         "selector": {"app": "fixture-gitea"},
                         "ports": [{"name": "http", "port": 3000,
                                    "targetPort": 3000}]}})
    ready = lab.kubectl("wait", "--for=condition=Ready", "pod/fixture-gitea",
                        "--timeout=110s", timeout=120, allow_failure=True)
    if ready.returncode:
        lab.kubectl("describe", "pod/fixture-gitea", allow_failure=True)
        lab.kubectl("logs", "pod/fixture-gitea", "--tail=50", allow_failure=True)
        lab.block("Fixture Gitea Pod did not become ready")


def run(lab, flux_checkpoint=None) -> None:
    temporary = pathlib.Path(tempfile.mkdtemp(prefix="saf-gitea-", dir="/tmp"))
    temporary.chmod(0o700)
    log_path = temporary / "port-forward.log"
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               f"kind-{lab.cluster}", "-n", "saf-test", "port-forward",
               "--address", "127.0.0.1", "pod/fixture-gitea", ":3000"]
    port_forward = None
    gpg_home = temporary / "gnupg"
    cleanup_ok = True
    try:
        setup_server(lab)
        configure_server_signer(lab)
        with log_path.open("w", encoding="utf-8") as output:
            port_forward = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                             env=lab.env)
            deadline = time.monotonic() + 35
            port = None
            while time.monotonic() < deadline and port_forward.poll() is None:
                text = log_path.read_text(encoding="utf-8", errors="replace")
                found = re.search(r"Forwarding from 127[.]0[.]0[.]1:(\d+) -> 3000", text)
                if found:
                    port = int(found.group(1))
                    break
                time.sleep(0.2)
            require(port is not None, "Owned loopback-only Gitea port-forward did not start")
            base = f"http://127.0.0.1:{port}"
            askpass = temporary / "askpass.sh"
            askpass.write_text("#!/bin/sh\ncase \"$1\" in *sername*) printf '%s\\n' \"$SAF_GIT_USERNAME\" ;; *) printf '%s\\n' \"$SAF_GIT_PASSWORD\" ;; esac\n",
                               encoding="utf-8")
            askpass.chmod(0o700)
            gpg_program = temporary / "gpg-wrapper.sh"
            gpg_wrapper(gpg_program)
            observations = observe(lab, base, temporary, askpass, gpg_home, gpg_program,
                                  flux_checkpoint=flux_checkpoint)
        (lab.evidence / "gitea-branch-observations.json").write_text(
            json.dumps(observations, indent=2) + "\n", encoding="utf-8")
        lab.check("positive", "The private fixture reads back both exact effective branch rules",
                  observations["fixture_repo_private"] and observations["allow_fast_forward_only_merge"],
                  {"gitea_version": observations["gitea_version"],
                   "main_rule": observations["effective_main_rule"],
                   "signature_rule": observations["effective_signature_rule"]})
        claims = (
            ("red", "ordinary_baseline_http_git_write", "Before branch rules, the writer can perform the baseline push"),
            ("positive", "baseline_signature_verified", "The same private repository starts from a Gitea-verified signed baseline"),
            ("green", "unsigned_signature_push_denied_ref_unchanged", "The exact signed-commit rule rejects unsigned Git writes without changing its ref"),
            ("positive", "signed_signature_push_accepted", "The same exact branch accepts a registered signed commit"),
            ("positive", "signed_signature_push_verified", "Gitea reports the accepted signature as verified"),
            ("green", "signed_direct_push_denied", "Protected main rejects even a signed direct push"),
            ("green", "direct_push_main_sha_unchanged", "Denied direct push leaves main at its exact prior SHA"),
            ("green", "status_case", "A prior approval does not bypass the missing required status"),
            ("green", "approval_case", "A prior successful status does not bypass missing approval"),
            ("positive", "promotion", "The fully gated fast-forward preserves the exact signed PR head"),
        )
        for phase, key, claim in claims:
            value = observations[key]
            if isinstance(value, dict):
                # Run-specific commit values are retained in the separate raw receipt.
                value = {name: item for name, item in value.items() if not name.endswith("_sha")}
                matched = all(bool(item) for item in value.values())
            else:
                matched = bool(value)
            lab.check(phase, claim, matched, value)
    finally:
        if port_forward is not None:
            if port_forward.poll() is None:
                port_forward.terminate()
            try:
                port_forward.wait(timeout=10)
            except subprocess.TimeoutExpired:
                port_forward.kill()
                port_forward.wait(timeout=5)
        port_forward_stopped = port_forward is None or port_forward.poll() is not None
        gpg_agent_stopped = True
        if gpg_home.exists():
            killed = safe_run(["gpgconf", "--homedir", str(gpg_home), "--kill", "gpg-agent"], check=False)
            gpg_agent_stopped = killed.returncode == 0
            cleanup_ok = cleanup_ok and gpg_agent_stopped
        try:
            shutil.rmtree(temporary, ignore_errors=False)
        except OSError:
            cleanup_ok = False
        cleanup_ok = cleanup_ok and port_forward_stopped and not temporary.exists()
        lab.check("cleanup", "Owned port-forward and private temporary credentials are removed",
                  cleanup_ok, {"port_forward_stopped": port_forward_stopped,
                               "temporary_directory_removed": not temporary.exists(),
                               "gpg_agent_stopped": gpg_agent_stopped})
