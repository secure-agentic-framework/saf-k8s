#!/usr/bin/env python3
"""Local Gitea deploy-key and collaborator permission case; no external targets."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
GITEA_IMAGE = ("docker.gitea.com/gitea:1.23.8-rootless@sha256:"
               "331875f35bdcc3c1110fc8410a4e809e3103ebb091ef424fec2df53ac1b658fc")
SCOPE = (
    "One isolated Gitea 1.23.8 instance on Kubernetes v1.36.1, two fixture private "
    "repositories, a repository deploy key and a separate maintenance collaborator. "
    "Uses normal Git reads and writes and a loopback-only port forward. Production "
    "repository coverage, branch protection and credential custody require separate evidence."
)
OWNER = "fixture-owner"
MAINTAINER = "fixture-maintainer"
SOURCE = "control-source"
RESTRICTED = "restricted-source"
EXPECTED_VERSION = "1.23.8"
SOURCE_MAIN = "refs/heads/main"
RED_REF = "refs/heads/lab-control-off-write"
MAINTENANCE_REF = "refs/heads/lab-maintenance"
READER_REF = "refs/heads/lab-reader-denied"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def raw_write(name: str, payload: bytes) -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    (RAW / name).write_bytes(payload)


def call(argv: list[str], *, env: dict[str, str] | None = None,
        cwd: pathlib.Path | None = None, raw_name: str | None = None,
        check: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False, timeout=40)
    if raw_name:
        credential = (env or {}).get("SAF_GIT_PASSWORD", "").encode()
        for destination, output in (("stdout",result.stdout),("stderr",result.stderr)):
            if credential:
                output = output.replace(credential, b"<fixture-credential>")
            raw_write(f"{raw_name}.{destination}", output)
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {shlex.join(argv)}")
    return result


def api(method: str, path: str, *, token: str | None = None,
        basic: tuple[str, str] | None = None,
        body: dict[str, object] | None = None) -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "token " + token
    if basic is not None:
        encoded = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        headers["Authorization"] = "Basic " + encoded
    payload = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + "/api/v1" + path, data=payload,
                                 headers=headers, method=method)
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=8) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def json_api(method: str, path: str, *, token: str,
             body: dict[str, object] | None = None,
             expected: tuple[int, ...] = (200,)) -> dict[str, object]:
    status, payload = api(method, path, token=token, body=body)
    require(status in expected, f"Gitea API {method} {path} returned HTTP {status}")
    return json.loads(payload) if payload else {}


def create_user(lab, username, password, *, admin=False):
    script = ('IFS= read -r secret; exec gitea admin user create --username "$1" '
              '--password "$secret" --email "$1@example.invalid" --must-change-password=false "$2"')
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "-n", "saf-test", "exec", "-i", "pod/fixture-gitea", "--", "sh", "-c",
               script, "create-user", username, "--admin" if admin else "--admin=false"]
    result = subprocess.run(command, input=password+"\n", capture_output=True, text=True,
                            env=lab.env, timeout=40)
    if result.returncode:
        safe_error = result.stderr.replace(password, "<fixture-credential>")
        lab.block(f"Could not create synthetic account {username}: {safe_error.strip()}")


def new_token(username: str, password: str, name: str, scopes: list[str]) -> str:
    status, payload = api("POST", f"/users/{username}/tokens",
                          basic=(username, password),
                          body={"name": name, "scopes": scopes})
    require(status == 201, f"Could not create ephemeral token for {username} (HTTP {status})")
    token = json.loads(payload).get("sha1")
    require(isinstance(token, str) and bool(token), "Gitea did not return the new token once")
    return token


def git_env(*, askpass: pathlib.Path | None = None, username: str = "",
            password: str = "", ssh_command: str | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "NO_PROXY": "127.0.0.1",
                "GIT_AUTHOR_NAME": "SAF fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "SAF fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_DATE": "2025-01-01T00:00:00Z",
                "GIT_AUTHOR_DATE": "2025-01-01T00:00:00Z"})
    if askpass is not None:
        env.update({"GIT_ASKPASS": str(askpass), "SAF_GIT_USERNAME": username,
                    "SAF_GIT_PASSWORD": password})
    if ssh_command is not None:
        env["GIT_SSH_COMMAND"] = ssh_command
    return env


def write_askpass(path: pathlib.Path) -> None:
    path.write_text("#!/bin/sh\ncase \"$1\" in\n  *sername*) printf '%s\\n' \"$SAF_GIT_USERNAME\" ;;\n  *) printf '%s\\n' \"$SAF_GIT_PASSWORD\" ;;\nesac\n")
    path.chmod(0o700)


def initialize_repo(path: pathlib.Path, file_name: str, content: bytes,
                    remote: str, token: str, askpass: pathlib.Path) -> str:
    path.mkdir(parents=True)
    call(["git", "init", "--template=", "--initial-branch=main"], cwd=path)
    call(["git", "-c", "commit.gpgsign=false", "config", "user.name", "SAF fixture"], cwd=path)
    call(["git", "-c", "commit.gpgsign=false", "config", "user.email", "fixture@example.invalid"], cwd=path)
    (path / file_name).write_bytes(content)
    call(["git", "add", file_name], cwd=path)
    call(["git", "-c", "commit.gpgsign=false", "commit", "-m", "fixture: seed synthetic repository"],
        cwd=path, env=git_env())
    commit = call(["git", "rev-parse", "HEAD"], cwd=path).stdout.decode().strip()
    call(["git", "remote", "add", "origin", remote], cwd=path)
    env = git_env(askpass=askpass, username=OWNER, password=token)
    call(["git", "push", "-u", "origin", "HEAD:refs/heads/main"], cwd=path,
        env=env, raw_name="seed-push-" + path.name)
    return commit


def observe(lab):
    require(shutil.which("git") is not None, "git CLI is required")
    require(shutil.which("ssh-keygen") is not None, "ssh-keygen is required")
    RAW.mkdir(parents=True, exist_ok=True)
    passwords = {name: secrets.token_urlsafe(24) for name in (OWNER, MAINTAINER)}
    with tempfile.TemporaryDirectory(prefix="saf-0606-027-") as scratch_name:
        scratch = pathlib.Path(scratch_name)
        askpass = scratch / "askpass.sh"
        write_askpass(askpass)
        create_user(lab, OWNER, passwords[OWNER], admin=True)
        create_user(lab, MAINTAINER, passwords[MAINTAINER])
        owner_token = new_token(OWNER, passwords[OWNER], "saf-0606-027-owner", ["write:repository", "write:user"])
        maint_token = new_token(MAINTAINER, passwords[MAINTAINER], "saf-0606-027-maint", ["write:repository"])
        version_status, version_report = api("GET", "/version", token=owner_token)
        require(version_status == 200 and json.loads(version_report).get("version") == EXPECTED_VERSION,
                "Authenticated version request did not confirm the pinned Gitea version")

        status, _ = api("POST", "/user/repos", token=owner_token,
                        body={"name": SOURCE, "private": True, "auto_init": False,
                              "default_branch": "main"})
        require(status == 201, f"Could not create private synthetic source repository (HTTP {status})")
        status, _ = api("POST", "/user/repos", token=owner_token,
                        body={"name": RESTRICTED, "private": True, "auto_init": False,
                              "default_branch": "main"})
        require(status == 201, f"Could not create private synthetic restricted repository (HTTP {status})")

        status, _ = api("PUT", f"/repos/{OWNER}/{SOURCE}/collaborators/{MAINTAINER}",
                        token=owner_token, body={"permission": "write"})
        require(status == 204, "Could not grant the synthetic maintenance identity repository write role")
        permission = json_api("GET", f"/repos/{OWNER}/{SOURCE}/collaborators/{MAINTAINER}/permission",
                              token=owner_token)
        require(permission.get("permission") == "write", "Gitea did not report the maintenance role as write")

        source_url = f"{BASE}/{OWNER}/{SOURCE}.git"
        restricted_url = f"{BASE}/{OWNER}/{RESTRICTED}.git"
        source_seed = initialize_repo(scratch / "source-seed", "deployment.yaml",
                                      (FIXTURES / "deployment.yaml").read_bytes(), source_url,
                                      owner_token, askpass)
        restricted_seed = initialize_repo(scratch / "restricted-seed", "restricted.txt",
                                          (FIXTURES / "restricted.txt").read_bytes(), restricted_url,
                                          owner_token, askpass)

        private_key = scratch / "reader_ed25519"
        call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "saf-0606-027-reader",
             "-f", str(private_key)])
        public_key = (scratch / "reader_ed25519.pub").read_text().strip()
        ssh_options = ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                       "-o", "UserKnownHostsFile=" + str(scratch / "known_hosts"),
                       "-o", "IdentitiesOnly=yes", "-i", str(private_key), "-p", str(SSH_PORT)]
        ssh_cmd = shlex.join(ssh_options)
        ssh_url = f"ssh://git@127.0.0.1:{SSH_PORT}/{OWNER}/{SOURCE}.git"
        reader_env = git_env(ssh_command=ssh_cmd)

        # Red probe: the exact repository key is first granted write, and a normal
        # signature-free fixture branch demonstrates that the unconfigured key can write.
        key_status, key_body = api("POST", f"/repos/{OWNER}/{SOURCE}/keys", token=owner_token,
                                   body={"title": "SAF local scope fixture", "key": public_key,
                                         "read_only": False})
        require(key_status == 201, f"Could not add initial synthetic deploy key (HTTP {key_status})")
        deploy_key_id = json.loads(key_body).get("id")
        key_record = json_api("GET", f"/repos/{OWNER}/{SOURCE}/keys/{deploy_key_id}", token=owner_token)
        require(key_record.get("read_only") is False, "Gitea did not persist the explicitly writable control-off key")
        red_clone = scratch / "red-clone"
        call(["git", "clone", "--branch", "main", ssh_url, str(red_clone)], env=reader_env,
            raw_name="control-off-clone")
        (red_clone / "control-off-note.txt").write_text("synthetic write while deploy key is read-write\n")
        call(["git", "add", "control-off-note.txt"], cwd=red_clone)
        call(["git", "-c", "commit.gpgsign=false", "commit", "-m", "fixture: control off write"],
            cwd=red_clone, env=git_env())
        red_commit = call(["git", "rev-parse", "HEAD"], cwd=red_clone).stdout.decode().strip()
        call(["git", "push", "origin", "HEAD:" + RED_REF], cwd=red_clone, env=reader_env,
            raw_name="control-off-write")
        red_refs = call(["git", "ls-remote", ssh_url, RED_REF], env=reader_env,
                       raw_name="control-off-ref-verify").stdout.decode().splitlines()
        require(len(red_refs) == 1 and red_refs[0] == red_commit + "\t" + RED_REF,
                "Control-off deploy key did not create the exact expected fixture ref")

        deleted_status, _ = api("DELETE", f"/repos/{OWNER}/{SOURCE}/keys/{deploy_key_id}", token=owner_token)
        require(deleted_status == 204, "Could not remove the temporary writable deploy-key grant")
        key_status, key_body = api("POST", f"/repos/{OWNER}/{SOURCE}/keys", token=owner_token,
                                   body={"title": "SAF local read-only fixture", "key": public_key,
                                         "read_only": True})
        require(key_status == 201, f"Could not add repository-scoped read-only deploy key (HTTP {key_status})")
        deploy_key_id = json.loads(key_body).get("id")
        key_record = json_api("GET", f"/repos/{OWNER}/{SOURCE}/keys/{deploy_key_id}", token=owner_token)
        require(key_record.get("read_only") is True, "Gitea did not persist read_only=true for the deploy key")

        refs = call(["git", "ls-remote", ssh_url, SOURCE_MAIN], env=reader_env,
                   raw_name="reader-known-ref").stdout.decode().splitlines()
        require(len(refs) == 1 and refs[0].endswith("\t" + SOURCE_MAIN),
                "Read-only deploy key did not read the expected main ref")
        expected_file_sha256 = hashlib.sha256((FIXTURES / "deployment.yaml").read_bytes()).hexdigest()
        reader_clone = scratch / "reader-clone"
        call(["git", "clone", "--branch", "main", ssh_url, str(reader_clone)], env=reader_env,
            raw_name="reader-clone").returncode
        actual_commit = call(["git", "rev-parse", "refs/remotes/origin/main"], cwd=reader_clone).stdout.decode().strip()
        actual_file_sha256 = hashlib.sha256((reader_clone / "deployment.yaml").read_bytes()).hexdigest()
        require(actual_commit == source_seed, "Clone did not resolve to the seeded known commit")
        require(actual_file_sha256 == expected_file_sha256, "Read bytes do not match the deterministic fixture")

        (reader_clone / "unauthorized-fixture.txt").write_text("signature-free read-only write probe\n")
        call(["git", "add", "unauthorized-fixture.txt"], cwd=reader_clone)
        call(["git", "-c", "commit.gpgsign=false", "commit", "-m", "fixture: read-only write probe"],
            cwd=reader_clone, env=git_env())
        denied = call(["git", "push", "origin", "HEAD:" + READER_REF], cwd=reader_clone,
                     env=reader_env, raw_name="reader-write-denied", check=False)
        denied_text = (denied.stdout + denied.stderr).decode(errors="replace").lower()
        require(denied.returncode != 0 and "gitea: deploy key:" in denied_text and
                f"not authorized to write to {OWNER}/{SOURCE}" in denied_text,
                "Read-only push did not return the exact Gitea authorization denial")
        refs_after_denial = call(["git", "ls-remote", ssh_url, READER_REF], env=reader_env,
                                raw_name="reader-denied-ref-check", check=False)
        require(refs_after_denial.returncode == 0 and not refs_after_denial.stdout.strip(),
                "Denied write ref unexpectedly exists or ref check failed")

        restricted_repo = json_api("GET", f"/repos/{OWNER}/{RESTRICTED}", token=owner_token)
        require(restricted_repo.get("private") is True, "Separate denial target is not confirmed private")
        denied_scope = call(["git", "ls-remote", f"ssh://git@127.0.0.1:{SSH_PORT}/{OWNER}/{RESTRICTED}.git"],
                           env=reader_env, raw_name="reader-cross-repo-denied", check=False)
        cross_text = (denied_scope.stdout + denied_scope.stderr).decode(errors="replace").lower()
        require(denied_scope.returncode != 0 and
                "gitea:" in cross_text and not denied_scope.stdout.strip() and
                any(word in cross_text for word in ("permission denied", "not authorized", "repository does not exist")),
                "Repository-scoped deploy key did not receive an authorization failure on the second private repo")

        maint_clone = scratch / "maint-clone"
        maint_env = git_env(askpass=askpass, username=MAINTAINER, password=maint_token)
        call(["git", "clone", source_url, str(maint_clone)], env=maint_env, raw_name="maintainer-clone")
        (maint_clone / "maintenance-note.txt").write_text("inert authorized maintenance fixture\n")
        call(["git", "add", "maintenance-note.txt"], cwd=maint_clone)
        call(["git", "-c", "commit.gpgsign=false", "commit", "-m", "fixture: inert maintenance update"],
            cwd=maint_clone, env=git_env())
        maint_commit = call(["git", "rev-parse", "HEAD"], cwd=maint_clone).stdout.decode().strip()
        call(["git", "push", "origin", "HEAD:" + MAINTENANCE_REF], cwd=maint_clone,
            env=maint_env, raw_name="maintainer-write")
        remote_refs = call(["git", "ls-remote", source_url, MAINTENANCE_REF], env=maint_env,
                          raw_name="maintainer-ref-verify").stdout.decode().splitlines()
        require(len(remote_refs) == 1 and remote_refs[0] == maint_commit + "\t" + MAINTENANCE_REF,
                "Maintenance branch did not resolve to the exact inert commit")

        return {
            "read_write_deploy_key_control_off": {
                "result": "PASS", "ref": RED_REF, "observed_remote_ref": "present",
                "commit": red_commit, "commit_signature": "disabled"},
            "read_only_deploy_key_read_known_ref": {
                "result": "PASS", "ref": SOURCE_MAIN, "commit": source_seed,
                "fixture_path": "deployment.yaml", "fixture_sha256": expected_file_sha256},
            "read_only_deploy_key_write_denied": {
                "result": "PASS", "ref": READER_REF, "observed_remote_ref": "absent",
                "commit_signature": "disabled"},
            "deploy_key_denied_on_separate_private_repo": {
                "result": "PASS", "repository": RESTRICTED, "repository_private": True,
                "deploy_key_present": False},
            "maintenance_collaborator_write": {
                "result": "PASS", "permission": "write", "ref": MAINTENANCE_REF,
                "commit": maint_commit,
                "fixture_sha256": hashlib.sha256((maint_clone / "maintenance-note.txt").read_bytes()).hexdigest(),
                "commit_signature": "disabled"}
        }


def setup_server(lab):
    settings = {
        "GITEA__database__DB_TYPE": "sqlite3",
        "GITEA__database__PATH": "/var/lib/gitea/data/gitea.db",
        "GITEA__security__INSTALL_LOCK": "true",
        "GITEA__service__DISABLE_REGISTRATION": "true",
        "GITEA__service__REQUIRE_SIGNIN_VIEW": "true",
        "GITEA__server__DOMAIN": "127.0.0.1",
        "GITEA__server__ROOT_URL": "http://127.0.0.1:3000/",
        "GITEA__server__SSH_DOMAIN": "127.0.0.1",
        "GITEA__server__SSH_USER": "git",
        "GITEA__server__SSH_LISTEN_PORT": "2222",
        "GITEA__server__SSH_PORT": "2222",
        "GITEA__server__START_SSH_SERVER": "true",
        "GITEA__repository__DEFAULT_BRANCH": "main",
    }
    lab.create({
        "apiVersion":"v1","kind":"Pod","metadata":{"name":"fixture-gitea"},
        "spec":{
            "automountServiceAccountToken":False,
            "securityContext":{"runAsNonRoot":True,"runAsUser":1000,"runAsGroup":1000,
                               "fsGroup":1000,"seccompProfile":{"type":"RuntimeDefault"}},
            "containers":[{
                "name":"gitea","image":GITEA_IMAGE,"imagePullPolicy":"IfNotPresent",
                "env":[{"name":name,"value":value} for name,value in settings.items()],
                "securityContext":{"allowPrivilegeEscalation":False,"capabilities":{"drop":["ALL"]}},
                "ports":[{"containerPort":3000},{"containerPort":2222}],
                "readinessProbe":{"tcpSocket":{"port":3000},
                                  "periodSeconds":2,"failureThreshold":20},
                "volumeMounts":[{"name":"data","mountPath":"/var/lib/gitea"},
                                {"name":"config","mountPath":"/etc/gitea"}],
            }],
            "volumes":[{"name":"data","emptyDir":{}},{"name":"config","emptyDir":{}}],
        },
    })
    wait = lab.kubectl("wait","--for=condition=Ready","pod/fixture-gitea","--timeout=110s",
                       timeout=120,allow_failure=True)
    if wait.returncode:
        lab.kubectl("describe","pod/fixture-gitea",allow_failure=True)
        lab.kubectl("logs","pod/fixture-gitea","--tail=50",allow_failure=True)
        lab.block("Fixture Gitea Pod did not become ready")


def run(lab):
    global BASE, SSH_PORT, RAW
    RAW = lab.evidence / "raw"
    RAW.mkdir()
    setup_server(lab)
    log = lab.evidence / "port-forward.log"
    command = ["kubectl","--kubeconfig",str(lab.kubeconfig),"--context",f"kind-{lab.cluster}",
               "-n","saf-test","port-forward","--address","127.0.0.1","pod/fixture-gitea",":3000",":2222"]
    with log.open("w") as output:
        forward = subprocess.Popen(command,stdout=output,stderr=subprocess.STDOUT,env=lab.env)
        try:
            deadline = time.monotonic()+35
            while time.monotonic()<deadline and forward.poll() is None:
                advertised = {target:int(port) for port,target in re.findall(
                    r"Forwarding from 127[.]0[.]0[.]1:(\d+) -> (3000|2222)",log.read_text())}
                if set(advertised)=={"3000","2222"}:
                    break
                time.sleep(0.2)
            else:
                lab.block("Fixture port forward did not expose both loopback endpoints")
            BASE = f"http://127.0.0.1:{advertised['3000']}"
            SSH_PORT = advertised["2222"]
            observations = observe(lab)
        finally:
            if forward.poll() is None:
                forward.terminate()
                forward.wait(timeout=10)

    for phase, key, claim in (
        ("red","read_write_deploy_key_control_off","The same fixture key can create its branch when given write permission"),
        ("green","read_only_deploy_key_write_denied","Changing that fixture key to read-only prevents the next branch creation"),
        ("positive","read_only_deploy_key_read_known_ref","The read-only key still retrieves the exact committed fixture"),
        ("green","deploy_key_denied_on_separate_private_repo","The key cannot read the separate owned private fixture repository"),
        ("positive","maintenance_collaborator_write","The approved maintenance collaborator updates the exact owned branch"),
    ):
        item = observations[key]
        lab.check(phase,claim,item["result"]=="PASS",item)
