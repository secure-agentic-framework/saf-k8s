"""Read one exact Tetragon event through Kubernetes and deliver it over mTLS."""
import hashlib
import json
import os
import re
from pathlib import Path
import socket
import ssl
import sys
import time
import urllib.error
from urllib.parse import quote
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
API_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
AGENT_NAMESPACE = os.environ["AGENT_NAMESPACE"]
AGENT_POD = os.environ["AGENT_POD"]
OTHER_AGENT_POD = os.environ["OTHER_AGENT_POD"]
FIXTURE_NAMESPACE = os.environ["FIXTURE_NAMESPACE"]
FIXTURE_POD = os.environ["FIXTURE_POD"]
POLICY = os.environ["FIXTURE_POLICY"]
MARKER = os.environ["FIXTURE_PATH"]
RECEIVER = os.environ["RECEIVER_URL"]
EXPECTED_DIGEST = os.environ["EXPECTED_EVENT_DIGEST"]
TLS_CERT = "/tls/tls.crt"
TLS_KEY = "/tls/tls.key"
CA_CERT = "/tls/ca.crt"


def api_log():
    token = TOKEN.read_text(encoding="utf-8").strip()
    path = (f"/api/v1/namespaces/{quote(AGENT_NAMESPACE, safe='')}/pods/"
            f"{quote(AGENT_POD, safe='')}/log?container=export-stdout&tailLines=100")
    request = Request("https://kubernetes.default.svc" + path,
                      headers={"Authorization": "Bearer " + token}, method="GET")
    context = ssl.create_default_context(cafile=API_CA)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=8) as response:
            raw = response.read(262145)
            if response.status != 200 or len(raw) > 262144:
                raise RuntimeError("bounded source log read failed")
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"source-log-http-{error.code}") from None
    except urllib.error.URLError as error:
        reason = error.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            raise RuntimeError(f"source-log-tls-{reason.verify_code}") from None
        raise RuntimeError("bounded source log read failed") from None
    return raw.decode("utf-8", errors="strict").splitlines()


def other_pod_logs_denied():
    token = TOKEN.read_text(encoding="utf-8").strip()
    other = quote(OTHER_AGENT_POD, safe="")
    ns = quote(AGENT_NAMESPACE, safe="")
    request = Request(
        f"https://kubernetes.default.svc/api/v1/namespaces/{ns}/pods/{other}/log?container=export-stdout",
        headers={"Authorization": "Bearer " + token}, method="GET")
    context = ssl.create_default_context(cafile=API_CA)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=4):
            return False
    except urllib.error.HTTPError as error:
        return error.code == 403
    except Exception:
        return False


def pod_identity(record):
    return record.get("process", {}).get("pod", {})


def matching_event(lines):
    executions = {}
    selected = []
    for line in lines:
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        if "process_exec" in row:
            record = row["process_exec"]
            process = record.get("process", {})
            if (pod_identity(record).get("namespace") == FIXTURE_NAMESPACE
                    and pod_identity(record).get("name") == FIXTURE_POD
                    and process.get("arguments") == f"cat {MARKER}"):
                executions[process.get("exec_id")] = record
        if "process_kprobe" not in row:
            continue
        record = row["process_kprobe"]
        process = record.get("process", {})
        pod = pod_identity(record)
        args = record.get("args", [])
        path_match = any(isinstance(arg, dict)
                         and arg.get("file_arg", {}).get("path") == MARKER
                         for arg in args)
        exec_id = process.get("exec_id")
        if (record.get("function_name") == "security_file_permission"
                and record.get("policy_name") == POLICY
                and pod.get("namespace") == FIXTURE_NAMESPACE
                and pod.get("name") == FIXTURE_POD
                and exec_id in executions and path_match):
            exact_event = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            if hashlib.sha256(exact_event).hexdigest() == EXPECTED_DIGEST:
                selection = (record, executions[exec_id])
                if selection not in selected:
                    selected.append(selection)
    if len(selected) != 1:
        raise RuntimeError("source did not contain exactly one selected event")
    return selected[0]


def no_client_refusal():
    context = ssl.create_default_context(cafile=CA_CERT)
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    from urllib.parse import urlparse
    parsed = urlparse(RECEIVER)
    for attempt in range(8):
        try:
            sock = socket.create_connection((parsed.hostname, parsed.port), timeout=4)
            break
        except ConnectionRefusedError:
            if attempt == 7:
                raise RuntimeError("receiver route unavailable") from None
            time.sleep(0.4)
    try:
        try:
            secure = context.wrap_socket(sock, server_hostname=parsed.hostname)
        except ssl.SSLError as error:
            return error.reason in {"SSLV3_ALERT_HANDSHAKE_FAILURE", "TLSV1_ALERT_HANDSHAKE_FAILURE",
                                    "TLSV13_ALERT_CERTIFICATE_REQUIRED"}
        secure.close()
        return False
    finally:
        sock.close()


def send(record, process_exec):
    context = ssl.create_default_context(cafile=CA_CERT)
    context.load_cert_chain(TLS_CERT, TLS_KEY)
    payload = json.dumps({"event_type": "process_kprobe", "event": record,
                          "process_exec": process_exec}, sort_keys=True,
                         separators=(",", ":")).encode()
    request = Request(RECEIVER + "/events", data=payload,
                     headers={"Content-Type": "application/json"}, method="POST")
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=6) as response:
            body = json.loads(response.read(4096))
            if response.status != 201 or body.get("accepted") is not True:
                raise RuntimeError("receiver did not accept event")
    except Exception:
        raise RuntimeError("authenticated event delivery failed") from None


def main():
    other_source_denied = other_pod_logs_denied()
    if not other_source_denied:
        raise RuntimeError("exporter log access was not limited to its named source")
    denied_without_certificate = no_client_refusal()
    if not denied_without_certificate:
        raise RuntimeError("receiver accepted unauthenticated TLS client")
    selected, execution = matching_event(api_log())
    send(selected, execution)
    event_bytes = json.dumps(selected, sort_keys=True, separators=(",", ":")).encode()
    print(json.dumps({"source_read": True, "other_source_denied": other_source_denied,
                      "event_sha256": hashlib.sha256(event_bytes).hexdigest(),
                      "exactly_one_event": True,
                      "client_certificate_required": denied_without_certificate,
                      "server_name_verified": True,
                      "authenticated_delivery": True}, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        reasons = {"exporter log access was not limited to its named source",
                   "receiver accepted unauthenticated TLS client", "receiver route unavailable",
                   "bounded source log read failed", "source did not contain exactly one selected event",
                   "authenticated event delivery failed"}
        reason = str(error)
        known = reason in reasons or re.fullmatch(r"source-log-(http|tls)-[0-9]{1,3}", reason)
        print(json.dumps({"delivery": "failed", "reason": reason if known else "fixture-gate"}), flush=True)
        sys.exit(1)
    except Exception:
        print('{"delivery":"failed","reason":"fixture-gate"}', flush=True)
        sys.exit(1)
