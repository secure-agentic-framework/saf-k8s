"""One bounded enrolled PyTorch Gloo rank; prints only fixed, non-secret fields."""
import json
import os
from pathlib import Path
import ssl
import sys
import time
from datetime import timedelta
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, HTTPSHandler, build_opener, urlopen


WORKER_ID = os.environ["FIXTURE_WORKER_ID"]
RANK_BY_WORKER = {"worker-a": 0, "worker-b": 1}
REQUEST_KEY_BY_WORKER = {"worker-a": "worker_a_valid", "worker-b": "worker_b_valid"}
REQUESTS = Path(__file__).with_name("requests.json")
TOKEN_PATH = Path("/run/fixture-identity/token")
API_TOKEN_PATH = Path("/run/fixture-identity/api-token")
API_CA_PATH = Path("/run/fixture-identity/ca.crt")
NAMESPACE = "saf-0901-002"
GATE = "gloo-collective-start-gate"


def post(url, body, token):
    request = Request(url, data=json.dumps(body, separators=(",", ":")).encode(),
                      headers={"Authorization": "Bearer " + token,
                               "Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=4) as response:
            return response.status, json.loads(response.read(4096))
    except HTTPError as error:
        return error.code, json.loads(error.read(4096))


def wait_enrollment_health(base):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            with urlopen(base + "/healthz", timeout=1) as response:
                if response.status == 200 and json.loads(response.read(1024)) == {
                        "fixture": "0901-002", "ok": True}:
                    return
        except (URLError, OSError, ValueError):
            pass
        time.sleep(0.25)
    raise RuntimeError("enrollment endpoint did not become ready")


def wait_collective_gate():
    token = API_TOKEN_PATH.read_text(encoding="utf-8").strip()
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]
    url = (f"https://{host}:{port}/api/v1/namespaces/{NAMESPACE}/configmaps/{GATE}")
    tls = ssl.create_default_context(cafile=str(API_CA_PATH))
    client = build_opener(ProxyHandler({}), HTTPSHandler(context=tls))
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        request = Request(url, headers={"Authorization": "Bearer " + token,
                                        "Accept": "application/json"})
        try:
            with client.open(request, timeout=5) as response:
                gate = json.loads(response.read(4096))
        except (HTTPError, URLError, OSError, TimeoutError, ValueError):
            raise RuntimeError("collective start gate read failed")
        if gate.get("data", {}).get("start") == "go":
            return
        time.sleep(0.2)
    raise RuntimeError("collective start gate expired")


def main():
    stage = "runtime"
    try:
        import torch
        import torch.distributed as dist

        if torch.__version__ != "2.15.0+cpu" or not dist.is_gloo_available():
            raise RuntimeError("unexpected pinned runtime")
        token = TOKEN_PATH.read_text(encoding="utf-8")
        request_map = json.loads(REQUESTS.read_text(encoding="utf-8"))
        request_body = request_map[REQUEST_KEY_BY_WORKER[WORKER_ID]]
        base = os.environ["ENROLLMENT_URL"]
        wait_enrollment_health(base)
        stage = "authenticated-contribution"
        contribution_status, contribution = post(
            base + "/v1/contribute", request_body, token)
        if contribution_status != 200 or contribution != {"status": "accepted"}:
            raise RuntimeError("fixed contribution was not accepted")

        stage = "authenticated-enrollment"
        status, enrollment = post(
            base + "/v1/enroll",
            {"round_id": "round-7"}, token)
        expected_rank = RANK_BY_WORKER[WORKER_ID]
        if (status != 200 or enrollment != {"status": "enrolled",
                                            "worker_id": WORKER_ID,
                                            "round_id": "round-7",
                                            "rank": expected_rank}):
            raise RuntimeError("worker was not assigned the expected fixture rank")

        # Hold both ranks at an authenticated Kubernetes API read gate while
        # the host installs exact Pod-IP-pair counters on their WireGuard nodes.
        print("SAF_GLOO_READY " + json.dumps({"worker_id": WORKER_ID,
              "rank": expected_rank, "enrolled": True}, sort_keys=True), flush=True)
        wait_collective_gate()

        stage = "collective"
        vector = request_body["vector"]
        tensor = torch.tensor(vector, dtype=torch.float64, device="cpu")
        dist.init_process_group(
            backend="gloo", init_method=os.environ["RANK_ZERO_URL"],
            rank=expected_rank, world_size=2, timeout=timedelta(seconds=30))
        dist.all_reduce(tensor, op=dist.ReduceOp.SUM)
        result = [round(float(value), 8) for value in tensor.tolist()]
        dist.destroy_process_group()
        print("SAF_GLOO_RESULT " + json.dumps({
            "worker_id": WORKER_ID,
            "rank": expected_rank,
            "round_id": "round-7",
            "accepted_http_status": contribution_status,
            "accepted_response": contribution,
            "torch_version": torch.__version__,
            "gloo_available": dist.is_gloo_available(),
            "backend": "gloo",
            "device": str(tensor.device),
            "world_size": 2,
            "input": vector,
            "operation": "sum",
            "result": result,
        }, sort_keys=True, separators=(",", ":")), flush=True)
    except Exception as error:
        # Never print exception text, request headers, tokens, or process state.
        print(json.dumps({"ok": False, "worker_id": WORKER_ID,
                          "stage": stage, "exception_type": type(error).__name__},
                         sort_keys=True, separators=(",", ":")), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
