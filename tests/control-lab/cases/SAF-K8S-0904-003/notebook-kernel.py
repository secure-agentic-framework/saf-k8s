"""Run a fixed harmless cell through the installed Jupyter kernel protocol."""
import json
import os
from pathlib import Path
import tempfile
import time

from jupyter_client import KernelManager


def run():
    with tempfile.TemporaryDirectory(dir="/tmp") as runtime:
        manager = KernelManager(kernel_name="python3", ip="127.0.0.1",
                                connection_file=str(Path(runtime) / "connection.json"))
        manager.start_kernel(cwd=runtime, env={**os.environ, "JUPYTER_RUNTIME_DIR": runtime,
                                               "IPYTHONDIR": runtime})
        client = manager.client()
        try:
            client.start_channels()
            client.wait_for_ready(timeout=20)
            message = client.execute("print('fixture-notebook-ok')", allow_stdin=False)
            output = []
            until = time.monotonic() + 20
            while time.monotonic() < until:
                observed = client.get_iopub_msg(timeout=max(0.1, until - time.monotonic()))
                if observed.get("parent_header", {}).get("msg_id") != message:
                    continue
                kind = observed["header"]["msg_type"]
                if kind == "error":
                    raise RuntimeError("The harmless fixture cell failed")
                if kind == "stream" and observed["content"].get("name") == "stdout":
                    output.append(observed["content"]["text"])
                if kind == "status" and observed["content"].get("execution_state") == "idle":
                    break
            else:
                raise RuntimeError("The fixture cell did not finish")
            return {"uid": os.getuid(), "stdout": "".join(output), "kernel": manager.kernel_name}
        finally:
            client.stop_channels()
            manager.shutdown_kernel(now=True)


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
