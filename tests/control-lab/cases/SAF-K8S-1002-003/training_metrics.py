"""Fixed synthetic PyTorch CPU fit with a bounded Prometheus text endpoint."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import math
import threading

import torch

torch.set_num_threads(1)
torch.set_num_interop_threads(1)
if torch.__version__ != "2.15.0+cpu" or torch.cuda.is_available():
    raise RuntimeError("expected the pinned CPU-only PyTorch build")

LOCK = threading.Lock()
STATE = {"receipt": None}
LABELS = 'framework="pytorch",version="2.15.0+cpu",device="cpu",workload="saf-pytorch-training"'


def _train_once():
    with LOCK:
        if STATE["receipt"] is not None:
            raise RuntimeError("the fixed one-shot training request was already consumed")
        model = torch.nn.Linear(1, 1, bias=True, device="cpu", dtype=torch.float64)
        with torch.no_grad():
            model.weight.fill_(0.0)
            model.bias.fill_(0.0)
        inputs = torch.tensor([[-1.0], [0.0], [1.0], [2.0]], dtype=torch.float64, device="cpu")
        targets = 2.0 * inputs + 1.0
        criterion = torch.nn.MSELoss()
        optimizer = torch.optim.SGD(model.parameters(), lr=0.1)
        with torch.no_grad():
            initial_loss = float(criterion(model(inputs), targets).item())
        epoch_losses = []
        for _ in range(3):
            optimizer.zero_grad(set_to_none=True)
            prediction = model(inputs)
            loss = criterion(prediction, targets)
            loss.backward()
            optimizer.step()
            with torch.no_grad():
                epoch_losses.append(float(criterion(model(inputs), targets).item()))
        final_loss = epoch_losses[-1]
        if (not all(math.isfinite(value) for value in [initial_loss, *epoch_losses])
                or not final_loss < initial_loss):
            raise RuntimeError("fixed optimizer steps did not produce finite decreasing loss")
        STATE["receipt"] = {
            "framework": "pytorch", "torch_version": torch.__version__, "device": "cpu",
            "optimizer": "SGD", "optimizer_steps": len(epoch_losses),
            "initial_loss": initial_loss, "epoch_losses": epoch_losses,
            "final_loss": final_loss,
        }
        return STATE["receipt"]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def _send(self, status, content_type, body):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path == "/metrics":
            receipt = STATE["receipt"]
            steps = 0 if receipt is None else receipt["optimizer_steps"]
            loss = 0.0 if receipt is None else receipt["final_loss"]
            body = (
                "# HELP saf_torch_optimizer_steps_total Completed fixed PyTorch optimizer steps.\n"
                "# TYPE saf_torch_optimizer_steps_total counter\n"
                f"saf_torch_optimizer_steps_total{{{LABELS}}} {steps}\n"
                "# HELP saf_torch_training_loss Measured post-step PyTorch mean squared error.\n"
                "# TYPE saf_torch_training_loss gauge\n"
                f"saf_torch_training_loss{{{LABELS}}} {loss:.17g}\n"
            )
            self._send(200, "text/plain; version=0.0.4; charset=utf-8", body)
            return
        if self.path == "/receipt":
            receipt = STATE["receipt"]
            if receipt is None:
                self._send(409, "application/json", '{"state":"not-trained"}')
            else:
                self._send(200, "application/json", json.dumps(receipt, sort_keys=True))
            return
        if self.path == "/healthz":
            self._send(200, "application/json", '{"status":"ok"}')
            return
        self._send(404, "application/json", '{"error":"not-found"}')

    def do_POST(self):
        if self.path != "/train" or self.headers.get("Content-Length") != "0":
            self._send(404, "application/json", '{"error":"not-found"}')
            return
        try:
            receipt = _train_once()
        except RuntimeError:
            self._send(409, "application/json", '{"error":"training-unavailable"}')
            return
        self._send(200, "application/json", json.dumps(receipt, sort_keys=True))


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
