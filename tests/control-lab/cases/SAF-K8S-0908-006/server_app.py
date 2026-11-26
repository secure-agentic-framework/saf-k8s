"""One bounded legacy workflow round using Flower's actual SecAgg+ components."""

import json
import os
from pathlib import Path

import numpy as np

from flwr.common import ndarrays_to_parameters, parameters_to_ndarrays
from flwr.server import LegacyContext, ServerConfig
from flwr.server.strategy import FedAvg
from flwr.server.workflow import DefaultWorkflow, SecAggPlusWorkflow
from flwr.app import Context
from flwr.serverapp import Grid, ServerApp

app = ServerApp()
RESULT_PATH = Path(os.environ.get("SAF_FLOWER_RESULT_PATH", "/flower-results/result.json"))


class AggregateReceiptStrategy(FedAvg):
    """Retain only the unmasked aggregate returned to the Flower strategy."""

    def aggregate_fit(self, server_round, results, failures):
        parameters, metrics = super().aggregate_fit(server_round, results, failures)
        if server_round == 1 and parameters is not None:
            vectors = parameters_to_ndarrays(parameters)
            if len(vectors) != 1 or vectors[0].shape != (2,):
                raise ValueError("Flower aggregate has an unexpected fixture shape")
            report = {
                "workflow": "SecAggPlusWorkflow",
                "round": 1,
                "participant_result_count": len(results),
                "failure_count": len(failures),
                "aggregate": [float(value) for value in vectors[0].tolist()],
            }
            RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
            temporary = RESULT_PATH.with_suffix(".tmp")
            temporary.write_text(json.dumps(report, sort_keys=True) + "\n")
            temporary.replace(RESULT_PATH)
        return parameters, metrics


@app.main()
def main(grid: Grid, context: Context) -> None:
    """Run exactly one fit round and persist only a bounded aggregate receipt."""
    settings = context.run_config
    strategy = AggregateReceiptStrategy(
        fraction_fit=1.0,
        fraction_evaluate=0.0,
        min_fit_clients=3,
        min_evaluate_clients=0,
        min_available_clients=3,
        accept_failures=False,
        initial_parameters=ndarrays_to_parameters([np.zeros(2, dtype=np.float64)]),
    )
    legacy = LegacyContext(
        context=context,
        config=ServerConfig(num_rounds=1, round_timeout=float(settings["timeout"])),
        strategy=strategy,
    )
    workflow = DefaultWorkflow(fit_workflow=SecAggPlusWorkflow(
        num_shares=float(settings["num-shares"]),
        reconstruction_threshold=float(settings["reconstruction-threshold"]),
        max_weight=float(settings["max-weight"]),
        clipping_range=float(settings["clipping-range"]),
        quantization_range=int(settings["quantization-range"]),
        modulus_range=int(settings["modulus-range"]),
        timeout=float(settings["timeout"]),
    ))
    workflow(grid, legacy)
