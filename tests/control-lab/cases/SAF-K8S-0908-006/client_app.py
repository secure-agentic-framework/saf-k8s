"""Three harmless vectors through Flower's legacy fit API and SecAgg+ mod."""

import numpy as np

from flwr.app import Context
from flwr.client import NumPyClient
from flwr.client.mod import secaggplus_mod
from flwr.clientapp import ClientApp


FIXED_VECTORS = {
    0: np.asarray([1.25, -2.5], dtype=np.float64),
    1: np.asarray([3.75, 4.0], dtype=np.float64),
    2: np.asarray([5.5, 2.25], dtype=np.float64),
}


class FixedVectorClient(NumPyClient):
    def __init__(self, participant):
        self.participant = participant

    def fit(self, parameters, config):
        return [FIXED_VECTORS[self.participant].copy()], 1, {}


def client_fn(context: Context):
    participant = int(context.node_config["partition-id"])
    if participant not in FIXED_VECTORS:
        raise ValueError("Fixture participant ID is outside the three-member cohort")
    return FixedVectorClient(participant).to_client()


app = ClientApp(client_fn=client_fn, mods=[secaggplus_mod])
