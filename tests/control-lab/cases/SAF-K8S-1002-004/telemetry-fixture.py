"""Synthetic AI workload telemetry for SAF-K8S-1002-004; no GPU access."""

# Metric values are deliberately inert, deterministic fixture data. The GPU XID
# value models a last-observed code gauge, not a count and not hardware output.
HEALTHY = {
    "training_loss": 0.20,
    "model_last_update_seconds": -10,
    "inference_accuracy_ratio": 0.98,
    "inference_latency_p99_seconds": 0.05,
    "training_last_checkpoint_seconds": -10,
    "DCGM_FI_DEV_XID_ERRORS": 0,
}

FAILURES = {
    "divergence": {"training_loss": 0.90},
    "staleness": {"model_last_update_seconds": -1_000},
    "gpu_xid": {"DCGM_FI_DEV_XID_ERRORS": 79},
    "gpu_xid_updated": {"DCGM_FI_DEV_XID_ERRORS": 31},
    "accuracy": {"inference_accuracy_ratio": 0.60},
    "latency": {"inference_latency_p99_seconds": 2.5},
    "training_hang": {"training_last_checkpoint_seconds": -1_000},
}

EXPECTED = {
    "divergence": ("AITrainingDivergence", "security-operations"),
    "staleness": ("AIModelStale", "security-operations"),
    "gpu_xid": ("AIGPULastXIDObserved", "security-operations"),
    "accuracy": ("AIInferenceAccuracyDegraded", "security-operations"),
    "latency": ("AIInferenceLatencyHigh", "ml-operations"),
    "training_hang": ("AITrainingCheckpointStalled", "ml-operations"),
}
