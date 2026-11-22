"""Deterministic, local-only queue and input-size model for inert bytes."""
from collections import deque
from dataclasses import dataclass
from typing import Optional


MAX_PENDING = 2
MAX_INPUT_BYTES = 16
RETRY_AFTER_SECONDS = 1


@dataclass(frozen=True)
class Decision:
    accepted: bool
    reason: str
    retry_after_seconds: Optional[int] = None


class BoundedWorker:
    """A single-threaded model; it starts no process and performs no I/O."""

    def __init__(self, max_pending=MAX_PENDING, max_input_bytes=MAX_INPUT_BYTES):
        if max_pending < 1 or max_input_bytes < 0:
            raise ValueError("limits must be non-negative, with at least one queue slot")
        self.max_pending = max_pending
        self.max_input_bytes = max_input_bytes
        self._pending = deque()

    @property
    def pending_ids(self):
        return tuple(job_id for job_id, _ in self._pending)

    def submit(self, job_id, payload):
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if len(payload) > self.max_input_bytes:
            return Decision(False, "input-too-large")
        if len(self._pending) >= self.max_pending:
            return Decision(False, "queue-full", RETRY_AFTER_SECONDS)
        if any(queued_id == job_id for queued_id, _ in self._pending):
            return Decision(False, "duplicate-job-id")
        self._pending.append((job_id, bytes(payload)))
        return Decision(True, "accepted")

    def complete_next(self):
        """Remove the oldest accepted item; None means there is no work."""
        return self._pending.popleft() if self._pending else None
