"""Run the inert queue and input model inside a nonroot fixture Job."""
import json

from bounds import BoundedWorker


worker = BoundedWorker()
first = worker.submit("first", b"a" * 16)
oversized = worker.submit("invalid", b"b" * 17)
oversize_effect = worker.pending_ids == ("first",)
second = worker.submit("second", b"b")
full = worker.submit("retry", b"c")
oldest = worker.complete_next()
retry = worker.submit("retry", b"c")
print(json.dumps({
    "queue_full_rejected": first.accepted and second.accepted and not full.accepted and full.reason == "queue-full",
    "oversize_rejected_without_enqueue": not oversized.accepted and oversized.reason == "input-too-large" and oversize_effect,
    "retry_after_seconds": full.retry_after_seconds,
    "retry_after_completion_accepted": oldest == ("first", b"a" * 16) and retry.accepted
    and worker.pending_ids == ("second", "retry"),
}))
