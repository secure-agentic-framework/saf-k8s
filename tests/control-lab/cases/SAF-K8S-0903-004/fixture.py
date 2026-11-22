"""Deterministic, in-process stand-in for a text generation serving boundary."""
from dataclasses import dataclass
import re


class FixtureError(RuntimeError):
    """Fixture invariant or invalid deterministic input."""


def count_tokens(text):
    """Count non-whitespace runs; intentionally not a production tokenizer."""
    if not isinstance(text, str):
        raise FixtureError("prompt must be text")
    return len(re.findall(r"\S+", text))


@dataclass(frozen=True)
class Request:
    session_id: str
    prompt: str
    requested_output_tokens: int


@dataclass(frozen=True)
class Result:
    accepted: bool
    reason: str
    input_tokens: int
    output_tokens: int
    text: str

    def as_dict(self):
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "text": self.text,
        }


class Backend:
    """Deterministic fake model; counters represent work admitted to backend."""

    def __init__(self):
        self.prompt_tokens = 0
        self.generated_tokens = 0
        self.requests = 0

    def begin(self, prompt_tokens):
        self.requests += 1
        self.prompt_tokens += prompt_tokens

    def next_token(self):
        self.generated_tokens += 1
        return "tok"

    def state(self):
        return {
            "requests": self.requests,
            "prompt_tokens": self.prompt_tokens,
            "generated_tokens": self.generated_tokens,
        }


class UnsafeService:
    """Red fixture with no serving-side token policy."""

    def __init__(self, backend):
        self.backend = backend

    def generate(self, request, now):
        del now
        tokens = count_tokens(request.prompt)
        self.backend.begin(tokens)
        if request.requested_output_tokens < 0:
            raise FixtureError("requested output token count must be non-negative")
        generated = [self.backend.next_token() for _ in range(request.requested_output_tokens)]
        return Result(True, "unguarded", tokens, len(generated), " ".join(generated))


class GuardedService:
    """Serving-side limits over a deterministic tokenizer and token backend."""

    def __init__(self, backend, *, max_input_tokens, max_request_output_tokens,
                 max_session_output_tokens, token_rate, burst):
        values = (max_input_tokens, max_request_output_tokens, max_session_output_tokens,
                  token_rate, burst)
        if any(not isinstance(value, int) or value < 0 for value in values):
            raise FixtureError("limits must be non-negative integers")
        if max_input_tokens < 1 or max_request_output_tokens < 1 or token_rate < 1 or burst < 1:
            raise FixtureError("input, request, and rate limits must be positive")
        self.backend = backend
        self.max_input_tokens = max_input_tokens
        self.max_request_output_tokens = max_request_output_tokens
        self.max_session_output_tokens = max_session_output_tokens
        self.token_rate = token_rate
        self.burst = burst
        self._session_output = {}
        self._bucket = {}

    def session_output(self, session_id):
        return self._session_output.get(session_id, 0)

    def _consume_rate_token(self, session_id, now):
        if not isinstance(now, int) or now < 0:
            raise FixtureError("logical time must be a non-negative integer")
        tokens, last = self._bucket.get(session_id, (self.burst, now))
        if now < last:
            raise FixtureError("logical time must be monotonic per session")
        tokens = min(self.burst, tokens + (now - last) * self.token_rate)
        if tokens < 1:
            self._bucket[session_id] = (tokens, now)
            return False
        self._bucket[session_id] = (tokens - 1, now)
        return True

    def generate(self, request, now):
        if not isinstance(request, Request) or not request.session_id:
            raise FixtureError("request must have a non-empty session ID")
        if not isinstance(request.requested_output_tokens, int) or request.requested_output_tokens < 0:
            raise FixtureError("requested output token count must be a non-negative integer")
        input_tokens = count_tokens(request.prompt)
        if input_tokens > self.max_input_tokens:
            return Result(False, "input_limit", input_tokens, 0, "")

        remaining_session = self.max_session_output_tokens - self.session_output(request.session_id)
        request_allowance = min(request.requested_output_tokens, self.max_request_output_tokens)
        allowance = min(request_allowance, max(0, remaining_session))
        reason_at_cap = (
            "session_budget" if remaining_session <= request_allowance
            and remaining_session <= self.max_request_output_tokens else "request_budget"
        )
        if allowance == 0 and remaining_session == 0:
            return Result(True, "session_budget", input_tokens, 0, "")

        # The request is admitted to backend only after complete input validation.
        self.backend.begin(input_tokens)
        output = []
        stop_reason = "complete"
        for _ in range(allowance):
            if not self._consume_rate_token(request.session_id, now):
                stop_reason = "token_rate"
                break
            output.append(self.backend.next_token())
            self._session_output[request.session_id] = self.session_output(request.session_id) + 1
        else:
            if allowance < request.requested_output_tokens:
                stop_reason = reason_at_cap
        return Result(True, stop_reason, input_tokens, len(output), " ".join(output))
