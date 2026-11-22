"""Execute one small, fixed token-accounting batch inside the fixture Pod."""
import json
import sys

from fixture import Backend, GuardedService, Request, UnsafeService


def run(items):
    results = {}
    for name, options in items.items():
        backend = Backend()
        policy = options["policy"]
        service = GuardedService(backend, **policy) if policy else UnsafeService(backend)
        steps = []
        for session, prompt, wanted, tick in options["requests"]:
            outcome = service.generate(Request(session, prompt, wanted), now=tick)
            steps.append({"response": outcome.as_dict(), "backend": backend.state(),
                          "session_output": service.session_output(session) if policy else None})
        results[name] = steps
    return results


if __name__ == "__main__":
    print(json.dumps(run(json.load(sys.stdin)), sort_keys=True))
