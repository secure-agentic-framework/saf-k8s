"""Isolated synthetic predictor and one-decimal response transformation."""
import json
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import ProxyHandler, Request, build_opener
from urllib.error import HTTPError

# Invented feature vectors and fixed model outputs; no training records exist.
FIXED = (
    {"features": [1, 0], "label": "class-a",
     "scores": {"class-a": 0.812345, "class-b": 0.133333, "class-c": 0.054322}},
    {"features": [0, 1], "label": "class-b",
     "scores": {"class-a": 0.071234, "class-b": 0.833333, "class-c": 0.095433}},
)
UTILITY_BOUND = Decimal("0.05")


def response_for(request_data, shaped):
    if not isinstance(request_data, dict):
        raise ValueError("expected fixed feature object")
    features = request_data.get("features")
    row = next((item for item in FIXED if item["features"] == features), None)
    if row is None:
        raise ValueError("input is outside the fixed benign fixture")
    if not shaped:
        return {"label": row["label"], "scores": row["scores"]}
    # Allocate ten integer steps by largest remainder, so coarsening preserves normalization.
    scaled = {key: Decimal(str(value)) * 10 for key, value in row["scores"].items()}
    units = {key: int(value) for key, value in scaled.items()}
    remainder = 10 - sum(units.values())
    for key in sorted(units, key=lambda name: (-(scaled[name] - units[name]), name))[:remainder]:
        units[key] += 1
    return {"label": row["label"], "probabilities": {key: value / 10 for key, value in units.items()}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        # Never write requests or response values to routine logs.
        return

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/predict":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > 256:
                raise ValueError("invalid fixture request size")
            payload = json.loads(self.rfile.read(size))
            output = response_for(payload, self.server.shaped)
            body = json.dumps(output, separators=(",", ":")).encode()
        except (ValueError, TypeError, json.JSONDecodeError):
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def post(base, path, payload):
    body = json.dumps(payload, separators=(",", ":")).encode()
    request = Request(base + path, body, {"Content-Type": "application/json"})
    with build_opener(ProxyHandler({})).open(request, timeout=3) as reply:
        return json.loads(reply.read().decode())


def decimals(value):
    exponent = Decimal(str(value)).normalize().as_tuple().exponent
    return max(0, -exponent)


def evaluate(baseline, protected):
    raw = [post(baseline, "/predict", {"features": row["features"]}) for row in FIXED]
    shaped = [post(protected, "/predict", {"features": row["features"]}) for row in FIXED]
    retired_raw_route = False
    try:
        post(protected, "/raw", {"features": FIXED[0]["features"]})
    except HTTPError as error:
        retired_raw_route = error.code == 404

    raw_schema = all(set(item) == {"label", "scores"} for item in raw)
    raw_precision = all(
        set(item["scores"]) == {"class-a", "class-b", "class-c"}
        and all(decimals(value) == 6 for value in item["scores"].values())
        for item in raw
    )
    green_schema = all(
        set(item) == {"label", "probabilities"}
        and set(item["probabilities"]) == {"class-a", "class-b", "class-c"}
        for item in shaped
    )
    green_precision = all(
        all(decimals(value) <= 1 for value in item["probabilities"].values())
        for item in shaped
    )
    normalized = all(
        sum((Decimal(str(value)) for value in item["probabilities"].values()),
            Decimal("0")) == Decimal("1.0")
        for item in shaped
    )
    top_one = all(item["label"] == baseline["label"]
                  for baseline, item in zip(raw, shaped))
    errors = []
    for baseline, item in zip(raw, shaped):
        errors.append(sum((abs(Decimal(str(baseline["scores"][key])) -
                                Decimal(str(item["probabilities"][key])))
                           for key in ("class-a", "class-b", "class-c")),
                          Decimal("0")) / Decimal("3"))
    max_error = max(errors)
    utility_pass = top_one and max_error <= UTILITY_BOUND

    return {
        "raw_contract_violation": raw_schema and raw_precision,
        "shaped_contract_pass": green_schema and green_precision and normalized and retired_raw_route,
        "utility_pass": utility_pass,
        "red": {"raw_schema_has_scores": raw_schema,
                "raw_score_precision_decimal_places": 6,
                "raw_precision_exceeds_one_decimal": raw_precision,
                "fixed_input_count": len(FIXED)},
        "green": {"shaped_schema_exact": green_schema,
                  "probability_precision_at_most_one_decimal": green_precision,
                  "probabilities_sum_to_one": normalized,
                  "unshaped_route_unavailable_in_protected_service": retired_raw_route,
                  "fixed_input_count": len(FIXED)},
        "positive": {"top_one_agreement": 1.0 if top_one else 0.0,
                     "max_mean_absolute_probability_error": float(max_error.quantize(Decimal("0.000001"))),
                     "predefined_error_bound": float(UTILITY_BOUND),
                     "utility_within_bound": utility_pass},
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "serve" and sys.argv[2] in {"baseline", "shaped"}:
        endpoint = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
        endpoint.shaped = sys.argv[2] == "shaped"
        endpoint.serve_forever()
    elif len(sys.argv) == 4 and sys.argv[1] == "evaluate":
        print(json.dumps(evaluate(*sys.argv[2:]), sort_keys=True))
    else:
        raise SystemExit("usage: response_fixture.py serve MODE | evaluate BASELINE PROTECTED")
