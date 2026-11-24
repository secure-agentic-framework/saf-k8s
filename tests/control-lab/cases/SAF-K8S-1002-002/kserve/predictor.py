"""Synthetic, explicitly instrumented KServe predictor used by this fixture."""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from opentelemetry import propagate, trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor


provider = TracerProvider(resource=Resource.create({
    "service.name": os.environ["SERVICE_NAME"],
    "saf.synthetic": True,
}))
provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(
    endpoint="http://otel.saf-test.svc.cluster.local:4318/v1/traces",
)))
trace.set_tracer_provider(provider)
tracer = trace.get_tracer("saf.kserve.carrier.fixture")

# Explicit W3C extraction from the actual Downward-API value populated from
# metadata.annotations['saf.example/traceparent'] on the KServe-generated Pod.
carrier = {"traceparent": os.environ.get("TRACEPARENT", "")}
parent_context = propagate.extract(carrier)
upstream_span_context = trace.get_current_span(parent_context).get_span_context()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            return
        if self.path != "/emit":
            self.send_error(404)
            return
        with tracer.start_as_current_span(
            "kserve.predictor.inference", context=parent_context
        ) as span:
            span.set_attribute("pipeline.stage", "kserve-predictor")
            span.set_attribute("saf.synthetic", True)
            body = json.dumps({
                "served": True,
                "trace_id": format(span.get_span_context().trace_id, "032x"),
                "span_id": format(span.get_span_context().span_id, "016x"),
                "parent_span_id": format(
                    upstream_span_context.span_id if upstream_span_context.is_valid else 0,
                    "016x",
                ),
            }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
