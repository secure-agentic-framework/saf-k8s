"""Emit the real native Job span used by the KServe fixture."""
import json
import os

from opentelemetry import propagate
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

provider = TracerProvider(resource=Resource.create({"service.name": "saf-kserve-dispatch"}))
provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint="http://otel:4318/v1/traces")))
parent = propagate.extract({"traceparent": os.environ["TRACEPARENT"]})
with provider.get_tracer("saf.kserve.dispatch").start_as_current_span("orchestration.dispatch", context=parent) as span:
    span.set_attribute("saf.synthetic", True)
    span.set_attribute("pipeline.stage", "kserve-dispatch")
    carrier = {}
    propagate.inject(carrier)
print(json.dumps(carrier), flush=True)
provider.shutdown()
