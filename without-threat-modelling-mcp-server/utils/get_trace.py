"""
Custom tracing processor that saves OpenAI Agents SDK trace data to a local JSON file.

Usage:
    In main.py, add before running the agent:

        from utils.get_trace import FileSpanExporter
        from agents.tracing import set_trace_processors

        set_trace_processors([FileSpanExporter("trace_output.json")])
"""

import json
from typing import Any

from agents.tracing import TracingProcessor, Span, Trace


class FileSpanExporter(TracingProcessor):
    """Collects all spans and writes the full trace to a JSON file when the trace ends."""

    def __init__(self, output_file: str = "trace_output.json"):
        self.output_file = output_file
        self._spans: list[dict[str, Any]] = []

    def on_trace_start(self, trace: Trace) -> None:
        self._spans = []

    def on_span_start(self, span: Span) -> None:
        pass

    def on_span_end(self, span: Span) -> None:
        span_export = span.export()
        if span_export is not None:
            self._spans.append(span_export)

    def on_trace_end(self, trace: Trace) -> None:
        trace_export = trace.export()
        output = {
            "trace": trace_export,
            "spans": self._spans,
        }
        with open(self.output_file, "w") as f:
            json.dump(output, f, indent=2, default=str)

        print(f"\nTrace saved to {self.output_file}")

    def shutdown(self) -> None:
        pass

    def force_flush(self) -> None:
        pass
