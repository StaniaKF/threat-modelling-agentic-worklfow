import json
from unittest.mock import MagicMock

from utils.get_trace import FileSpanExporter


def test_init_stores_output_file(tmp_path):
    exporter = FileSpanExporter(str(tmp_path / "trace.json"))
    assert exporter.output_file == str(tmp_path / "trace.json")
    assert exporter._spans == []


def test_init_default_filename():
    exporter = FileSpanExporter()
    assert exporter.output_file == "trace_output.json"


def test_on_trace_start_clears_spans():
    exporter = FileSpanExporter("out.json")
    exporter._spans = [{"existing": "span"}]
    exporter.on_trace_start(MagicMock())
    assert exporter._spans == []


def test_on_span_start_is_noop():
    exporter = FileSpanExporter("out.json")
    exporter.on_span_start(MagicMock())
    assert exporter._spans == []


def test_on_span_end_appends_non_none_export():
    exporter = FileSpanExporter("out.json")
    span = MagicMock()
    span.export.return_value = {"span_id": "abc"}
    exporter.on_span_end(span)
    assert exporter._spans == [{"span_id": "abc"}]


def test_on_span_end_ignores_none_export():
    exporter = FileSpanExporter("out.json")
    span = MagicMock()
    span.export.return_value = None
    exporter.on_span_end(span)
    assert exporter._spans == []


def test_on_span_end_appends_multiple_spans():
    exporter = FileSpanExporter("out.json")
    for i in range(3):
        span = MagicMock()
        span.export.return_value = {"id": i}
        exporter.on_span_end(span)
    assert len(exporter._spans) == 3


def test_on_trace_end_writes_json_file(tmp_path):
    output_file = str(tmp_path / "trace.json")
    exporter = FileSpanExporter(output_file)
    exporter._spans = [{"span": "data"}]

    trace = MagicMock()
    trace.export.return_value = {"trace": "info"}
    exporter.on_trace_end(trace)

    with open(output_file) as f:
        data = json.load(f)
    assert data["trace"] == {"trace": "info"}
    assert data["spans"] == [{"span": "data"}]


def test_on_trace_end_writes_empty_spans(tmp_path):
    output_file = str(tmp_path / "trace.json")
    exporter = FileSpanExporter(output_file)

    trace = MagicMock()
    trace.export.return_value = {}
    exporter.on_trace_end(trace)

    with open(output_file) as f:
        data = json.load(f)
    assert data["spans"] == []


def test_shutdown_is_noop():
    exporter = FileSpanExporter("out.json")
    exporter.shutdown()


def test_force_flush_is_noop():
    exporter = FileSpanExporter("out.json")
    exporter.force_flush()
