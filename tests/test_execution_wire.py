import pytest

from tainted.execution.wire import RunRequest, decode_event, encode_event


def test_a_run_request_round_trips_through_json():
    req = RunRequest(
        repo_path="/repo",
        setup={"target": {"url": "http://localhost:3000"}},
        ownership_verified=True,
        autodiscover=False,
        plan=None,
        plan_signature=None,
    )
    assert RunRequest.model_validate_json(req.model_dump_json()) == req


def test_events_are_one_json_object_per_line():
    line = encode_event("finding", finding={"id": "f1"})
    assert "\n" not in line
    assert decode_event(line) == {"kind": "finding", "finding": {"id": "f1"}}


def test_a_malformed_line_raises_rather_than_being_read_as_a_partial_report():
    """Spec test 9. Silently tolerating garbage on this channel means a truncated run reads as
    a clean one with fewer findings."""
    with pytest.raises(ValueError, match="not a JSON object"):
        decode_event("Traceback (most recent call last):")


def test_an_event_without_a_kind_is_refused():
    with pytest.raises(ValueError, match="kind"):
        decode_event('{"finding": {}}')
