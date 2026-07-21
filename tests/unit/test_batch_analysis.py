from core.batch_analysis import BatchAnalysisError, ContextItem, execute_batch, pack_contexts, validate_response_items
from core.config import BatchLimits


def test_packer_preserves_order_and_groups_small_contexts() -> None:
    contexts = [{"file_path": f"src/{index}.py", "content": "x" * 20} for index in range(3)]
    batches = pack_contexts(contexts, limits=BatchLimits(max_items=2, max_chars=10_000, max_input_tokens=10_000, max_output_tokens=512))
    assert [len(batch.items) for batch in batches] == [2, 1]
    assert [item.payload["file_path"] for batch in batches for item in batch.items] == ["src/0.py", "src/1.py", "src/2.py"]


def test_response_validation_rejects_missing_and_duplicate_ids() -> None:
    batch = pack_contexts([{"file_path": "a.py"}, {"file_path": "b.py"}], limits=BatchLimits(max_chars=10_000, max_input_tokens=10_000, max_output_tokens=512))[0]
    with_error = {"items": [{"context_id": batch.item_ids[0]}]}
    try:
        validate_response_items(batch, with_error)
    except BatchAnalysisError as exc:
        assert exc.error_code == "missing_context_id"
    else:
        raise AssertionError("missing context IDs must be rejected")

    duplicate = {"items": [{"context_id": batch.item_ids[0]}, {"context_id": batch.item_ids[0]}]}
    try:
        validate_response_items(batch, duplicate)
    except BatchAnalysisError as exc:
        assert exc.error_code == "duplicate_context_id"
    else:
        raise AssertionError("duplicate context IDs must be rejected")


def test_execute_batch_counts_single_request_for_valid_response() -> None:
    batch = pack_contexts([{"file_path": "a.py"}], limits=BatchLimits(max_chars=10_000, max_input_tokens=10_000, max_output_tokens=512))[0]
    outcome = execute_batch(batch, lambda value, _mode: {"items": [{"context_id": value.item_ids[0], "status": "ok", "summary": "summary", "evidence": "evidence", "findings": []}]}, mode="analysis", request_budget=1)
    assert outcome.status == "completed"
    assert outcome.request_count == 1


def test_retryable_provider_status_is_retried_once() -> None:
    batch = pack_contexts([{"file_path": "a.py"}], limits=BatchLimits(max_chars=10_000, max_input_tokens=10_000, max_output_tokens=512))[0]
    attempts = {"count": 0}

    class RateLimitedError(Exception):
        status_code = 429

    def adapter(value, _mode):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RateLimitedError()
        return {"items": [{"context_id": value.item_ids[0], "status": "ok", "summary": "summary", "evidence": "evidence", "findings": []}]}

    outcome = execute_batch(batch, adapter, mode="analysis", request_budget=2)
    assert outcome.status == "completed"
    assert outcome.attempts == 2


def test_duplicate_source_context_gets_a_stable_ordinal_id() -> None:
    batches = pack_contexts([{"file_path": "a.py"}, {"file_path": "a.py"}], limits=BatchLimits(max_chars=10_000, max_input_tokens=10_000, max_output_tokens=512))
    assert batches[0].item_ids[0] != batches[0].item_ids[1]


def test_analysis_schema_requires_evidence_fields() -> None:
    batch = pack_contexts([{"file_path": "a.py"}], limits=BatchLimits(max_chars=10_000, max_input_tokens=10_000, max_output_tokens=512))[0]
    outcome = execute_batch(batch, lambda value, _mode: {"items": [{"context_id": value.item_ids[0], "status": "ok"}]}, mode="analysis", request_budget=1)
    assert outcome.status == "failed"
    assert outcome.errors == ("schema_invalid",)


def test_error_result_requires_an_error_code() -> None:
    batch = pack_contexts([{"file_path": "a.py"}], limits=BatchLimits(max_chars=10_000, max_input_tokens=10_000, max_output_tokens=512))[0]
    outcome = execute_batch(batch, lambda value, _mode: {"items": [{"context_id": value.item_ids[0], "status": "error"}]}, mode="analysis", request_budget=1)
    assert outcome.status == "failed"
