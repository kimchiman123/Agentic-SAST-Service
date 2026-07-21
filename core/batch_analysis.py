"""Deterministic, provider-agnostic batch contracts for LLM analysis.

The module deliberately owns packing and ID validation.  Provider adapters may
change, but an adapter can never reorder a finding or silently accept a result
for a different source context.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable, Mapping, Sequence

from core.config import BatchLimits


class BatchAnalysisError(ValueError):
    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


@dataclass(frozen=True)
class ContextItem:
    context_id: str
    payload: Mapping[str, Any]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ContextItem":
        normalized = canonical_json(payload)
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:20]
        return cls(context_id=f"ctx_{digest}", payload=dict(payload))


@dataclass(frozen=True)
class AnalysisBatch:
    batch_id: str
    items: tuple[ContextItem, ...]
    envelope: Mapping[str, Any]

    @property
    def item_ids(self) -> tuple[str, ...]:
        return tuple(item.context_id for item in self.items)


@dataclass(frozen=True)
class BatchOutcome:
    batch_id: str
    status: str
    results: tuple[Mapping[str, Any], ...] = ()
    errors: tuple[str, ...] = ()
    attempts: int = 0
    request_count: int = 0


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def estimate_tokens(value: Any) -> int:
    """Conservative token estimate used until a model tokenizer is verified."""
    return (len(canonical_json(value).encode("utf-8")) + 3) // 4


def _fits(envelope: Mapping[str, Any], items: Sequence[ContextItem], limits: BatchLimits, context_window_tokens: int | None) -> bool:
    payload = {"shared": envelope, "items": [dict(item.payload, context_id=item.context_id) for item in items]}
    serialized = canonical_json(payload)
    return (
        len(items) <= limits.max_items
        and len(serialized) <= limits.max_chars
        and estimate_tokens(payload) + limits.max_output_tokens <= limits.max_input_tokens + limits.max_output_tokens
        and estimate_tokens(payload) <= limits.max_input_tokens
        and (context_window_tokens is None or estimate_tokens(payload) + limits.max_output_tokens <= context_window_tokens)
    )


def pack_contexts(
    contexts: Iterable[Mapping[str, Any] | ContextItem],
    *,
    envelope: Mapping[str, Any] | None = None,
    limits: BatchLimits = BatchLimits(),
    context_window_tokens: int | None = None,
) -> list[AnalysisBatch]:
    """Stable greedy packing that preserves input order and all hard limits."""
    shared = dict(envelope or {})
    items = [item if isinstance(item, ContextItem) else ContextItem.from_payload(item) for item in contexts]
    seen_ids: dict[str, int] = {}
    unique_items: list[ContextItem] = []
    for item in items:
        count = seen_ids.get(item.context_id, 0) + 1
        seen_ids[item.context_id] = count
        unique_items.append(item if count == 1 else replace(item, context_id=f"{item.context_id}_{count}"))
    items = unique_items
    batches: list[AnalysisBatch] = []
    pending: list[ContextItem] = []
    for item in items:
        if not _fits(shared, [item], limits, context_window_tokens):
            raise BatchAnalysisError("item_too_large", f"Context {item.context_id} exceeds batch limits.")
        candidate = [*pending, item]
        if pending and not _fits(shared, candidate, limits, context_window_tokens):
            batch_id = f"batch_{len(batches) + 1:04d}"
            batches.append(AnalysisBatch(batch_id, tuple(pending), shared))
            pending = [item]
        else:
            pending = candidate
    if pending:
        batch_id = f"batch_{len(batches) + 1:04d}"
        batches.append(AnalysisBatch(batch_id, tuple(pending), shared))
    return batches


def validate_response_items(
    batch: AnalysisBatch, response: Mapping[str, Any], *, key: str = "items"
) -> tuple[Mapping[str, Any], ...]:
    raw_items = response.get(key)
    if not isinstance(raw_items, list):
        raise BatchAnalysisError("schema_invalid", f"{key} must be a list.")
    expected = set(batch.item_ids)
    received: set[str] = set()
    normalized: list[Mapping[str, Any]] = []
    for item in raw_items:
        if not isinstance(item, Mapping) or not isinstance(item.get("context_id"), str):
            raise BatchAnalysisError("schema_invalid", "Each result requires context_id.")
        context_id = item["context_id"]
        if context_id not in expected:
            raise BatchAnalysisError("unknown_context_id", f"Unknown context ID {context_id}.")
        if context_id in received:
            raise BatchAnalysisError("duplicate_context_id", f"Duplicate context ID {context_id}.")
        received.add(context_id)
        normalized.append(dict(item))
    if received != expected:
        missing = ",".join(sorted(expected - received))
        raise BatchAnalysisError("missing_context_id", f"Missing context IDs: {missing}")
    order = {context_id: index for index, context_id in enumerate(batch.item_ids)}
    return tuple(sorted(normalized, key=lambda item: order[str(item["context_id"])]))


def validate_pass_schema(items: Sequence[Mapping[str, Any]], mode: str) -> None:
    for item in items:
        status = item.get("status")
        if status not in {"ok", "error", "skipped"}:
            raise BatchAnalysisError("schema_invalid", "Each result requires a valid status.")
        if status in {"error", "skipped"} and not isinstance(item.get("error_code"), str):
            raise BatchAnalysisError("schema_invalid", "Error and skipped results require error_code.")
        if mode == "analysis" and status == "ok":
            if not isinstance(item.get("summary"), str) or not isinstance(item.get("evidence"), str) or not isinstance(item.get("findings"), list):
                raise BatchAnalysisError("schema_invalid", "Analysis results require summary, evidence, and findings.")
        if mode == "verification" and status == "ok":
            if item.get("verdict") not in {"tp", "fp", "unknown", "error", "skipped"} or not isinstance(item.get("rationale"), str):
                raise BatchAnalysisError("schema_invalid", "Verification results require verdict and rationale.")


Adapter = Callable[[AnalysisBatch, str], Mapping[str, Any]]


def _retryable(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
    return status in {408, 429, 500, 502, 503, 504} or isinstance(exc, TimeoutError)


def execute_batch(
    batch: AnalysisBatch,
    adapter: Adapter,
    *,
    mode: str,
    request_budget: int,
    max_attempts: int = 2,
) -> BatchOutcome:
    """Run one pass with bounded retry and explicit failure classification."""
    attempts = 0
    last_error: BatchAnalysisError | None = None
    while attempts < max_attempts:
        if attempts >= request_budget:
            return BatchOutcome(batch.batch_id, "failed", errors=("request_budget_exhausted",), attempts=attempts, request_count=attempts)
        attempts += 1
        try:
            response = adapter(batch, mode)
            results = validate_response_items(batch, response)
            validate_pass_schema(results, mode)
            return BatchOutcome(batch.batch_id, "completed", results=results, attempts=attempts, request_count=attempts)
        except BatchAnalysisError as exc:
            last_error = exc
            break
        except Exception as exc:  # Adapter boundary: provider errors are normalized here only.
            if not _retryable(exc):
                return BatchOutcome(batch.batch_id, "failed", errors=("provider_error",), attempts=attempts, request_count=attempts)
            last_error = BatchAnalysisError("provider_retry_exhausted", type(exc).__name__)
            if attempts < max_attempts:
                time.sleep(0.1 * attempts)
    return BatchOutcome(
        batch.batch_id,
        "failed",
        errors=((last_error.error_code if last_error else "provider_retry_exhausted"),),
        attempts=attempts,
        request_count=attempts,
    )


def execute_two_passes(
    batches: Sequence[AnalysisBatch],
    adapter: Adapter,
    *,
    request_budget: int,
) -> tuple[list[BatchOutcome], list[BatchOutcome]]:
    """Analysis then verification. Failed analysis batches never reach verification."""
    analyses: list[BatchOutcome] = []
    verifications: list[BatchOutcome] = []
    remaining = request_budget
    for batch in batches:
        outcome = execute_batch(batch, adapter, mode="analysis", request_budget=remaining)
        analyses.append(outcome)
        remaining -= outcome.request_count
        if outcome.status != "completed":
            continue
        verify_batch = AnalysisBatch(batch.batch_id, batch.items, {"analyses": list(outcome.results)})
        verification = execute_batch(verify_batch, adapter, mode="verification", request_budget=remaining)
        verifications.append(verification)
        remaining -= verification.request_count
    return analyses, verifications
