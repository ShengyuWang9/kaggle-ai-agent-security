"""Compare the H1 deterministic baseline with a Kaggle GPT-OSS trace."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = (
    REPO_ROOT / "outputs" / "phase5_6_3_test" / "phase5_6_llm_records.jsonl"
)
DEFAULT_LLM = REPO_ROOT / "phase5_6_llm_records.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "phase5.6.4_first_llm_trace_analysis.md"


@dataclass(frozen=True)
class TraceMetrics:
    assistant_messages: int
    response_characters: int
    tool_calls: int
    successful_tool_calls: int
    failed_tool_calls: int
    refusal: bool
    predicate_results: int
    predicate_triggered: bool


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as err:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {err}") from err
            if not isinstance(payload, dict):
                raise ValueError(f"{path}:{line_number}: record must be an object")
            records.append(payload)
    if not records:
        raise ValueError(f"{path}: no records")
    return records


def _latest_probe(records: Iterable[dict[str, Any]], probe: str) -> dict[str, Any]:
    matches = [
        record
        for record in records
        if record.get("probe_name", record.get("experiment_id")) == probe
    ]
    if not matches:
        raise ValueError(f"no {probe} record found")
    return matches[-1]


def _validate_record(record: dict[str, Any], *, label: str) -> None:
    required = {
        "timestamp",
        "backend",
        "model_name",
        "agent_type",
        "prompt_profile",
        "probe_name",
        "trace",
        "tool_events",
        "predicate_result",
        "failure_category",
    }
    missing = sorted(required.difference(record))
    if missing:
        raise ValueError(f"{label}: missing fields: {', '.join(missing)}")
    if not isinstance(record["trace"], dict):
        raise ValueError(f"{label}: trace must be an object")
    if not isinstance(record["tool_events"], list):
        raise ValueError(f"{label}: tool_events must be a list")
    if not isinstance(record["predicate_result"], list):
        raise ValueError(f"{label}: predicate_result must be a list")


def _validate_gpt_oss_record(record: dict[str, Any]) -> None:
    expected = {
        "backend": "gateway",
        "model_name": "gpt_oss",
        "agent_type": "llm",
        "prompt_profile": "llm",
        "probe_name": "H1_URL",
    }
    mismatches = [
        f"{key}={record.get(key)!r} (expected {value!r})"
        for key, value in expected.items()
        if record.get(key) != value
    ]
    if mismatches:
        raise ValueError("LLM record metadata mismatch: " + "; ".join(mismatches))


def _assistant_texts(trace: dict[str, Any]) -> list[str]:
    messages = trace.get("assistant_messages", [])
    if not isinstance(messages, list):
        return []
    return [message for message in messages if isinstance(message, str)]


def _metrics(record: dict[str, Any]) -> TraceMetrics:
    assistant_messages = _assistant_texts(record["trace"])
    tool_events = record["tool_events"]
    successful = sum(event.get("ok") is True for event in tool_events)
    failed = len(tool_events) - successful
    failure_categories = set(record.get("failure_category", []))
    refusal = bool(record.get("agent_refused_any")) or "AGENT_REFUSED" in failure_categories
    predicates = record["predicate_result"]
    return TraceMetrics(
        assistant_messages=len(assistant_messages),
        response_characters=sum(len(message) for message in assistant_messages),
        tool_calls=len(tool_events),
        successful_tool_calls=successful,
        failed_tool_calls=failed,
        refusal=refusal,
        predicate_results=len(predicates),
        predicate_triggered=bool(predicates),
    )


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _render_report(
    baseline_path: Path,
    llm_path: Path,
    baseline: dict[str, Any],
    llm: dict[str, Any],
) -> str:
    deterministic = _metrics(baseline)
    gpt_oss = _metrics(llm)
    lines = [
        "# Phase 5.6.4 First Real LLM Trace Analysis",
        "",
        "## Scope",
        "",
        "This report compares the existing unchanged `H1_URL` probe under the local "
        "deterministic baseline and the Kaggle Gateway `gpt_oss` run. It is an "
        "observation-only baseline; no attack prompt or H1-H8 logic was changed.",
        "",
        "## Record identity",
        "",
        "| Field | deterministic | gpt_oss |",
        "|---|---:|---:|",
        f"| source | `{baseline_path.as_posix()}` | `{llm_path.as_posix()}` |",
        f"| timestamp | {baseline.get('timestamp', '')} | {llm.get('timestamp', '')} |",
        f"| backend | {baseline.get('backend')} | {llm.get('backend')} |",
        f"| model | {baseline.get('model_name')} | {llm.get('model_name')} |",
        f"| agent type | {baseline.get('agent_type')} | {llm.get('agent_type')} |",
        f"| prompt profile | {baseline.get('prompt_profile')} | {llm.get('prompt_profile')} |",
        f"| probe | {baseline.get('probe_name')} | {llm.get('probe_name')} |",
        f"| budget (s) | {baseline.get('budget_s')} | {llm.get('budget_s')} |",
        "",
        "## Observed trace metrics",
        "",
        "| Metric | deterministic | gpt_oss |",
        "|---|---:|---:|",
        f"| assistant messages | {deterministic.assistant_messages} | {gpt_oss.assistant_messages} |",
        f"| assistant response characters | {deterministic.response_characters} | {gpt_oss.response_characters} |",
        f"| tool calls | {deterministic.tool_calls} | {gpt_oss.tool_calls} |",
        f"| successful tool calls | {deterministic.successful_tool_calls} | {gpt_oss.successful_tool_calls} |",
        f"| failed/blocked tool calls | {deterministic.failed_tool_calls} | {gpt_oss.failed_tool_calls} |",
        f"| refusal observed | {_yes_no(deterministic.refusal)} | {_yes_no(gpt_oss.refusal)} |",
        f"| predicate results | {deterministic.predicate_results} | {gpt_oss.predicate_results} |",
        f"| predicate triggered | {_yes_no(deterministic.predicate_triggered)} | {_yes_no(gpt_oss.predicate_triggered)} |",
        "",
        "## Observation",
        "",
        f"The GPT-OSS trace emitted {gpt_oss.tool_calls} tool call(s) and "
        f"{gpt_oss.response_characters} assistant-response character(s). "
        f"Refusal was {_yes_no(gpt_oss.refusal)}, and predicate triggering was "
        f"{_yes_no(gpt_oss.predicate_triggered)} ({gpt_oss.predicate_results} result(s)).",
        "",
        "This first trace validates only the real-model experiment loop. A single H1 "
        "trace is not sufficient to choose a Phase 6 attack direction.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deterministic", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--llm", type=Path, default=DEFAULT_LLM)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    baseline = _latest_probe(_read_jsonl(args.deterministic), "H1_URL")
    llm = _latest_probe(_read_jsonl(args.llm), "H1_URL")
    _validate_record(baseline, label="deterministic baseline")
    _validate_record(llm, label="gpt_oss")
    _validate_gpt_oss_record(llm)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        _render_report(args.deterministic, args.llm, baseline, llm),
        encoding="utf-8",
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
