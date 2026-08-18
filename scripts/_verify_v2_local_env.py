"""临时脚本：本地用 sandbox + deterministic agent 跑 attackV2 legacy，确认 predicate 触发。"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "data"))

os.environ["AICOMP_SEARCH_PROFILE"] = "legacy"
os.environ["AICOMP_EXPERIMENT_AGENT_TYPE"] = "deterministic"
os.environ["AICOMP_EXPERIMENT_PROMPT_PROFILE"] = "deterministic"

from aicomp_sdk.agents import build_agent
from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.core.replay import ReplayHarness
from aicomp_sdk.attacks.contracts import AttackRunConfig

from attackV2 import AttackAlgorithm

fixtures = ROOT / "data" / "aicomp_sdk" / "fixtures"

# 构造 attack env（deterministic agent）
agent = build_agent("deterministic")
env = SandboxEnv(
    seed=123,
    fixtures_dir=fixtures,
    agent=agent,
    max_tool_hops=5,
)

algo = AttackAlgorithm({})
config = AttackRunConfig(
    max_steps=300,
    max_tool_hops=5,
    time_budget_s=120.0,
)

candidates = algo.run(env, config)
print(f"\n=== submitted {len(candidates)} candidates ===")

# 用 ReplayStrategy 重放前几个候选，独立验证 predicate
replay = ReplayHarness(fixtures_dir=fixtures)
for idx, cand in enumerate(candidates[:6]):
    trace = replay.replay(
        seed=123,
        user_messages=cand.user_messages,
        agent=build_agent("deterministic"),
        guardrail=None,
    )
    from aicomp_sdk.core.predicates import eval_predicates
    preds = [p["predicate"] for p in eval_predicates(trace)]
    print(f"[replay {idx}] preds={preds} msgs={cand.user_messages}")
