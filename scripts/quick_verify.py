"""快速本地验证：用本地 deterministic agent + 小候选集，秒级反馈攻击质量。

用法:
    python scripts/quick_verify.py [max_candidates] [budget_s]

说明:
- deterministic agent 是"理想配合"agent，代表攻击在真实 LLM 下的理论上限。
- 真实 LLM (gpt_oss/gemma) 会因拒绝/不执行而打折，需用小批量真实 LLM 校准成功率。
- 每次运行会快速验证: 候选能否触发 predicate、是否通过 guardrail、cell 是否唯一。
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "data"))

from aicomp_sdk.agents import AgentSelection
from aicomp_sdk.core.env.api import EnvSelection
from aicomp_sdk.evaluation.runner import evaluate_redteam


def load_attack_class(path: Path):
    spec = importlib.util.spec_from_file_location("_quick_attack", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_quick_attack"] = mod
    spec.loader.exec_module(mod)
    return mod.AttackAlgorithm


def main() -> int:
    attack_path = ROOT / "attack.py"
    max_candidates = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    budget_s = float(sys.argv[2]) if len(sys.argv) > 2 else 120.0

    if not attack_path.exists():
        print(f"未找到攻击文件: {attack_path}")
        return 1

    print(f"攻击文件: {attack_path}")
    print(f"候选上限: {max_candidates}, 时间预算: {budget_s:.0f}s, agent=deterministic")
    print("=" * 60)

    attack_cls = load_attack_class(attack_path)
    start = time.time()
    execution = evaluate_redteam(
        attack_cls,
        budget_s=budget_s,
        agent_selection=AgentSelection.DETERMINISTIC,
        env_selection=EnvSelection.GYM,
        attack_config={"max_candidates": max_candidates},
        attack_env_seed=123,
    )
    elapsed = time.time() - start
    attack = execution.attack

    print("\n==== 本地快速验证结果 ====")
    print(f"归一化分:    {attack.score:.2f} / 1000")
    print(f"原始分(raw): {attack.score_raw:.1f}")
    print(f"有效findings: {attack.findings_count}")
    print(f"唯一cells:   {attack.unique_cells}")
    print(f"guardrail:   {attack.guardrail_id}")
    print(f"评估耗时:    {attack.time_taken:.1f}s (总 {elapsed:.1f}s)")
    print("=" * 60)
    print("解读: deterministic 是理想配合 agent，代表理论上限；")
    print("      真实 LLM 下每个候选都有成功率折扣，需要小批量真实 LLM 校准。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
