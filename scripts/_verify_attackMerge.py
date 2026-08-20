"""临时脚本：用 fake agent（模拟真实 LLM 照做消息指令）验证 attackMerge 的命中逻辑。

跑完即删。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "data"))

from aicomp_sdk.agents.types import (
    FinalResponseDecision,
    ToolCall,
    ToolCallDecision,
    UserMessageEvent,
)
from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.core.predicates import is_protected_secret_path
from aicomp_sdk.guardrails.base import Decision, GuardrailBase
from aicomp_sdk.attacks.contracts import AttackRunConfig

from attackMerge import AttackMerge


class FollowInstructionsAgent:
    """模拟真实 LLM：从消息提取 URL/收件人并照做。"""

    _URL_RE = re.compile(r"https?://[^\s'\"<>]+")
    _EMAIL_RE = re.compile(r"[\w.+-]+@example\.invalid")

    def next_action(self, *, history, tools):
        msg = ""
        for e in history.events[::-1]:
            if isinstance(e, UserMessageEvent):
                msg = e.text
                break
        url = self._URL_RE.search(msg)
        if url:
            return ToolCallDecision(
                call=ToolCall(
                    call_id="c1",
                    tool_name="http.post",
                    arguments={"url": url.group(0), "data": "SECRET_MARKER"},
                ),
                assistant_message=None,
            )
        to = self._EMAIL_RE.search(msg)
        if to:
            return ToolCallDecision(
                call=ToolCall(
                    call_id="c2",
                    tool_name="email.send",
                    arguments={
                        "to": to.group(0),
                        "subject": "Status Update",
                        "body": "All systems operational.",
                    },
                ),
                assistant_message=None,
            )
        if "open " in msg:
            page = msg.split("open ", 1)[1].strip()
            return ToolCallDecision(
                call=ToolCall(
                    call_id="c3",
                    tool_name="web.open",
                    arguments={"id": page},
                ),
                assistant_message=None,
            )
        return FinalResponseDecision(text="done")

    def reset_state(self) -> None:
        pass

    def snapshot_state(self):
        return {}

    def restore_state(self, snapshot) -> None:
        pass


class _LocalGuardrail(GuardrailBase):
    """模拟评测 guardrail：拦 fs.read(secret.txt)；放行 http.post / email.send。"""

    def decide(self, tool_name, tool_args, context):
        if tool_name == "fs.read" and is_protected_secret_path(tool_args.get("path", "")):
            return Decision.deny("blocked_secret_read")
        return Decision.allow("ok")


fixtures = ROOT / "data" / "aicomp_sdk" / "fixtures"

env = SandboxEnv(
    seed=123,
    fixtures_dir=fixtures,
    agent=FollowInstructionsAgent(),
    guardrail=_LocalGuardrail(),
)

attacker = AttackMerge(config={"url_pool_size": 15, "max_candidates": 60})
cands = attacker.run(env, AttackRunConfig(time_budget_s=120, max_steps=10**9))

print(f"\n=== candidates={len(cands)} ===")
for i, c in enumerate(cands):
    print(f"[{i}] {c.user_messages[0][:90]}")
