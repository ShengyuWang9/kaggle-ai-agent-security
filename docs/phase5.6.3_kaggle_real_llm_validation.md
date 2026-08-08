# Phase 5.6.3 Kaggle Real LLM Validation

## 1. 目标与边界

本阶段建立最小 Kaggle hosted LLM 验证闭环，不修改攻击策略、不增加 prompt，也不修改 H1-H8。

最小闭环定义为：

```text
单一 Kaggle model
  -> 1 个已有 probe
  -> 60-120 秒攻击侧预算
  -> 完整 assistant/tool trace
  -> ExperimentRecord JSONL
  -> gateway 日志确认实际模型
```

当前推荐起点：

- model：`gpt_oss`
- probe：`H1_URL`
- budget：90 秒

## 2. Lightweight 模式

新增 experiment mode：

```text
phase5_6_lightweight
```

行为：

1. 只运行 H1-H8 中显式选择的 probe；
2. `probe_set` 为空时默认只运行 `H1_URL`；
3. 未知 probe id 直接抛出配置错误；
4. 不构建或运行默认 search plan；
5. 配置预算与 evaluator 预算取较小值；
6. 最终攻击侧预算不超过 120 秒；
7. 记录写入 `phase5_6_llm_records.jsonl`。

这只缩小实验执行范围，不改变 probe 文本或单条 probe 的执行方式。一次 `env.interact()` 若正在等待真实模型，仍由 Kaggle Gateway 的总 deadline 兜底。

## 3. Kaggle metadata 配置

提交侧需要显式声明：

```python
import os

os.environ["AICOMP_ATTACK_EXPERIMENT_MODE"] = "phase5_6_lightweight"
os.environ["AICOMP_EXPERIMENT_BACKEND"] = "gateway"
os.environ["AICOMP_EXPERIMENT_MODEL"] = "gpt_oss"
os.environ["AICOMP_EXPERIMENT_AGENT_TYPE"] = "llm"
os.environ["AICOMP_EXPERIMENT_PROMPT_PROFILE"] = "llm"
os.environ["AICOMP_EXPERIMENT_SEED"] = "123"
os.environ["AICOMP_EXPERIMENT_BUDGET_S"] = "90"
os.environ["AICOMP_EXPERIMENT_PROBE_SET"] = "H1_URL"
os.environ["AICOMP_EXPERIMENT_ENVIRONMENT"] = "kaggle_gym"
```

预期记录：

```json
{
  "backend": "gateway",
  "model_name": "gpt_oss",
  "agent_type": "llm",
  "prompt_profile": "llm",
  "budget_s": 90.0,
  "probe_name": "H1_URL",
  "environment": "kaggle_gym"
}
```

这些字段是提交侧声明的实验元数据，不会选择 Kaggle model。实际模型必须由 Gateway 日志确认。

如果未设置 `AICOMP_EXPERIMENT_MODEL`：

```json
{
  "backend": "gateway",
  "model_name": "unknown",
  "agent_type": "llm"
}
```

代码不会从 `agent_type` 或 `prompt_profile` 推断 `model_name`。

## 4. 单模型 Gateway 配置

仓库内受控 gateway 支持：

```python
os.environ["AICOMP_MODEL_NAMES"] = "gpt_oss"
```

该变量必须在导入 `jed_attack_gateway` 之前设置，因为 `MODEL_NAMES` 在模块导入时解析。

重要限制：

- `AICOMP_MODEL_NAMES` 是 gateway 侧配置；
- `AICOMP_EXPERIMENT_MODEL` 是 attack 提交侧声明元数据；
- 两者必须一致；
- 正式 competition rerun 的 gateway 可能由 Kaggle scorer 管理，提交代码不能假设可以覆盖其模型集合。

在 starter notebook/受控验证 notebook 中，如果 gateway 与提交 inference server 是不同进程或容器，需要确认相应环境变量分别传入两侧。不要仅凭 JSONL 中的 `model_name` 判定真实模型。

## 5. 最小 Kaggle 实验流程

### Step 1：本地离线合同检查

在 WSL Python 3.12 中运行：

```bash
source .venv/bin/activate
export PYTHONPATH="$PWD/data"
python scripts/verify_phase5_6_kaggle.py
```

脚本只检查模块加载、配置、schema 和 JSON 序列化，不加载模型、不执行攻击。

### Step 2：配置单模型 notebook

在导入 gateway/inference server 之前：

```python
import os

# Gateway side: controlled validation notebook only.
os.environ["AICOMP_MODEL_NAMES"] = "gpt_oss"

# Attack-side declared metadata.
os.environ["AICOMP_ATTACK_EXPERIMENT_MODE"] = "phase5_6_lightweight"
os.environ["AICOMP_EXPERIMENT_BACKEND"] = "gateway"
os.environ["AICOMP_EXPERIMENT_MODEL"] = "gpt_oss"
os.environ["AICOMP_EXPERIMENT_AGENT_TYPE"] = "llm"
os.environ["AICOMP_EXPERIMENT_PROMPT_PROFILE"] = "llm"
os.environ["AICOMP_EXPERIMENT_BUDGET_S"] = "90"
os.environ["AICOMP_EXPERIMENT_PROBE_SET"] = "H1_URL"
os.environ["AICOMP_EXPERIMENT_ENVIRONMENT"] = "kaggle_gym"
```

### Step 3：运行最小验证

只启动单模型、单 probe 验证。不要启动双模型、全部 H1-H8、public/private 多轮 replay 的完整长评测。

### Step 4：确认 Gateway 证据

运行日志至少应包含等价信息：

```text
[GATEWAY] Models: ['gpt_oss']
[ATTACK] Starting attack for model=gpt_oss
```

模型 server 日志应表明 GPT-OSS GGUF 已加载或正在使用预下载模型。

### Step 5：确认 attack 侧元数据

attack 日志应包含：

```text
[attack-mode] agent_type=llm backend=gateway model=gpt_oss \
prompt_profile=llm budget_s=90.0 experiment_mode=phase5_6_lightweight \
generated_candidate_chains=1 focused_probes=on
```

### Step 6：确认 trace

检查 `/kaggle/working/phase5_6_llm_records.jsonl`：

- 只有所选 probe 的新记录；
- `trace.assistant_messages` 来自真实模型；
- `tool_events` 与 `trace.tool_events` 一致；
- `predicate_result` 与同一 trace 对应；
- `failure_category` 可解释无 predicate 的原因；
- metadata 与 Gateway 日志中的 model 一致。

如果文件不可从提交容器持久化，使用 evaluator 捕获的 `[experiment-record]` stdout JSON，并与 gateway 日志一起保存。不要修改攻击逻辑来规避容器边界。

### Step 7：决定是否扩大

只有以下条件满足后才扩大到更多现有 probe：

1. Gateway 确认真正运行 GPT-OSS；
2. trace 行为与 deterministic baseline 有可观察差异；
3. assistant response/tool calls 完整；
4. metadata 与实际模型一致；
5. 单次执行能在目标时间内结束。

下一轮可把 `AICOMP_EXPERIMENT_PROBE_SET` 改为逗号分隔的 H1-H8 子集。不得添加新 probe 或新 prompt。

## 6. Gemma 验证

GPT-OSS 最小闭环通过后，使用完全相同流程单独验证 Gemma：

```python
os.environ["AICOMP_MODEL_NAMES"] = "gemma"
os.environ["AICOMP_EXPERIMENT_MODEL"] = "gemma"
```

其他设置保持不变。Kaggle gateway 中的 `gemma` 使用 `Gemma4Agent` 语义和 Gemma 4 GGUF model server，不等同于本地 SDK `--agent gemma`。

## 7. 本地与 Kaggle 的区别

| 项目 | WSL 小测试 | Kaggle 最小真实模型验证 |
|---|---|---|
| backend | `local` | `gateway` |
| model | `deterministic` | `gpt_oss` 或 `gemma` |
| evaluator agent | 显式 `--agent deterministic` | Gateway RemoteAgent + GGUF model server |
| prompt profile | deterministic | llm |
| 目的 | schema/控制流回归 | 真实模型 trace baseline |
| 结论范围 | 不代表 LLM 能力 | Gateway 证据完整时可作为对应模型结论 |

本地 small deterministic test 只验证 lightweight 选择、预算、日志与 schema。它不能替代 Kaggle hosted model trace。

## 8. 验证失败处理

| 现象 | 处理 |
|---|---|
| 日志仍显示两个模型 | gateway 单模型配置未生效或设置晚于模块导入 |
| record 为 `model_name=unknown` | attack 侧未声明模型；补齐 metadata，但仍需 gateway 证据 |
| record 为 `gpt_oss`，gateway 实际是 Gemma | 记录无效；修正两侧配置并重跑 |
| generated chains 大于所选 probe 数 | lightweight mode/probe_set 未生效 |
| 超过 120 秒仍未结束 | 检查是否卡在模型加载或单次 inference；不要扩大 probe 集合 |
| trace 与 deterministic 完全一致 | 先核验 Gateway model server，不要据此调整攻击方向 |

## 9. Phase 6 门槛

Phase 6 方向选择仍需真实 GPT-OSS/Gemma H1-H8 trace。单个 H1 lightweight 结果只证明实验闭环可用，不足以选择 Exfiltration、Confused Deputy、Context Drift 或 Tool Misuse。
