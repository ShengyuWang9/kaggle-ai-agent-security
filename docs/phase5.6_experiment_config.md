# Phase 5.6.2 Experiment Configuration

## 1. 目标

Phase 5.6.2 只统一实验配置和日志元数据，不修改 H1-H8、攻击模板、candidate ranking 或搜索顺序。

新增的 `ExperimentConfig` 解决两个问题：

1. 把攻击侧 PromptProfile 与 evaluator 实际 backend/model 分开描述；
2. 让 WSL 本地回归和 Kaggle 单模型实验使用同一套记录 schema。

## 2. 三个概念的区别

### 2.1 `agent_type`

`agent_type` 是行为类别标签，例如：

- `deterministic`
- `llm`

它用于描述实验面向哪类 agent，但不能证明实际运行了哪个 backend。

### 2.2 `prompt_profile`

`prompt_profile` 决定 `PromptGenerator` 使用哪套已有措辞：

- `deterministic`
- `llm`

它只控制 prompt 选择。`prompt_profile=llm` 不代表 evaluator 已加载真实 LLM。

### 2.3 `backend`

`backend` 描述 agent 由哪里提供，例如：

- `local`：WSL 中的本地 SDK evaluator；
- `gateway`：Kaggle Gateway/RemoteAgent 路径。

它描述执行管线，不描述具体模型。

### 2.4 `model_name`

`model_name` 描述声明的具体模型，例如：

- `deterministic`
- `gpt_oss`
- `gemma`
- `unknown`

`backend` 和 `model_name` 必须分别记录。正确示例：

```json
{
  "backend": "gateway",
  "model_name": "gpt_oss",
  "agent_type": "llm",
  "prompt_profile": "llm"
}
```

如果 Kaggle evaluator 没有把模型名传给提交侧，而且 notebook 没有显式声明模型，必须记录 `model_name=unknown`，不能从 `agent_type=llm` 推断。

## 3. `ExperimentConfig`

字段：

| 字段 | 含义 | 默认值 |
|---|---|---|
| `backend` | 声明的执行管线 | `local` |
| `model_name` | 声明的具体模型 | 本地 deterministic 默认值为 `deterministic`，其他情况为 `unknown` |
| `agent_type` | agent 行为类别 | `deterministic` |
| `prompt_profile` | 已有 PromptProfile 名称 | 由 agent type 兼容推导 |
| `seed` | 声明的实验 seed | `123` |
| `budget_s` | 声明预算；运行时由 `AttackRunConfig` 提供实际值 | `0.0` |
| `probe_set` | 声明的 probe 集合 | 空 tuple |
| `environment` | 执行环境标签 | 本地为 `local`，否则 `unknown` |

`probe_set` 在本阶段只进入统一配置，不改变 H1-H8 的执行逻辑。Phase 5.6.3 快速模式再使用它限制 probe 数量。

### 3.1 Python mapping 入口

推荐使用嵌套 `experiment` mapping：

```python
config = {
    "experiment_mode": "phase5_2_only",
    "experiment": {
        "backend": "local",
        "model_name": "deterministic",
        "agent_type": "deterministic",
        "prompt_profile": "deterministic",
        "seed": 123,
        "budget_s": 60,
        "probe_set": ["H1_URL"],
        "environment": "wsl_gym",
    },
}
```

为兼容已有调用者，相同字段也可以暂时放在顶层。嵌套 mapping 优先于顶层同名字段。

### 3.2 环境变量入口

Kaggle 当前执行 `attack_cls(config={})`，因此提交侧主要通过环境变量接收声明元数据：

| 环境变量 | 配置字段 |
|---|---|
| `AICOMP_EXPERIMENT_BACKEND` | `backend` |
| `AICOMP_EXPERIMENT_MODEL` | `model_name` |
| `AICOMP_EXPERIMENT_AGENT_TYPE` | `agent_type` |
| `AICOMP_EXPERIMENT_PROMPT_PROFILE` | `prompt_profile` |
| `AICOMP_EXPERIMENT_SEED` | `seed` |
| `AICOMP_EXPERIMENT_BUDGET_S` | `budget_s` |
| `AICOMP_EXPERIMENT_PROBE_SET` | comma-separated `probe_set` |
| `AICOMP_EXPERIMENT_ENVIRONMENT` | `environment` |

旧入口仍兼容：

- `AICOMP_ATTACK_AGENT_TYPE`
- `AICOMP_AGENT_TYPE`
- `AICOMP_ATTACK_EXPERIMENT_MODE`

解析优先级：

1. constructor mapping（嵌套 `experiment` 优先于顶层）；
2. Phase 5.6 专用环境变量；
3. 旧 agent type 环境变量；
4. 安全默认值。

### 3.3 WSL 本地示例

```bash
export AICOMP_EXPERIMENT_BACKEND=local
export AICOMP_EXPERIMENT_MODEL=deterministic
export AICOMP_EXPERIMENT_AGENT_TYPE=deterministic
export AICOMP_EXPERIMENT_PROMPT_PROFILE=deterministic
export AICOMP_EXPERIMENT_ENVIRONMENT=wsl_gym
```

本地 evaluator 仍应显式使用：

```bash
python -m aicomp_sdk.cli.main test redteam attack.py \
  --agent deterministic \
  --env gym \
  --budget-s 60
```

`--agent deterministic` 控制 evaluator agent；`AICOMP_EXPERIMENT_*` 只描述并记录实验，两者职责不同。

### 3.4 Kaggle 单模型示例

在受控的单模型 Kaggle Notebook 中，提交侧元数据可声明为：

```python
import os

os.environ["AICOMP_EXPERIMENT_BACKEND"] = "gateway"
os.environ["AICOMP_EXPERIMENT_MODEL"] = "gpt_oss"
os.environ["AICOMP_EXPERIMENT_AGENT_TYPE"] = "llm"
os.environ["AICOMP_EXPERIMENT_PROMPT_PROFILE"] = "llm"
os.environ["AICOMP_EXPERIMENT_ENVIRONMENT"] = "kaggle_gym"
```

这组变量不会选择 Kaggle 模型。真实模型仍由 Gateway 的单模型配置决定。只有两侧配置一致且 gateway 日志确认模型后，记录才能作为真实 LLM baseline。

## 4. `AttackRunConfig` 兼容性

`ExperimentConfig` 不替代或修改 SDK `AttackRunConfig`：

- `AttackRunConfig.time_budget_s` 继续控制真实运行时预算；
- `AttackRunConfig.max_steps` 和 `max_tool_hops` 不变；
- `run()` 开始时，日志配置中的 `budget_s` 更新为实际 `time_budget_s`；
- trace 中存在 seed 时，记录使用实际 trace seed；否则使用声明 seed。

因此实验元数据不会改变 evaluator 的时间和工具调用约束。

## 5. `ExperimentRecord` schema

每条记录新增：

```json
{
  "timestamp": "2026-08-08T00:00:00Z",
  "backend": "gateway",
  "model_name": "gpt_oss",
  "agent_type": "llm",
  "prompt_profile": "llm",
  "seed": 123,
  "budget_s": 600.0,
  "probe_name": "H1_URL",
  "environment": "kaggle_gym",
  "trace": {},
  "tool_events": [],
  "predicate_result": [],
  "failure_category": []
}
```

字段说明：

- `timestamp`：UTC ISO-8601；
- `trace`：`env.export_trace_dict()` 的完整结果，包含 assistant response；
- `tool_events`：从同一 trace 提取的原始工具事件，便于流式分析；
- `predicate_result`：`eval_predicates()` 的完整结果；
- `failure_category`：与现有 `failure_reasons` 相同的分类列表；
- `probe_name`：H1-H8 使用 experiment id，默认搜索使用 chain/template 名称。

旧字段全部保留，包括 `experiment_id`、`tool_sequence`、`predicates`、`failure_reasons` 和 `trace_seed`，已有分析不会因 schema 扩展而失效。

## 6. 为什么旧 H1-H8 不能作为 LLM 结论

旧实验只设置了 `agent_type=llm`，但本地 evaluator 使用 `agent_selection=auto`。本地 GPT-OSS backend 不可用时，SDK 最终运行 deterministic agent。

因此旧记录只能证明：

- LLM PromptProfile 能被实验框架执行；
- trace、failure classification 和 JSONL 写入链路可用。

它们不能证明 GPT-OSS 或 Gemma 的 tool calling、拒绝、multi-step completion 或 predicate triggering 行为。

## 7. Phase 5.6.2 验证范围

本阶段只验证：

1. WSL Python 3.12 compile/import；
2. SDK validate；
3. deterministic 小预算测试；
4. 新字段可序列化并与旧字段共存。

不运行长时间 Kaggle evaluation，也不根据本地 deterministic trace 调整攻击策略。
