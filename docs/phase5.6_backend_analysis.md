# Phase 5.6.1 Backend Analysis

## 1. 范围与结论

本阶段只分析现有 `attack.py`、AIComp SDK 3.1.2 和仓库内 Kaggle evaluator，不增加攻击 prompt，也不修改攻击算法。

核心结论：

1. 本地 SDK CLI 和 Kaggle 比赛 evaluator 使用两条不同的 agent pipeline。
2. 本地 `agent_selection=auto` 会依次尝试本地 GPT-OSS、OpenAI、deterministic；本项目不使用 OpenAI，因此没有可加载的本地 GPT-OSS 时最终回退到 deterministic。
3. Kaggle 不依赖本地 `auto` 选择真实模型。Gateway 默认分别运行 `gpt_oss` 和 `gemma`，通过独立 GGUF model server 提供真实模型。
4. `attack.py` 的 `agent_type` 当前只选择 `PromptProfile`，不是 evaluator 实际 backend。过去记录中的 `agent_type=llm` 不能证明运行了 LLM。
5. 当前 Kaggle command-response 协议没有把 `model_name` 传入 `AttackAlgorithm`：`AttackSession` 固定执行 `attack_cls(config={})`。这是 Phase 5.6 实验闭环需要解决的主要元数据缺口。
6. 仓库内 gateway 源码的 `DEFAULT_BUDGET_S` 是 9000 秒。若 Kaggle Notebook 实际显示 8750 秒，差异来自当前仓库之外的 notebook/scorer 包装或 evaluator 版本，不能在 `attack.py` 中假设固定值。

## 2. 当前 `attack.py` 与实验框架

### 2.1 已有结构

当前工作区中的实验路径为：

```text
AttackAlgorithm(config)
  -> 根据 config/env 解析 agent_type
  -> agent_type 选择 DETERMINISTIC_PROFILE 或 LLM_PROFILE
  -> experiment_mode 选择 search 或 phase5_2_only
  -> H1-H8 VerificationSpec / 默认搜索计划
  -> env.reset() + env.interact()
  -> env.export_trace_dict()
  -> TraceAnalyzer / failure classification
  -> ExperimentRecord / ExperimentLogger
  -> Archive ranking
  -> list[AttackCandidate]
```

已有 `ExperimentRecord` 保存 prompt、工具摘要、拒绝、guardrail block、predicate、cell 和 failure reason，但存在三个 Phase 5.6 缺口：

- `agent_type` 是攻击侧声明，不是 evaluator 实际 backend。
- 记录没有独立的 `backend`、`model` 和稳定的 trace/run 标识。
- 记录只保存工具摘要，没有保存用于离线对比的完整 trace/assistant response。

### 2.2 当前配置入口

`AttackAlgorithm.__init__` 当前按以下顺序解析提示词 profile：

1. `config["agent_type"]`
2. `AICOMP_ATTACK_AGENT_TYPE`
3. `AICOMP_AGENT_TYPE`
4. 默认 `deterministic`

实验模式按以下顺序解析：

1. `config["experiment_mode"]`
2. `AICOMP_ATTACK_EXPERIMENT_MODE`
3. 默认 `search`

这两个入口可以保留兼容，但 Phase 5.6.2 应新增独立的 `ExperimentConfig`，避免继续混淆 prompt profile 与真实模型。

## 3. 本地 SDK agent pipeline

### 3.1 `agent_selection` 实际逻辑

本地 CLI 的 `--agent` 使用 `AgentSelection`，可选值为：

- `auto`
- `deterministic`
- `openai`（本项目禁用）
- `gpt_oss`
- `gemma`
- `gemma_4`

调用链：

```text
WSL CLI --agent
  -> cli.commands.options.add_shared_execution_arguments()
  -> cli.commands.test/evaluate
  -> evaluation.runner.evaluate_redteam()
  -> resolve_agent_factory()
  -> agents.factory.build_agent_factory()
  -> build_attack_env(agent_factory=...)
  -> AttackAlgorithm.run(opaque_env, AttackRunConfig)
```

`--agent` 控制 evaluator 中的 agent factory；它不会自动传入 `AttackAlgorithm(config)`，因此与攻击侧 `agent_type` 是两个独立配置面。

### 3.2 `auto` fallback 条件

SDK `_resolve_auto_factory()` 的顺序是：

```text
尝试 build_gpt_oss_backend()
  -> 成功：GPTOSSAgent
  -> RuntimeError：继续

检查 OPENAI_API_KEY
  -> 存在：OpenAIResponsesAgent
  -> 不存在：VulnerableDeterministicAgent
```

本项目明确不使用 OpenAI。GPT-OSS backend 默认 `local_files_only=True`；本地没有可用模型、Transformers 依赖或模型加载失败时通常抛出 `RuntimeError`，于是 `auto` 回退到 deterministic。

注意事项：

- `auto` 不会尝试 Gemma。
- `auto` 只捕获 GPT-OSS 构建过程中的 `RuntimeError`；其他异常可能直接终止，而不是回退。
- evaluation history 中的 `agent_selection` 记录的是请求值（如 `auto`），不是最终解析出的具体 backend，因此仅看 history 不能证明实际模型。
- 过去 trace 中固定的 `https://example.invalid/collect`、固定 `demo` payload 和重复 deterministic 工具行为，与该 fallback 一致。

### 3.3 本地强制 backend

WSL Python 3.12 的日常验证应显式使用 deterministic，避免误判：

```bash
source .venv/bin/activate
export PYTHONPATH="$PWD/data"
python -m aicomp_sdk.cli.main validate redteam attack.py
python -m aicomp_sdk.cli.main test redteam attack.py \
  --agent deterministic \
  --env gym \
  --budget-s 60
```

SDK 也支持强制 `--agent gpt_oss`、`--agent gemma` 或 `--agent gemma_4`。强制模式会直接构建对应 backend；模型不可用时应失败，而不会静默回退。模型路径入口为：

- GPT-OSS：`GPT_OSS_MODEL_PATH` / `GPT_OSS_MODEL_ID`
- Gemma 3：`GEMMA_MODEL_PATH` / `GEMMA_MODEL_ID`
- Gemma 4：`GEMMA4_MODEL_PATH` / `GEMMA4_MODEL_ID`

这些入口仅用于具备相应模型和算力时的本地诊断。本项目的真实 LLM baseline 以 Kaggle hosted model 为准，不要求在 WSL 下载模型。

## 4. Kaggle hosted model pipeline

### 4.1 模型选择

仓库内 `jed_attack_gateway.py` 默认：

```python
AICOMP_MODEL_NAMES = "gpt_oss,gemma"
```

模块导入时解析为 `MODEL_NAMES`。对受控的 Kaggle 开发 Notebook，可在导入 gateway 模块之前设置单模型值，例如 `gpt_oss` 或 `gemma`。正式 competition rerun 中 gateway/scorer 属于可信侧，模型集合可能由 Kaggle 控制，不能假设提交代码能够覆盖它。

Kaggle 模型映射：

| gateway 名称 | model server | agent 语义 | 默认模型/文件 |
|---|---|---|---|
| `gpt_oss` | `gpt_oss_model_server.py` | `GPTOSSAgent` | `openai/gpt-oss-20b`; `unsloth/gpt-oss-20b-GGUF/gpt-oss-20b-Q4_K_M.gguf` |
| `gemma` | `gemma_model_server.py` | `Gemma4Agent` (`backend_label=gemma_4`) | `google/gemma-4-26B-A4B-it`; `unsloth/gemma-4-26B-A4B-it-GGUF/gemma-4-26B-A4B-it-UD-Q4_K_M.gguf` |

这里的 Kaggle `gemma` 不是本地 CLI `--agent gemma` 所代表的 Gemma 3 4B。更接近的本地语义入口是 `--agent gemma_4`，但 Kaggle 使用 llama.cpp GGUF model server，而本地 SDK 默认使用 Transformers backend。

### 4.2 真实模型调用流程

```text
Kaggle Gateway（可信 evaluator 容器）
  -> 遍历 MODEL_NAMES: gpt_oss, gemma
  -> _make_agent_factory(model_name)
  -> RemoteAgent(model_server.predict)
  -> build_attack_env(..., env_selection="gym")

Kaggle Attack Inference Server（提交容器）
  -> 动态加载 attack.py
  -> 接收 init {budget_s, seed}
  -> AttackSession(attack_cls, budget_s, seed)
  -> attack_cls(config={})
  -> AttackAlgorithm.run(RemoteEnv, AttackRunConfig)

RemoteEnv command-response loop
  -> attack.py 请求 reset/interact/export_trace_dict
  -> gateway 在真实 GPT-OSS/Gemma env 中执行
  -> RemoteAgent 将 history + tool schema 发给 GGUF model server
  -> 模型返回 agent decision/tool call
  -> gateway 执行 tool、guardrail 和 trace 更新
  -> 结果返回 attack.py

评分
  -> attack.py 返回 AttackCandidate
  -> gateway 在同一模型上独立 replay
  -> eval_predicates(replayed_trace)
  -> public/private guardrail 分别计分
```

`attack.py` 不直接加载 GPT-OSS 或 Gemma，也不通过 `agent_selection=auto` 进入真实模型。它通过 `RemoteEnv.interact()` 间接驱动 gateway 中已经绑定的真实模型。

### 4.3 Kaggle 配置与当前缺口

当前 `init` 请求只包含：

```json
{
  "cmd": "init",
  "budget_s": 9000,
  "seed": 123
}
```

`AttackSession` 随后执行：

```python
self.attacker = attack_cls(config={})
self.config = AttackRunConfig(time_budget_s=budget_s)
```

因此：

- `model_name` 没有传入提交侧。
- `backend` 没有传入提交侧。
- `AttackAlgorithm` 在没有额外环境变量时仍选择 deterministic PromptProfile，即使 gateway 的真实 agent 是 GPT-OSS/Gemma。
- 单靠 `ExperimentRecord.agent_type` 不能建立模型归因。

在不修改正式 evaluator 协议的前提下，受控的单模型 Kaggle 快速实验应同时声明两组配置：

1. gateway 侧：单一 `AICOMP_MODEL_NAMES=gpt_oss` 或 `gemma`；
2. attack 侧：显式实验元数据和 LLM prompt profile，例如未来的 `AICOMP_EXPERIMENT_BACKEND=kaggle`、`AICOMP_EXPERIMENT_MODEL=gpt_oss`、`AICOMP_EXPERIMENT_PROMPT_PROFILE=llm`。

这些名称将在 Phase 5.6.2 统一实现。必须在记录中把“声明的模型”标识为 declared metadata；只有 gateway 日志/trace 能确认实际执行模型。对于正式 multi-model rerun，如果 scorer 不转发 `model_name`，提交侧记录应使用 `unknown`，不能伪造归因。

## 5. 本地测试流程与 Kaggle 流程差异

| 项目 | WSL 本地开发 | Kaggle 真实模型验证 |
|---|---|---|
| Python | WSL Ubuntu Python 3.12 | Kaggle competition runtime |
| 主要目的 | syntax、SDK、failure taxonomy、trace 分析、deterministic 回归 | GPT-OSS/Gemma 行为 baseline |
| agent 构建 | SDK `build_agent_factory(--agent)` | gateway `RemoteAgent` + 独立 GGUF model server |
| 推荐选择 | 显式 `deterministic` | 显式单模型 `gpt_oss` 或 `gemma`（快速模式） |
| `auto` | 可能静默回退 deterministic | 不参与 hosted model 路由 |
| environment | `sandbox` 或更接近比赛的 `gym` | 固定 `gym` |
| attack config | Python API 可传 `attack_config`; CLI `--agent` 不自动传入 | 当前固定 `attack_cls(config={})` |
| seed | SDK options/默认 123 | gateway 默认 123，`init` 转发 |
| budget | CLI `--budget-s` | gateway 源码默认每个 generation/replay 9000 秒；实际 notebook 可能为 8750 秒 |
| trace | 本地可完整输出 transcript/event/debug JSONL | attack trace 经 RemoteEnv 返回；gateway 也打印 assistant/tool 摘要 |
| 模型归因 | CLI 请求值可知，`auto` 的最终 backend 不透明 | gateway 知道 `model_name`，attack.py 当前不知道 |

## 6. Phase 5.6 实验流程整理

### 6.1 本地开发门

每次修改先执行：

1. WSL Python 3.12 syntax/import validation；
2. deterministic + gym 小预算回归；
3. 验证 H1-H8 数量、JSONL schema、failure classification；
4. 不把本地 deterministic 结果标记成真实 LLM。

### 6.2 Kaggle 最小验证门

Phase 5.6.3 的快速模式应满足：

1. 一次只运行一个 hosted model；
2. 先运行 1 个已有 probe，再扩到 H1-H8；
3. 攻击侧内部停止条件小于 evaluator 总预算；
4. 同时保留 gateway 模型标识、assistant response、tool events、predicate 和 failure；
5. 首条 trace 必须与 deterministic trace 有可观察差异，才继续扩大实验；
6. 不新增 prompt，不依据单次 trace 调整攻击方向。

模型加载本身可能占用数分钟，因此“5-10 分钟”是快速验证目标，不是 `attack.py` 可保证的硬时限。

### 6.3 H1-H8 baseline 门

只有以下条件同时满足时，记录才可进入 `phase5_6_llm_records.jsonl`：

- backend/model 明确且不是 `auto`；
- prompt profile 明确；
- trace 含 assistant response 和 tool events；
- seed、budget、probe、timestamp、trace id 可追踪；
- predicate 与 failure category 来自同一条 trace；
- gateway 日志能证明实际运行 GPT-OSS 或 Gemma。

## 7. Phase 5.6.2 实现边界

下一步应做小范围配置重构，不改 H1-H8 文本和攻击搜索逻辑：

1. 新增 `ExperimentConfig`，分离：
   - `backend`
   - `model_name`
   - `prompt_profile`
   - `seed`
   - `budget`
   - `probes`
2. 保留现有 `agent_type`/`experiment_mode` 兼容入口。
3. 采用“constructor mapping > Phase 5.6 专用环境变量 > 安全默认值”的解析顺序。
4. `ExperimentRecord` 新增 backend/model/probe/timestamp/trace_id/trace/tool_events/predicate_result/failure_type；旧字段不删除。
5. backend/model 缺失时记录 `unknown`，禁止根据 `prompt_profile=llm` 推断实际模型。
6. 先用 deterministic 本地回归验证 schema，再进入 Kaggle 单模型最小实验。

## 8. Phase 6 决策约束

Phase 6 的 Exfiltration、Confused Deputy、Context Drift、Tool Misuse 方向必须由真实 GPT-OSS/Gemma trace 支持。在 H1-H8 的真实 baseline 完成前，不增加 prompt 数量，也不预选攻击方向。

## 9. 审查依据

- `attack.py`
- `data/aicomp_sdk/agents/factory.py`
- `data/aicomp_sdk/agents/gpt_oss_agent.py`
- `data/aicomp_sdk/agents/gemma_agent.py`
- `data/aicomp_sdk/agents/gemma4_agent.py`
- `data/aicomp_sdk/agents/hf_chat_template/backends/transformers.py`
- `data/aicomp_sdk/cli/commands/options.py`
- `data/aicomp_sdk/cli/commands/test.py`
- `data/aicomp_sdk/evaluation/runner.py`
- `data/aicomp_sdk/evaluation/ops.py`
- `data/kaggle_evaluation/jed_attack_134815/jed_attack_gateway.py`
- `data/kaggle_evaluation/jed_attack_134815/jed_attack_inference_server.py`
- `data/kaggle_evaluation/jed_attack_134815/remote_agent.py`
- `data/kaggle_evaluation/jed_attack_134815/remote_env.py`
- `data/kaggle_evaluation/jed_attack_134815/gpt_oss_model_server.py`
- `data/kaggle_evaluation/jed_attack_134815/gemma_model_server.py`
- `data/kaggle_evaluation/jed_attack_134815/gguf_model_server.py`
