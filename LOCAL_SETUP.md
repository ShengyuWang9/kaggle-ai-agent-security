# Kaggle AI Agent Security — Local Environment Guide

> Project: AI Agent Security - Multi-Step Tool Attacks
> SDK: `aicomp_sdk 3.1.2`
>
> **重要：这个项目目前在两台不同的 Windows 电脑上开发，两台电脑的 Python 环境不同。不要混用下面的运行方式。**

---

# 1. 两台电脑的环境区别

## Computer A — Windows + WSL Ubuntu

这台电脑的 Windows 原生 Python 是：

```text
Python 3.14.x
```

**不要使用 Windows PowerShell 中的 Python 3.14 直接运行 Kaggle SDK。**

这台电脑之前能够正常运行项目，是因为使用：

```text
Windows
└── WSL / Ubuntu
    └── Python 3.12
        └── Kaggle project
```

项目在 Windows 中的位置：

```text
D:\Documents\kaggle_competition\kaggle-ai-agent-security
```

对应 WSL 路径：

```text
/mnt/d/Documents/kaggle_competition/kaggle-ai-agent-security
```

因此这台电脑应当：

**使用 WSL Ubuntu + Python 3.12。**

---

## Computer B — Windows Native Python 3.12

另一台电脑已经安装：

```text
Python 3.12.x
```

因此可以直接：

```text
Windows PowerShell
└── Python 3.12
    └── .venv
        └── Kaggle project
```

这台电脑可以直接使用 PowerShell 运行比赛。

---

# 2. 为什么 `.venv\Scripts\Activate.ps1` 有时不存在

如果 `.venv` 是在 WSL / Linux 中创建的，它的结构是：

```text
.venv/
├── bin/
│   ├── activate
│   └── python
└── lib/
```

激活方式：

```bash
source .venv/bin/activate
```

Windows 创建的 virtual environment 则是：

```text
.venv/
├── Scripts/
│   ├── Activate.ps1
│   └── python.exe
└── Lib/
```

激活方式：

```powershell
.\.venv\Scripts\Activate.ps1
```

因此：

```powershell
.\.venv\Scripts\Activate.ps1
```

出现：

```text
无法识别 .\.venv\Scripts\Activate.ps1
```

并不一定表示 `.venv` 损坏。

有可能只是：

> 这个 `.venv` 原本是 WSL/Linux 创建的 virtual environment。

---

# 3. Computer A：WSL Ubuntu 运行方式

## 进入 WSL

PowerShell：

```powershell
wsl
```

进入项目：

```bash
cd /mnt/d/Documents/kaggle_competition/kaggle-ai-agent-security
```

---

## 检查 Python

```bash
python3.12 --version
```

应看到：

```text
Python 3.12.x
```

---

## 第一次创建环境

如果 `.venv` 不存在：

```bash
python3.12 -m venv .venv
```

如果出现 `ensurepip` / `python3.12-venv` 缺失：

```bash
sudo apt update
sudo apt install python3.12-venv
```

然后重新：

```bash
python3.12 -m venv .venv
```

---

## 激活

```bash
source .venv/bin/activate
```

确认：

```bash
python --version
```

应为：

```text
Python 3.12.x
```

---

## 安装依赖

第一次运行：

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

如果 SDK 报：

```text
ModuleNotFoundError: No module named 'pydantic'
```

执行：

```bash
python -m pip install "pydantic>=2"
```

---

## 设置 SDK 路径

每次新终端：

```bash
export PYTHONPATH="$PWD/data"
```

检查：

```bash
python -c "import aicomp_sdk; print('SDK OK')"
```

应输出：

```text
SDK OK
```

---

## Validate

```bash
python -m aicomp_sdk.cli.main validate redteam attack.py
```

正常结果：

```text
Valid Python syntax
All imports look valid
Valid attack structure
Validation passed
```

---

## 本地快速测试

```bash
python -m aicomp_sdk.cli.main test redteam attack.py
```

---

## 更接近 Kaggle 环境的测试

推荐：

```bash
python -m aicomp_sdk.cli.main test redteam attack.py \
  --budget-s 60 \
  --agent deterministic \
  --env gym
```

或者：

```bash
python -m aicomp_sdk.cli.main evaluate redteam attack.py \
  --budget-s 60 \
  --agent deterministic \
  --env gym
```

`gym` 比默认的本地 `sandbox` 更接近 Kaggle 公共评测环境。

---

# 4. Computer B：Windows Python 3.12 运行方式

打开 PowerShell：

```powershell
cd D:\Documents\kaggle_competition\kaggle-ai-agent-security
```

检查：

```powershell
python --version
```

必须确认：

```text
Python 3.12.x
```

---

## 第一次创建环境

```powershell
python -m venv .venv
```

激活：

```powershell
.\.venv\Scripts\Activate.ps1
```

---

## 安装依赖

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

如果缺少 Pydantic：

```powershell
python -m pip install "pydantic>=2"
```

---

## 设置 SDK 路径

每次打开新的 PowerShell：

```powershell
$env:PYTHONPATH = "$PWD\data"
```

检查：

```powershell
python -c "import aicomp_sdk; print('SDK OK')"
```

---

## Validate

```powershell
python -m aicomp_sdk.cli.main validate redteam attack.py
```

---

## 本地测试

```powershell
python -m aicomp_sdk.cli.main test redteam attack.py
```

---

## Kaggle-style local test

```powershell
python -m aicomp_sdk.cli.main test redteam attack.py --budget-s 60 --agent deterministic --env gym
```

或者：

```powershell
python -m aicomp_sdk.cli.main evaluate redteam attack.py --budget-s 60 --agent deterministic --env gym
```

---

# 5. Computer A 不要这样运行

Computer A 的 Windows 原生 Python 当前为：

```text
Python 3.14.x
```

因此不要在 PowerShell 中：

```powershell
python -m venv .venv
```

然后使用 Python 3.14 跑比赛。

即使部分 SDK 能够运行，也可能产生：

* SDK 依赖兼容问题
* PyTorch compatibility 问题
* grpc / protobuf 问题
* evaluation environment 差异
* WSL `.venv` 被 Windows `.venv` 覆盖

Computer A 应直接进入：

```powershell
wsl
```

然后使用 Ubuntu Python 3.12。

---

# 6. 非常重要：不要跨系统复用 `.venv`

不要：

```text
WSL 创建 .venv
↓
Windows PowerShell 使用同一个 .venv
```

也不要：

```text
Windows 创建 .venv
↓
WSL 使用同一个 .venv
```

virtual environment 是平台相关的。

Linux：

```text
.venv/bin/python
```

Windows：

```text
.venv\Scripts\python.exe
```

所以 `.venv`：

* 不上传 Git
* 不在不同电脑之间同步
* 不在 Windows / WSL 之间共享

每个系统自己创建。

建议 `.gitignore` 至少包含：

```gitignore
.venv/
.venv-*/
__pycache__/
*.pyc
```

---

# 7. 日常运行速查

## Computer A

```powershell
wsl
```

然后：

```bash
cd /mnt/d/Documents/kaggle_competition/kaggle-ai-agent-security
source .venv/bin/activate
export PYTHONPATH="$PWD/data"

python -m aicomp_sdk.cli.main validate redteam attack.py
python -m aicomp_sdk.cli.main test redteam attack.py
```

---

## Computer B

```powershell
cd D:\Documents\kaggle_competition\kaggle-ai-agent-security

.\.venv\Scripts\Activate.ps1

$env:PYTHONPATH = "$PWD\data"

python -m aicomp_sdk.cli.main validate redteam attack.py
python -m aicomp_sdk.cli.main test redteam attack.py
```

---

# 8. Local Test、Gym Test 与 Kaggle Score

三个概念不要混在一起。

## Level 1 — Validate

```text
validate
```

只确认：

* Python syntax
* imports
* AttackAlgorithm structure
* submission compatibility

它不表示攻击有效。

---

## Level 2 — Local Sandbox Test

```bash
aicomp test redteam attack.py
```

默认主要用于本地开发和 smoke test。

例如：

```text
Env selection: sandbox

Findings: 0
Unique cells: 0
Attack Score: 0.00
```

说明：

> 当前 attack.py 在这次本地 sandbox evaluation 中没有触发可计分 predicate。

它不代表代码运行失败。

---

## Level 3 — Local Gym Test

推荐进一步运行：

```bash
aicomp test redteam attack.py \
  --budget-s 60 \
  --agent deterministic \
  --env gym
```

`gym` 的环境行为更接近 Kaggle 公共评测。

---

## Level 4 — Kaggle Hosted Evaluation

真正想知道：

```text
Public Score
```

最终仍然必须把 `attack.py` 放进 Kaggle 的比赛提交 / Notebook evaluation 流程。

线上评测才包含 Kaggle 托管 evaluator 的真实环境。

因此推荐工作流：

```text
修改 attack.py
      ↓
validate
      ↓
local sandbox smoke test
      ↓
local gym test
      ↓
确认没有异常
      ↓
Kaggle Notebook / Hosted Submission
      ↓
Public Score
      ↓
根据结果继续迭代
```

不要每改一行就上传 Kaggle。

本地环境负责：

```text
debug + structure + quick iteration
```

Kaggle 环境负责：

```text
true hosted evaluation + leaderboard score
```

---

# 9. 当前已确认状态 — 2026-08-07

本轮 Computer A 曾错误地使用 Windows Python：

```text
Python 3.14.6
```

并重新创建了 Windows `.venv`。

补充：

```powershell
python -m pip install "pydantic>=2"
```

之后：

```text
SDK OK
```

Validate：

```text
Validation passed
```

Test：

```text
Env selection: sandbox
Evaluation complete: 0.7s

Attack Score: 0.00
Findings: 0
Unique cells: 0
Raw score: 0.00
```

因此：

```text
SDK          ✅
imports      ✅
attack.py    ✅ structurally valid
evaluator    ✅ successfully ran
finding      ❌ none in this local sandbox run
```

随后已经删除了这个错误创建的 Windows Python 3.14 `.venv`。

Computer A 后续恢复：

```text
WSL Ubuntu + Python 3.12
```

Computer B 继续：

```text
Windows Native + Python 3.12
```

---

# 10. 一句话记忆

```text
Computer A = WSL Ubuntu + Python 3.12
Computer B = Windows PowerShell + Python 3.12

Python 3.14 ≠ 当前 Kaggle 开发环境

Local 0 score ≠ 程序运行失败
Local test ≠ Kaggle Public Score
```
