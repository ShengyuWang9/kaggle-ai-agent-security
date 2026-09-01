# Kaggle AI Agent Security - Multi-Step Tool Attacks

This repository is a research and competition workspace for Kaggle's **AI Agent Security - Multi-Step Tool Attacks** challenge. It preserves the main attack implementation alongside historical variants, scheduler experiments, hosted-evaluator experiments, local validation material, analysis documents, and experiment records.

All work is intended for the competition's controlled evaluation environment. The repository documents security research and experiment history; it is not a guide for attacking real-world systems.

## Repository Structure

```text
attack.py                 Main Kaggle AttackAlgorithm implementation
attacks/                  Historical and experimental attack variants
data/                     Competition SDK, evaluator, and local project data
docs/                     Analysis, designs, configuration, and validation notes
notebooks/                Kaggle and hosted-validation notebooks
scripts/                  Validation, trace-analysis, notebook-build, and environment helpers
logs/                     Preserved experiment records
result/                   Historical evaluator and experiment result files
DeepThink.py              Standalone reasoning-boundary/evaluator experiment
LOCAL_SETUP.md            Complete local-environment guide
requirements.txt          Python dependencies
```

### Main and supporting implementations

- [`attack.py`](attack.py) is the main Kaggle `AttackAlgorithm` implementation. It retains a legacy baseline/comparison path while also containing later adaptive scheduling and scheduling-budget experiments. The historical 41.7 baseline/legacy path is an experimental reference point, not a score claim for the current `attack.py`.
- [`attacks/`](attacks/) contains preserved variants such as `attackV1.py`, `attackV1.1.py`, `attackV2.py`, `attackV2Impro.py`, `attack7.py`, `attackGuantouyu.py`, and `attackMerge.py`. These support static comparison, experiment records, and strategy evolution; they are not all final submissions.
- [`DeepThink.py`](DeepThink.py) is an independent experiment for reasoning-boundary and evaluator-behavior hypotheses. It is not the default production entry point.
- [`data/`](data/) contains competition SDK/evaluator-related local project data. It does not imply that a hosted model must be downloaded locally to make a submission.

### Research and experiment material

The [`docs/`](docs/) directory holds attack analysis, algorithm comparisons, agent-capability profiling, phase designs, experiment configuration, and hosted/real-LLM validation notes. Useful starting points include:

- [Attack analysis](docs/attack_analysis.md)
- [Attack algorithm comparison](docs/attack_algorithms_comparison.md)
- [Agent capability profiling](docs/agent_capability_profiling.md)
- [Phase 5.6 experiment configuration](docs/phase5.6_experiment_config.md)
- [Kaggle real-LLM validation](docs/phase5.6.3_kaggle_real_llm_validation.md)

[`notebooks/`](notebooks/) contains Kaggle/hosted-validation notebooks. [`scripts/`](scripts/) contains supporting validation, trace-analysis, notebook-build, and environment-verification utilities. [`logs/`](logs/) and [`result/`](result/) are intentionally retained experiment records; their files may refer to different algorithm revisions and evaluator configurations, so they should not be treated as one directly comparable result set.

## Competition Execution Model

The core Kaggle submission artifact is `/kaggle/working/attack.py`. It must provide `AttackAlgorithm(AttackAlgorithmBase)` and return `list[AttackCandidate]`. The hosted evaluator/competition environment executes and replays those candidates; that evaluation is the basis for leaderboard scores.

Local testing is useful for SDK validation, deterministic environment checks, debugging, and candidate-generation sanity checks. It is not a substitute for hosted/Kaggle evaluation, and submitting does not require downloading GPT-OSS, Gemma, or another hosted model locally.

## Current Algorithm Architecture

At a high level, the current `attack.py` combines:

- deterministic candidate construction across scenario families;
- live predicate validation and family-level statistics;
- adaptive scheduling with latency-aware ranking;
- replay-budget accounting and deadline-aware stopping;
- predicate-coverage considerations; and
- a legacy fallback/comparison path.

This is an engineering-level description only; the repository does not reproduce attack prompts or payloads in this README.

## Experimental History

The repository intentionally preserves multiple stages of work:

```text
Baseline -> V1/V1.1 -> V2 -> composite/merged experiments
         -> adaptive scheduling experiments -> reasoning-boundary experiments
```

Version numbers are not a leaderboard ranking. Later experiments do not necessarily score higher than earlier ones: some were retained to test a hypothesis even when they did not improve a final evaluation outcome.

## Results

Results in this repository must be read in context. Distinguish historical leaderboard results, local deterministic tests, hosted-evaluator experiments, and experimental-branch output. In particular, any 41.7 reference is a historical baseline/reference, not evidence that the current `attack.py` has that leaderboard score. The files under [`result/`](result/) are preserved records rather than a single current benchmark.

## Quick Start

Use Python 3.12:

```bash
python -m venv .venv
source .venv/bin/activate  # use the equivalent activation command on Windows
python -m pip install -r requirements.txt
export PYTHONPATH="$PWD/data"  # PowerShell: $env:PYTHONPATH = "$PWD\\data"

python -m aicomp_sdk.cli.main validate redteam attack.py
python -m aicomp_sdk.cli.main test redteam attack.py
```

See [LOCAL_SETUP.md](LOCAL_SETUP.md) for the complete local environment guide.

## Repository Hygiene

Do not commit local-only or temporary material such as:

- `.venv/`
- `.aicomp/`
- `evaluation_artifacts/`
- temporary logs or caches

The committed [`logs/`](logs/) and [`result/`](result/) directories are intentional experiment records; they are distinct from ignored temporary `.log` files.
