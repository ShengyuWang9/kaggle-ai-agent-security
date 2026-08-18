"""Build the attackV2 Kaggle submission notebook (legacy 194-chain search)."""

from __future__ import annotations

import argparse
from pathlib import Path

import nbformat


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "notebooks" / "phase5_6_gpt_oss_validation.ipynb"


def build_notebook(attack_source: str) -> nbformat.NotebookNode:
    notebook = nbformat.v4.new_notebook()
    notebook["metadata"].update(
        {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {"name": "python", "version": "3"},
            "kaggle": {
                "accelerator": "gpu",
                "dataSources": [
                    {
                        "sourceId": 134815,
                        "sourceType": "competition",
                    }
                ],
                "isInternetEnabled": False,
            },
        }
    )
    notebook["cells"] = [
        nbformat.v4.new_markdown_cell(
            """# attackV2: Kaggle submission (legacy search, 194 chains)

Runs the full legacy 194-chain search against both Gateway models
(GPT-OSS and Gemma 4) within the evaluator-provided 9000s budget.

Key changes vs the failed attack7 run:
- `AICOMP_ATTACK_EXPERIMENT_MODE` is NOT set to `phase5_6_lightweight`
  (that mode disabled template search and ran a single H1_URL probe).
- `AICOMP_SEARCH_PROFILE=legacy` enables the full 194-chain plan.
- T1 direct exfiltration chains (read secret -> post SECRET_MARKER) run
  first; every unique URL yields a distinct score cell (+2 raw bonus)."""
        ),
        nbformat.v4.new_code_cell(
            """import glob
import os
import sys
from pathlib import Path

# These values must be set before importing the inference server/gateway.
os.environ["AICOMP_MODEL_NAMES"] = "gpt_oss"
os.environ["AICOMP_SEARCH_PROFILE"] = "legacy"
os.environ["AICOMP_EXPERIMENT_BACKEND"] = "gateway"
os.environ["AICOMP_EXPERIMENT_MODEL"] = "gpt_oss"
os.environ["AICOMP_EXPERIMENT_AGENT_TYPE"] = "llm"
os.environ["AICOMP_EXPERIMENT_PROMPT_PROFILE"] = "llm"
os.environ["AICOMP_EXPERIMENT_SEED"] = "123"
os.environ["AICOMP_EXPERIMENT_ENVIRONMENT"] = "kaggle_gym"

sys.argv = [sys.argv[0]]
competition_roots = [
    str(Path(path).parent)
    for path in glob.glob("/kaggle/input/**/kaggle_evaluation", recursive=True)
]
if not competition_roots:
    raise RuntimeError("Competition SDK input was not mounted")
if competition_roots[0] not in sys.path:
    sys.path.insert(0, competition_roots[0])

print(f"Competition root: {competition_roots[0]}")
print("Gateway model: gpt_oss")
print("Experiment: search / legacy 194 chains / evaluator budget")"""
        ),
        nbformat.v4.new_code_cell(
            "%%writefile /kaggle/working/attack.py\n" + attack_source
        ),
        nbformat.v4.new_code_cell(
            """from pathlib import Path

attack_path = Path("/kaggle/working/attack.py")
compile(attack_path.read_text(encoding="utf-8"), str(attack_path), "exec")
print(f"attack.py compile: PASS ({attack_path.stat().st_size} bytes)")"""
        ),
        nbformat.v4.new_code_cell(
            """import csv
import os

if os.getenv("KAGGLE_IS_COMPETITION_RERUN"):
    from kaggle_evaluation.jed_attack_134815 import jed_attack_inference_server

    server = jed_attack_inference_server.JEDAttackInferenceServer()
    server.serve()
else:
    submission_path = "/kaggle/working/submission.csv"
    with open(submission_path, "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Id", "Score"])
        writer.writerows([
            ["gpt_oss_public", 0.0],
            ["gpt_oss_private", 0.0],
            ["gemma_public", 0.0],
            ["gemma_private", 0.0],
        ])
    print(f"Placeholder written: {submission_path}")
    print("Save Version should finish quickly; real scoring starts after Submit to Competition.")"""
        ),
        nbformat.v4.new_code_cell(
            """from pathlib import Path

submission_path = Path("/kaggle/working/submission.csv")
if not os.getenv("KAGGLE_IS_COMPETITION_RERUN"):
    if not submission_path.exists():
        raise FileNotFoundError(submission_path)
    print("Notebook smoke run: PASS")
    print("Next step: Save Version, then Submit to Competition to get the Public Score.")"""
        ),
    ]
    return notebook


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    attack_source = (REPO_ROOT / "attackV2.py").read_text(encoding="utf-8")
    notebook = build_notebook(attack_source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    nbformat.write(notebook, args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
