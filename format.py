import glob
import os
import sys
from pathlib import Path

# 定位比赛 SDK input
competition_roots = [
    str(Path(path).parent)
    for path in glob.glob("/kaggle/input/**/kaggle_evaluation", recursive=True)
]
if not competition_roots:
    raise RuntimeError("Competition SDK input was not mounted")
if competition_roots[0] not in sys.path:
    sys.path.insert(0, competition_roots[0])
print(f"Competition root: {competition_roots[0]}")


# -----------------------------------------------------------------------------

%%writefile /kaggle/working/attack.py

# code here


# -----------------------------------------------------------------------------

import os, csv
if os.getenv('KAGGLE_IS_COMPETITION_RERUN'):
    import kaggle_evaluation.jed_attack_134815.jed_attack_inference_server as server
    server.JEDAttackInferenceServer().serve()
else:
    with open('/kaggle/working/submission.csv', 'w', newline='') as fh:
        w = csv.writer(fh); w.writerow(['Id', 'Score'])
        w.writerows([['gpt_oss_public', 0.0], ['gpt_oss_private', 0.0], ['gemma_public', 0.0], ['gemma_private', 0.0]])
    print('placeholder submission.csv written. Set GPU T4 x2, Internet Off, then Submit.')