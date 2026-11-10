"""Compare naive_all, naive_step and cumulative gating; write results/results.json.

    python evals/run_eval.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from riskgate.scenarios import all_chains  # noqa: E402
from riskgate.simulate import run  # noqa: E402

POLICIES = ["naive_all", "naive_step", "cumulative"]
KEYS = [
    "detection_rate",
    "chain_signal_rate",
    "harm_prevented_rate_simulated_reviewer",
    "total_prompts",
    "approvals_per_hour",
    "benign_prompts_per_chain",
    "benign_chain_false_alarms",
    "rubber_stamp_rate_simulated",
    "mean_time_to_approve_s_simulated",
    "reapproval_scope_change",
    "reapproval_expired",
]


def main() -> None:
    chains = all_chains()
    res = {p: run(chains, p) for p in POLICIES}
    fam = {}
    for p in POLICIES:
        f: dict = {}
        for r in res[p]["rows"]:
            if r["harmful"]:
                d = f.setdefault(r["family"], [0, 0])
                d[0] += (
                    r["chain_signal_at_harm_step"]
                    if p == "cumulative"
                    else r["prompted_at_harm_step"]
                )
                d[1] += 1
        fam[p] = {k: f"{v[0]}/{v[1]}" for k, v in sorted(f.items())}
    res["per_family"] = fam
    out = ROOT / "results" / "results.json"
    out.write_text(json.dumps(res, indent=2))
    print(
        f"chains: {res['cumulative']['n_harmful']} harmful, {res['cumulative']['n_benign']} benign"
    )
    for p in POLICIES:
        print(p, {k: res[p][k] for k in KEYS})
    print(json.dumps(fam, indent=1))


if __name__ == "__main__":
    main()
