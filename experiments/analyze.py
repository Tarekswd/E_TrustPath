"""Summarise TrustPath raw.csv: mean and 95% t-confidence interval across seeds for each configuration.
Stdlib only; plots need matplotlib and are skipped without it.

Usage: python experiments/analyze.py <raw.csv> <out_dir>
"""
import csv
import math
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

# two-sided 95% Student-t critical values by degrees of freedom (from standard tables)
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
       14: 2.145, 19: 2.093, 29: 2.045}
METRICS = ("delivery_ratio", "exposure", "median_stretch", "median_stretch_real", "fake_link_paths", "copies_per_flow", "trust_precision", "trust_recall",
           "honest_trust_mean", "malicious_trust_mean", "fake_reports_accepted",
           "agree_weight_to_attackers", "agree_weight_to_honest")
KEYS = {
    "A_fraction": ("net_malicious_frac", "strategy"),
    "B_attribution": ("strategy", "attribution"),
    "C_sybil": ("net_sybils", "report_policy", "strategy"),
    "D_crash": ("strategy",),
    "E_decay": ("trust_decay", "strategy"),
    "F_explore": ("explore", "strategy"),
}


def t95(df):
    return T95.get(df) or T95[max(k for k in T95 if k <= df)]


def ci(xs):
    xs = [x for x in xs if not math.isnan(x)]
    if len(xs) < 2:
        return (xs[0] if xs else float("nan")), float("nan")
    return st.fmean(xs), t95(len(xs) - 1) * st.stdev(xs) / math.sqrt(len(xs))


def main(raw, out):
    rows = list(csv.DictReader(open(raw, newline="")))
    out = Path(out)
    lines = ["# TrustPath results (SIMULATED)\n", f"Source `{Path(raw).name}`: {len(rows)} runs. Cells: mean +/- 95% CI half-width across seeds.\n"]
    table = defaultdict(dict)
    for scen, keys in KEYS.items():
        groups = defaultdict(list)
        for r in rows:
            if r["scenario"] == scen:
                groups[tuple(r[k] for k in keys)].append(r)
        if not groups:
            continue
        lines += [f"\n## {scen}\n", "| " + " | ".join(keys + ("n",) + METRICS) + " |", "|" + "---|" * (len(keys) + 1 + len(METRICS))]
        for g in sorted(groups):
            cells = []
            for m in METRICS:
                mean, h = ci([float(r[m]) for r in groups[g]])
                table[(scen,) + g][m] = mean
                cells.append(f"{mean:.3f} +/- {h:.3f}" if not math.isnan(h) else f"{mean:.3f}")
            lines.append("| " + " | ".join(list(g) + [str(len(groups[g]))] + cells) + " |")
    sy = [r for r in rows if r["scenario"] == "C_sybil"]
    if sy:
        lines.append("\nSybil identities (requested=admitted): " + ", ".join(sorted({f"{r['net_sybils']}={r['sybils_admitted']}" for r in sy})))
    lines.append("\nForged (impersonation) ads rejected per run: " + ", ".join(sorted({r['rejected_ads'] for r in rows}, key=int)))
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    print((out / "summary.md").read_text())

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping plot")
        return
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
    for ax, m, label in zip(axes, ("delivery_ratio", "exposure"), ("delivery ratio", "paths through attacker")):
        for stg in ("shortest", "reliability", "trust", "trust_multi"):
            pts = sorted((float(k[1]), v[m]) for k, v in table.items() if k[0] == "A_fraction" and k[2] == stg)
            if pts:
                ax.plot([p[0] for p in pts], [p[1] for p in pts], marker="o", label=stg)
        ax.set_xlabel("fraction of malicious nodes")
        ax.set_ylabel(f"{label} (simulated)")
        ax.grid(alpha=0.3)
    axes[0].legend(fontsize=8)
    fig.suptitle("TrustPath scenario A: 100-node random geometric topologies")
    fig.tight_layout()
    fig.savefig(out / "scenario_A.png", dpi=130)
    print(f"wrote {out / 'scenario_A.png'}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
