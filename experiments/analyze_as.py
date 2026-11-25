"""Summarise AS-level raw.csv: mean +/- 95% t-CI half-width across seeds per configuration.

Usage: python experiments/analyze_as.py <raw.csv> <out_dir>
"""
import csv
import math
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze import ci  # noqa: E402

KEYS = ("adopt_frac", "policy", "attacker", "mal_placement", "mal_frac", "receipt_frac", "receipt_placement", "multipath")
METRICS = ("delivery_adopters", "delivery_others", "adopter_gain", "delivery_all", "exposure_adopters",
           "exposure_others", "loc_auc", "loc_auc_mle", "mean_hops")


def main(raw, out):
    rows = list(csv.DictReader(open(raw, newline="")))
    for r in rows:
        a, o = float(r["delivery_adopters"]), float(r["delivery_others"])
        r["adopter_gain"] = a - o  # NaN when one group is empty
    varying = [k for k in KEYS if len({r[k] for r in rows}) > 1]
    metrics = [m for m in METRICS if m in rows[0]]  # loc_auc_mle is missing from the T1/T2 runs
    groups = defaultdict(list)
    for r in rows:
        groups[tuple(r[k] for k in varying)].append(r)
    lines = ["# TrustPath AS-level results (SIMULATED)\n",
             f"Source `{Path(raw).name}`: {len(rows)} runs, {rows[0]['n_ases']} ASes. Cells: mean +/- 95% CI half-width across seeds.\n",
             "| " + " | ".join(varying + ["n"] + metrics) + " |", "|" + "---|" * (len(varying) + 1 + len(metrics))]
    for g in sorted(groups, key=lambda t: tuple(float(x) if x.replace(".", "").isdigit() else x for x in t)):
        cells = []
        for m in metrics:
            mean, h = ci([float(r[m]) for r in groups[g]])
            cells.append("nan" if math.isnan(mean) else (f"{mean:.3f} +/- {h:.3f}" if not math.isnan(h) else f"{mean:.3f}"))
        lines.append("| " + " | ".join(list(g) + [str(len(groups[g]))] + cells) + " |")
    (Path(out) / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
