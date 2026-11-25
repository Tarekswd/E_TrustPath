"""H-T3 (partial receipts) on the T3 grid. Mean over 30 seeds, 95% t-CI.

    python experiments/hypothesis_t3.py results/as-T3-30seeds/raw.csv

For each attacker setting and receipt placement it reports, per receipt fraction g:
  - AUC, both metrics (loc_auc = posterior mean, pre-registered; loc_auc_mle = failure share, no prior)
  - lift = AUC(attack) - AUC(placebo: same placement and g, attackers never drop), paired by seed
  - recovered = (lift_g - lift_0) / (lift_1 - lift_0): share of the full-deployment improvement (pre-registered
    criterion: >= 0.8 at a small top-placed g)
"""
import csv
import math
import statistics as st
import sys
from collections import defaultdict

T95 = 2.045
GS = ("0.0", "0.01", "0.05", "0.1", "0.25", "1.0")


def ci(xs):
    m = st.mean(xs)
    return m, T95 * st.stdev(xs) / math.sqrt(len(xs))


def main(raw):
    cell = defaultdict(dict)  # (mal_place, attacker, drop, rp, g) -> seed -> row
    for r in csv.DictReader(open(raw, newline="")):
        cell[(r["mal_placement"], r["attacker"], r["drop"], r["receipt_placement"], r["receipt_frac"])][r["seed"]] = r
    settings = sorted({k[:3] for k in cell if k[2] != "0.0"})
    for metric in ("loc_auc", "loc_auc_mle"):
        print(f"\n## {metric}\n")
        for mp, att, drop in settings:
            for rp in ("top", "random"):
                lift = {}
                for g in GS:
                    a, p = cell[(mp, att, drop, rp, g)], cell[(mp, "always", "0.0", rp, g)]
                    lift[g] = [float(a[s][metric]) - float(p[s][metric]) for s in a]
                full = st.mean(lift["1.0"]) - st.mean(lift["0.0"])
                parts = []
                for g in GS:
                    auc = ci([float(r[metric]) for r in cell[(mp, att, drop, rp, g)].values()])
                    lm, lh = ci(lift[g])
                    rec = (lm - st.mean(lift["0.0"])) / full if abs(full) > 0.02 else float("nan")
                    parts.append(f"g={g}: {auc[0]:.3f} (lift {lm:+.3f}+/-{lh:.3f}, rec {rec:.2f})")
                print(f"attackers {mp:6} {att:11} drop={drop} | receipts {rp:6} | " + "; ".join(parts))
    print("\n## delivery_all (does localisation feed back into delivery?)\n")
    for mp, att, drop in settings:
        for rp in ("top", "random"):
            print(f"{mp:6} {att:11} drop={drop} receipts {rp:6} | " + "  ".join(
                f"g={g}: {ci([float(r['delivery_all']) for r in cell[(mp, att, drop, rp, g)].values()])[0]:.3f}" for g in GS))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
