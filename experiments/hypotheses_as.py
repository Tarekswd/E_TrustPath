"""Check pre-registered H-T1, H-T2, H-T4 (NOVELTY_PLAN.md 3.3) on the AS-level grids. Mean +/- 95% t-CI over seeds.

Usage: python experiments/hypotheses_as.py results/as-T1-30seeds/raw.csv results/as-T2-30seeds/raw.csv
"""
import csv
import math
import statistics as st
import sys
from collections import defaultdict

T95 = 2.045  # t(0.975, 29) for 30 seeds


def ci(xs):
    xs = [x for x in xs if not math.isnan(x)]
    m = st.mean(xs)
    h = T95 * st.stdev(xs) / math.sqrt(len(xs)) if len(xs) > 1 else float("nan")
    return f"{m:+.3f} +/- {h:.3f}"


def load(path):
    rows = list(csv.DictReader(open(path, newline="")))
    for r in rows:
        r["gain"] = float(r["delivery_adopters"]) - float(r["delivery_others"])
    return rows


def by(rows, keys, metric):
    g = defaultdict(dict)
    for r in rows:
        g[tuple(r[k] for k in keys)][r["seed"]] = float(r[metric]) if metric != "gain" else r["gain"]
    return g


def main(t1, t2):
    r1, r2 = load(t1), load(t2)
    print("## H-T1: adopter gain (adopter - non-adopter delivery) vs adoption fraction, attacker always")
    for place, frac in (("top", "0.05"), ("random", "0.05"), ("top", "0.1")):
        rows = [r for r in r1 if r["mal_placement"] == place and r["mal_frac"] == frac and r["adopt_frac"] not in ("0.0", "1.0")]
        g = by(rows, ("policy", "adopt_frac"), "gain")
        fs = sorted({k[1] for k in g}, key=float)
        print(f"\n{place} {frac}: | policy | " + " | ".join(f"f={f}" for f in fs) + " |")
        for p in ("local", "agreement", "shared"):
            print(f"| {p} | " + " | ".join(ci(g[(p, f)].values()) for f in fs) + " |")
        # agreement - local, paired by seed
        print("| agreement-local (paired) | " + " | ".join(
            ci([g[("agreement", f)][s] - g[("local", f)][s] for s in g[("local", f)]]) for f in fs) + " |")

    print("\n## H-T2/H-T4 (T2: top placement, 5% malicious)")
    for metric in ("delivery_others", "delivery_adopters", "delivery_all", "loc_auc"):
        g = by(r2, ("attacker", "policy", "adopt_frac"), metric)
        fs = sorted({k[2] for k in g}, key=float)
        print(f"\n{metric}: | attacker | policy | " + " | ".join(f"f={f}" for f in fs) + " |")
        for a in ("always", "on_off", "adopter_aware", "conflicting"):
            for p in ("local", "agreement"):
                print(f"| {a} | {p} | " + " | ".join(ci(g[(a, p, f)].values()) for f in fs) + " |")
    print("\nH-T2 paired: non-adopter delivery, adopter_aware - always (local policy)")
    g = by(r2, ("attacker", "policy", "adopt_frac"), "delivery_others")
    for f in sorted({k[2] for k in g}, key=float):
        print(f"  f={f}: {ci([g[('adopter_aware', 'local', f)][s] - g[('always', 'local', f)][s] for s in g[('always', 'local', f)]])}")
    print("H-T4 paired: adopter delivery, agreement - local, under conflicting (and always for reference)")
    g = by(r2, ("attacker", "policy", "adopt_frac"), "delivery_adopters")
    for f in sorted({k[2] for k in g}, key=float):
        d = {a: ci([g[(a, 'agreement', f)][s] - g[(a, 'local', f)][s] for s in g[(a, 'local', f)]]) for a in ("conflicting", "always")}
        print(f"  f={f}: conflicting {d['conflicting']}   always {d['always']}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
