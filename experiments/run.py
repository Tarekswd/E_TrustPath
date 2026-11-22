"""Single command to reproduce all TrustPath experiments:

    python3 experiments/run.py [seeds=10] [out_root=results]

Writes results/<UTC timestamp>/{raw.csv, environment.txt} and then calls analyze.py.
Scenarios (all values are SIMULATED, not measured on a real network):
  A malicious-fraction sweep  f in {0, .1, .2, .3}, all strategies, e2e attribution
  B attribution               f = .2, trust strategies, e2e vs per_hop
  C sybil                     f = .1, open admission, {0,10,50} Sybils, 5 fake reports/identity/epoch,
                              naive vs flow-bound report acceptance
  D crash                     f = 0, 15 % honest nodes crash halfway (benign failures / partitions)
"""
import csv
import os
import platform
import subprocess
import sys
import time
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from trustpath.network import NetConfig  # noqa: E402
from trustpath.routing import STRATEGIES  # noqa: E402
from trustpath.sim import SimConfig, run  # noqa: E402


def grid(seeds):
    for s in seeds:
        for f in (0.0, 0.1, 0.2, 0.3):
            for st in STRATEGIES:
                yield "A_fraction", SimConfig(NetConfig(seed=s, malicious_frac=f), strategy=st)
        for st in ("trust", "trust_multi"):
            for att in ("e2e", "per_hop"):
                yield "B_attribution", SimConfig(NetConfig(seed=s, malicious_frac=0.2), strategy=st, attribution=att)
        for sybils in (0, 10, 50):
            for policy in ("naive", "flow_bound"):
                for st in ("trust", "trust_multi"):
                    yield "C_sybil", SimConfig(NetConfig(seed=s, malicious_frac=0.1, sybils=sybils, admission="open"),
                                               strategy=st, fake_reports_per_epoch=5, report_policy=policy)
        for st in STRATEGIES:
            yield "D_crash", SimConfig(NetConfig(seed=s, crash_frac=0.15), strategy=st)


def job(item):
    scenario, cfg = item
    return {"scenario": scenario, **run(cfg)}


def main():
    seeds = range(1, 1 + int(sys.argv[1] if len(sys.argv) > 1 else 10))
    out = Path(sys.argv[2] if len(sys.argv) > 2 else "results") / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out.mkdir(parents=True)
    items = list(grid(seeds))
    t0 = time.time()
    with Pool(max(1, (os.cpu_count() or 2) - 1)) as pool:
        rows = pool.map(job, items, chunksize=4)
    with open(out / "raw.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    import cryptography
    import networkx

    (out / "environment.txt").write_text(
        f"date_utc: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
        f"runs: {len(rows)} ({len(seeds)} seeds), wall time {time.time() - t0:.0f} s\n"
        f"python: {platform.python_version()} ({platform.platform()})\n"
        f"networkx: {networkx.__version__}, cryptography: {cryptography.__version__}\n"
        "all metrics are simulated (see README: Simulation model)\n"
    )
    subprocess.run([sys.executable, str(Path(__file__).parent / "analyze.py"), str(out / "raw.csv"), str(out)], check=False)
    print(f"results in {out}")


if __name__ == "__main__":
    main()
